//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/fidotest"
	"github.com/go-vcs/forge/internal/gittest"
	"github.com/go-vcs/forge/internal/sshtest"
	"github.com/go-vcs/forge/internal/store"
)

func writeHostKey(t *testing.T, mode os.FileMode) (path string, pub ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(shortDir(t), "host")
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(priv)
	return path, s.PublicKey()
}

func TestSSHFlagsRefusals(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	host, _ := writeHostKey(t, 0o600)
	open, _ := writeHostKey(t, 0o644)
	repos := t.TempDir()
	for name, c := range map[string]struct {
		extra []string
		want  string
	}{
		"no repos root":      {[]string{"--ssh-listen", "127.0.0.1:0", "--ssh-host-key", host}, "--repos-root is required"},
		"zero sessions":      {[]string{"--ssh-listen", "127.0.0.1:0", "--ssh-host-key", host, "--repos-root", repos, "--git-sessions", "0"}, "must be positive"},
		"zero per account":   {[]string{"--ssh-listen", "127.0.0.1:0", "--ssh-host-key", host, "--repos-root", repos, "--git-sessions-per-account", "0"}, "must be positive"},
		"zero timeout":       {[]string{"--ssh-listen", "127.0.0.1:0", "--ssh-host-key", host, "--repos-root", repos, "--git-timeout", "0s"}, "must be positive"},
		"no host key":        {[]string{"--ssh-listen", "127.0.0.1:0", "--repos-root", repos}, "ssh-host-key"},
		"host key is absent": {[]string{"--ssh-listen", "127.0.0.1:0", "--repos-root", repos, "--ssh-host-key", filepath.Join(repos, "nope")}, "nope"},
		"host key is open":   {[]string{"--ssh-listen", "127.0.0.1:0", "--repos-root", repos, "--ssh-host-key", open}, "0600"},
		"repos root absent":  {[]string{"--ssh-listen", "127.0.0.1:0", "--ssh-host-key", host, "--repos-root", filepath.Join(repos, "nope")}, "repositories root"},
	} {
		args, _, _ := baseArgs(t, a, 0o600)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		_, _, err := run(t, ctx, append(args, c.extra...))
		timedOut := ctx.Err() != nil
		cancel()
		if err == nil || timedOut || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v (timed out %v), want a refusal naming %q", name, err, timedOut, c.want)
		}
	}
}

func TestSSHPortInUseStopsTheOthers(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	host, _ := writeHostKey(t, 0o600)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	args, _, sock := baseArgs(t, a, 0o600)
	args = append(args, "--ssh-listen", busy.Addr().String(), "--ssh-host-key", host, "--repos-root", t.TempDir())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("a busy SSH port made serve panic: %v", r)
			}
		}()
		_, _, err = run(t, ctx, args)
	}()
	if err == nil || ctx.Err() != nil || !strings.Contains(err.Error(), busy.Addr().String()) {
		t.Fatalf("a busy SSH port: err = %v (ctx %v), want an immediate refusal naming the address", err, ctx.Err())
	}
	// the listeners opened before the failure were released
	ln, lerr := adminsrv.ListenUnix(sock)
	if lerr != nil {
		t.Fatalf("the enrolment socket was left open: %v", lerr)
	}
	ln.Close()
}

func TestServeGitOverSSH(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	args, _, _ := baseArgs(t, a, 0o600)
	hostPath, hostPub := writeHostKey(t, 0o600)
	repos := t.TempDir()
	gittest.NewRepo(t, repos, "alice", "proj", false)

	// an account with a key, in the database serve will open
	dbPath := args[2]
	st, err := store.Open(t.Context(), dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(t.Context(), "alice", "Alice"); err != nil {
		t.Fatal(err)
	}
	key := sshtest.NewEd25519(t)
	if _, err := st.AddSSHKey(t.Context(), "alice", key.Line); err != nil {
		t.Fatal(err)
	}
	st.Close()

	args = append(args, "--ssh-listen", "127.0.0.1:0", "--ssh-host-key", hostPath, "--repos-root", repos,
		"--git-sessions", "4", "--git-sessions-per-account", "2", "--git-timeout", "30s")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var out lockedBuf
	done := make(chan error, 1)
	go func() {
		c := RootCmd()
		c.SetArgs(args)
		c.SetOut(&out)
		c.SetErr(&lockedBuf{})
		done <- c.ExecuteContext(ctx)
	}()
	waitFor(t, &out, "git over SSH listening on ")
	const pfx = "git over SSH listening on "
	line := out.String()
	addr := strings.TrimSpace(strings.SplitN(line[strings.Index(line, pfx)+len(pfx):], "\n", 2)[0])

	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "git", Auth: []ssh.AuthMethod{ssh.PublicKeys(key.Signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	s, err := cc.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Setenv("GIT_PROTOCOL", "version=2"); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	s.Stdout, s.Stdin = &got, strings.NewReader("0000")
	if err := s.Run("git-upload-pack 'alice/proj.git'"); err != nil || !strings.HasPrefix(got.String(), "000eversion 2\n") {
		t.Fatalf("%v %q", err, got.String())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned %v after a clean stop", err)
	}
}
