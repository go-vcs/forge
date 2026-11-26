//go:build unix

package main

import (
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/fidotest"
	"github.com/go-vcs/forge/internal/gittest"
)

func TestHTTPFlagsRefusals(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	repos := t.TempDir()
	for name, c := range map[string]struct {
		extra []string
		want  string
	}{
		"no repos root":     {[]string{"--http-listen", "127.0.0.1:0"}, "--repos-root is required"},
		"zero sessions":     {[]string{"--http-listen", "127.0.0.1:0", "--repos-root", repos, "--git-sessions", "0"}, "must be positive"},
		"zero per account":  {[]string{"--http-listen", "127.0.0.1:0", "--repos-root", repos, "--git-sessions-per-account", "0"}, "must be positive"},
		"zero timeout":      {[]string{"--http-listen", "127.0.0.1:0", "--repos-root", repos, "--git-timeout", "0s"}, "must be positive"},
		"repos root absent": {[]string{"--http-listen", "127.0.0.1:0", "--repos-root", filepath.Join(repos, "nope")}, "repositories root"},
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

func TestHTTPPortInUseStopsTheOthers(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	args, _, _ := baseArgs(t, a, 0o600)
	args = append(args, "--http-listen", busy.Addr().String(), "--repos-root", t.TempDir())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, _, err := run(t, ctx, args); err == nil || ctx.Err() != nil {
		t.Fatalf("a busy HTTP port: err = %v (ctx %v), want an immediate refusal", err, ctx.Err())
	}
}

// TestServeGitOverHTTPS clones and fetches with the real git client over TLS
// 1.3, trusting the test certificate through the git configuration (no
// credential and no secret is on a command line).
func TestServeGitOverHTTPS(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	args, _, _ := baseArgs(t, a, 0o600)
	var certPath string
	for i, s := range args {
		if s == "--tls-cert" {
			certPath = args[i+1]
		}
	}
	repos := t.TempDir()
	work := gittest.NewRepo(t, repos, "alice", "pub", true)
	gittest.NewRepo(t, repos, "alice", "priv", false)
	args = append(args, "--http-listen", "127.0.0.1:0", "--repos-root", repos, "--git-timeout", "30s")

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
	const pfx = "git over HTTP listening on "
	waitFor(t, &out, pfx)
	line := out.String()
	addr := strings.TrimSpace(strings.SplitN(line[strings.Index(line, pfx)+len(pfx):], "\n", 2)[0])
	base := "https://" + addr

	git := func(dir string, a ...string) (string, error) {
		c := exec.Command("git", append([]string{"-c", "http.sslCAInfo=" + certPath, "-c", "protocol.version=2"}, a...)...)
		c.Dir = dir
		c.Env = gittest.Env()
		b, err := c.CombinedOutput()
		return string(b), err
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "c")
	if o, err := git(dir, "clone", "-q", base+"/alice/pub.git", dst); err != nil {
		t.Fatalf("clone: %v\n%s", err, o)
	}
	if got, want := gittest.Git(t, dst, "rev-parse", "HEAD"), gittest.Git(t, work, "rev-parse", "HEAD"); got != want {
		t.Fatalf("HEAD %s, want %s", got, want)
	}
	gittest.Commit(t, work, repos, "alice", "pub", "more.txt")
	if o, err := git(dst, "fetch", "-q", "origin"); err != nil {
		t.Fatalf("fetch: %v\n%s", err, o)
	}
	if got, want := gittest.Git(t, dst, "rev-parse", "origin/main"), gittest.Git(t, work, "rev-parse", "HEAD"); got != want {
		t.Fatalf("origin/main %s, want %s", got, want)
	}
	if o, err := git(dir, "clone", "-q", base+"/alice/priv.git", filepath.Join(dir, "p")); err == nil || !strings.Contains(o, "not found") {
		t.Fatalf("private clone: %v\n%s", err, o)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned %v after a clean stop", err)
	}
}
