// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package gitssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/go-vcs/gitproto"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gittest"
	"github.com/go-vcs/forge/internal/sshtest"
	"github.com/go-vcs/forge/internal/store"
)

type rig struct {
	st   *store.Store
	root string
	host sshtest.Key
	addr string
	srv  *Server
}

// newRig starts a server on a loopback port. mod may change it before it starts.
func newRig(t *testing.T, mod func(*Server)) *rig {
	t.Helper()
	st, err := store.Open(t.Context(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	root := t.TempDir()
	host := sshtest.NewEd25519(t)
	srv := &Server{
		Auth:     st,
		Repos:    &gitrepo.Service{Root: root},
		Sessions: &gitrepo.Limiter{Total: 16, PerKey: 8},
		HostKey:  host.Signer,
		Log:      slog.New(slog.DiscardHandler),
	}
	if mod != nil {
		mod(srv)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return &rig{st: st, root: root, host: host, addr: ln.Addr().String(), srv: srv}
}

// user creates an account with one registered key.
func (r *rig) user(t *testing.T, login string) sshtest.Key {
	t.Helper()
	if _, err := r.st.CreateUser(t.Context(), login, login); err != nil {
		t.Fatal(err)
	}
	k := sshtest.NewEd25519(t)
	if _, err := r.st.AddSSHKey(t.Context(), login, k.Line); err != nil {
		t.Fatal(err)
	}
	return k
}

func (r *rig) dial(key ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", r.addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(r.host.Signer.PublicKey()),
		Timeout:         5 * time.Second,
	})
}

func (r *rig) connect(t *testing.T, k sshtest.Key) *ssh.Client {
	t.Helper()
	c, err := r.dial(k.Signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// pkt encodes one pkt-line.
func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

const (
	flush = "0000"
	delim = "0001"
)

// lsRefs is an ls-refs request with the given ref-prefix lines, followed by
// the empty request that ends the session.
func lsRefs(prefixes ...string) string {
	s := pkt("command=ls-refs\n") + pkt("agent=test\n") + delim + pkt("peel\n")
	for _, p := range prefixes {
		s += pkt("ref-prefix " + p + "\n")
	}
	return s + flush + flush
}

type result struct {
	out, errOut string
	status      int
	err         error
}

// newSession opens a session channel, retrying briefly: the server frees the
// connection's one session slot a moment after the previous channel closed.
func newSession(t *testing.T, c *ssh.Client) *ssh.Session {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s, err := c.NewSession()
		if err == nil {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func run(t *testing.T, c *ssh.Client, cmd string, v2 bool, stdin string) result {
	t.Helper()
	s := newSession(t, c)
	defer s.Close()
	if v2 {
		if err := s.Setenv("GIT_PROTOCOL", "version=2"); err != nil {
			t.Fatal(err)
		}
	}
	var out, eb bytes.Buffer
	s.Stdout, s.Stderr, s.Stdin = &out, &eb, strings.NewReader(stdin)
	err := s.Run(cmd)
	res := result{out: out.String(), errOut: eb.String(), err: err}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		res.status = ee.ExitStatus()
	}
	return res
}

const upload = "git-upload-pack 'alice/proj'"

func TestSessionServesTheAdvertisementAndLsRefs(t *testing.T) {
	r := newRig(t, nil)
	k := r.user(t, "alice")
	gittest.NewRepo(t, r.root, "alice", "proj", false)
	c := r.connect(t, k)

	res := run(t, c, upload, true, lsRefs("refs/heads/"))
	if res.err != nil || res.status != 0 {
		t.Fatalf("%+v", res)
	}
	if !strings.HasPrefix(res.out, "000eversion 2\n") || !strings.Contains(res.out, "refs/heads/main") || strings.Contains(res.out, "refs/tags/") {
		t.Fatalf("output %q", res.out)
	}
	// the path forms git sends
	for _, cmd := range []string{"git-upload-pack '/alice/proj.git'", "git-upload-pack 'alice/proj.git'"} {
		if res := run(t, c, cmd, true, flush); res.err != nil {
			t.Errorf("%s: %+v", cmd, res)
		}
	}
}

func TestSessionRefusals(t *testing.T) {
	r := newRig(t, nil)
	k := r.user(t, "alice")
	r.user(t, "bob")
	gittest.NewRepo(t, r.root, "alice", "proj", false)
	gittest.NewRepo(t, r.root, "bob", "secret", false)
	gittest.NewRepo(t, r.root, "bob", "open", true)
	c := r.connect(t, k)

	for _, tc := range []struct {
		name, cmd string
		v2        bool
		want      string
	}{
		{"push", "git-receive-pack 'alice/proj'", true, "push over SSH is not supported yet"},
		{"shell command", "sh -c id", true, "only git-upload-pack"},
		{"empty command", "", true, "only git-upload-pack"},
		{"traversal", "git-upload-pack 'alice/../bob/secret'", true, "invalid repository path"},
		{"absolute", "git-upload-pack '/etc/passwd/shadow'", true, "invalid repository path"},
		{"absolute two segments is owner/name, below the root", "git-upload-pack '/etc/passwd'", true, "repository not found"},
		{"missing repository", "git-upload-pack 'alice/none'", true, "repository not found"},
		{"someone else's private repository", "git-upload-pack 'bob/secret'", true, "repository not found"},
		{"unknown owner", "git-upload-pack 'carol/x'", true, "repository not found"},
		{"no protocol parameter", upload, false, "version 2 is required"},
	} {
		res := run(t, c, tc.cmd, tc.v2, flush)
		if res.status != 1 || !strings.Contains(res.errOut, tc.want) || res.out != "" {
			t.Errorf("%s: %+v; want status 1 and %q", tc.name, res, tc.want)
		}
	}
	// a public repository of someone else is readable
	if res := run(t, c, "git-upload-pack 'bob/open'", true, flush); res.err != nil {
		t.Errorf("public repository: %+v", res)
	}
}

func TestOnlyGitUploadPackOnASessionChannel(t *testing.T) {
	r := newRig(t, nil)
	k := r.user(t, "alice")
	gittest.NewRepo(t, r.root, "alice", "proj", false)
	c := r.connect(t, k)

	if _, err := c.Dial("tcp", "127.0.0.1:1"); err == nil {
		t.Error("direct-tcpip accepted")
	}
	if ln, err := c.Listen("tcp", "127.0.0.1:0"); err == nil {
		ln.Close()
		t.Error("tcpip-forward accepted")
	}
	if ch, _, err := c.OpenChannel("direct-streamlocal@openssh.com", nil); err == nil {
		ch.Close()
		t.Error("streamlocal channel accepted")
	}
	if ch, _, err := c.OpenChannel("x11", nil); err == nil {
		ch.Close()
		t.Error("x11 channel accepted")
	}

	s0 := newSession(t, c)
	for name, f := range map[string]func() error{
		"pty":       func() error { return s0.RequestPty("xterm", 24, 80, nil) },
		"shell":     s0.Shell,
		"subsystem": func() error { return s0.RequestSubsystem("sftp") },
		"env":       func() error { return s0.Setenv("LD_PRELOAD", "/tmp/x.so") },
		"env path":  func() error { return s0.Setenv("PATH", "/tmp") },
		"long env":  func() error { return s0.Setenv("GIT_PROTOCOL", strings.Repeat("x", MaxEnvValueLen+1)) },
		"x11":       func() error { return failIfAccepted(s0, "x11-req") },
		"agent":     func() error { return failIfAccepted(s0, "auth-agent-req@openssh.com") },
		"window":    func() error { return failIfAccepted(s0, "window-change") },
		"signal":    func() error { return failIfAccepted(s0, "signal") },
		"made up":   func() error { return failIfAccepted(s0, "no-such-request@example.org") },
		"empty env": func() error { return s0.Setenv("", "") },
		"long name": func() error { return s0.Setenv(strings.Repeat("A", 1000), "1") },
	} {
		if err := f(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s0.Close()

	// refusals do not end the session: the one allowed variable and the one
	// allowed command still work after them
	s := newSession(t, c)
	defer s.Close()
	if err := s.RequestPty("xterm", 24, 80, nil); err == nil {
		t.Error("pty accepted")
	}
	if err := s.Setenv("LD_PRELOAD", "x"); err == nil {
		t.Error("env accepted")
	}
	if err := s.Setenv("GIT_PROTOCOL", "version=2"); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s.Stdout, s.Stdin = &out, strings.NewReader(flush)
	if err := s.Run(upload); err != nil || !strings.HasPrefix(out.String(), "000eversion 2\n") {
		t.Fatalf("%v %q", err, out.String())
	}
}

// failIfAccepted sends a request that wants a reply and returns an error when
// the server refused (reply false), nil when it accepted.
func failIfAccepted(s *ssh.Session, typ string) error {
	ok, err := s.SendRequest(typ, true, nil)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return errors.New("refused")
}

func TestOneSessionChannelAtATime(t *testing.T) {
	r := newRig(t, nil)
	k := r.user(t, "alice")
	gittest.NewRepo(t, r.root, "alice", "proj", false)
	c := r.connect(t, k)
	s1, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if s2, err := c.NewSession(); err == nil {
		s2.Close()
		t.Fatal("a second session channel was opened while the first was active")
	}
	s1.Close()
	// once the first is gone, a new one opens (the server frees it when its
	// goroutine ends)
	deadline := time.Now().Add(3 * time.Second)
	for {
		s, err := c.NewSession()
		if err == nil {
			s.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRequestsBeforeTheExecAreBounded(t *testing.T) {
	r := newRig(t, nil)
	k := r.user(t, "alice")
	c := r.connect(t, k)
	s := newSession(t, c)
	defer s.Close()
	for i := 0; i < MaxPreExec+5; i++ {
		ok, err := s.SendRequest("pty-req", true, nil)
		if i < MaxPreExec && (err != nil || ok) {
			t.Fatalf("request %d: %v %v; want a plain refusal", i, ok, err)
		}
		if i >= MaxPreExec {
			if err == nil {
				t.Fatalf("request %d was answered: the session should have been closed", i)
			}
			return
		}
	}
}

func TestAuthentication(t *testing.T) {
	r := newRig(t, nil)
	k := r.user(t, "alice")
	gittest.NewRepo(t, r.root, "alice", "proj", false)
	ctx := t.Context()

	// the registered key works
	r.connect(t, k)

	// an unregistered key, and a password, do not
	if _, err := r.dial(sshtest.NewEd25519(t).Signer); err == nil {
		t.Error("an unregistered key was accepted")
	}
	_, err := ssh.Dial("tcp", r.addr, &ssh.ClientConfig{
		User: "git", Auth: []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.FixedHostKey(r.host.Signer.PublicKey()), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Error("password authentication was accepted")
	}
	// more wrong keys than MaxAuthTries end the connection
	var signers []ssh.Signer
	for i := 0; i < MaxAuthTries+2; i++ {
		signers = append(signers, sshtest.NewEd25519(t).Signer)
	}
	_, err = ssh.Dial("tcp", r.addr, &ssh.ClientConfig{
		User: "git", Auth: []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.FixedHostKey(r.host.Signer.PublicKey()), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Error("too many wrong keys were accepted")
	}

	// a disabled account, a removed key and the sk- policy each stop a key that worked
	if err := r.st.SetPolicy(ctx, store.Policy{RequireSKKeys: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.dial(k.Signer); err == nil {
		t.Error("a plain key was accepted under the sk- policy")
	}
	if err := r.st.SetPolicy(ctx, store.Policy{}); err != nil {
		t.Fatal(err)
	}
	r.connect(t, k)
	if err := r.st.DisableUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.dial(k.Signer); err == nil {
		t.Error("a disabled account's key was accepted")
	}
	k2 := r.user(t, "bob")
	r.connect(t, k2)
	if err := r.st.RemoveSSHKey(ctx, k2.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := r.dial(k2.Signer); err == nil {
		t.Error("a removed key was accepted")
	}
}

// ---- bounds ----

// hold opens a session, runs the command and reads the advertisement, so the
// server is inside a git session holding its slot. The returned function ends
// the session cleanly.
func hold(t *testing.T, c *ssh.Client, cmd string) (finish func() error) {
	t.Helper()
	s := newSession(t, c)
	t.Cleanup(func() { s.Close() })
	if err := s.Setenv("GIT_PROTOCOL", "version=2"); err != nil {
		t.Fatal(err)
	}
	in, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(cmd); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("000eversion 2\n"))
	if _, err := io.ReadFull(out, buf); err != nil {
		t.Fatal(err)
	}
	go io.Copy(io.Discard, out)
	return func() error {
		in.Write([]byte(flush))
		in.Close()
		return s.Wait()
	}
}

// eventually runs f until it reports ok, for at most 3 s.
func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within 3 s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSessionsPerAccountAreCapped(t *testing.T) {
	r := newRig(t, func(s *Server) { s.Sessions = &gitrepo.Limiter{Total: 16, PerKey: 1} })
	ka := r.user(t, "alice")
	kb := r.user(t, "bob")
	gittest.NewRepo(t, r.root, "alice", "proj", true)
	a1, a2, b := r.connect(t, ka), r.connect(t, ka), r.connect(t, kb)

	finish := hold(t, a1, upload)
	res := run(t, a2, upload, true, flush)
	if res.status != 1 || !strings.Contains(res.errOut, "too many concurrent git sessions") {
		t.Fatalf("second session of one account: %+v", res)
	}
	// another account is not affected
	if res := run(t, b, upload, true, flush); res.err != nil {
		t.Fatalf("another account: %+v", res)
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "slot freed", func() bool { return run(t, a2, upload, true, flush).err == nil })
}

func TestSessionsInTotalAreCapped(t *testing.T) {
	r := newRig(t, func(s *Server) { s.Sessions = &gitrepo.Limiter{Total: 1, PerKey: 8} })
	ka := r.user(t, "alice")
	kb := r.user(t, "bob")
	gittest.NewRepo(t, r.root, "alice", "proj", true)
	a, b := r.connect(t, ka), r.connect(t, kb)

	finish := hold(t, a, upload)
	res := run(t, b, upload, true, flush)
	if res.status != 1 || !strings.Contains(res.errOut, "too many concurrent git sessions") {
		t.Fatalf("session over the total: %+v", res)
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "slot freed", func() bool { return run(t, b, upload, true, flush).err == nil })
}

func TestSessionTimeIsBounded(t *testing.T) {
	r := newRig(t, func(s *Server) {
		s.RequestTimeout = 300 * time.Millisecond
		s.Sessions = &gitrepo.Limiter{Total: 16, PerKey: 1}
	})
	k := r.user(t, "alice")
	gittest.NewRepo(t, r.root, "alice", "proj", false)
	c := r.connect(t, k)

	// a client that connects and says nothing is cut off, and its slot is freed
	s := newSession(t, c)
	defer s.Close()
	if err := s.Setenv("GIT_PROTOCOL", "version=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := s.Run(upload)
	if err == nil {
		t.Fatal("a stalled session ended cleanly")
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 3*time.Second {
		t.Fatalf("cut off after %v, want about 300 ms", d)
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) && ee.ExitStatus() == 0 {
		t.Fatalf("a timed-out session reported success: %v", err)
	}
	eventually(t, "slot freed", func() bool { return run(t, c, upload, true, flush).err == nil })
}

func TestRequestSizeIsBounded(t *testing.T) {
	r := newRig(t, func(s *Server) {
		s.Repos.Limits = gitproto.Limits{MaxRequestLines: 6, MaxRequestBytes: 400}
	})
	k := r.user(t, "alice")
	gittest.NewRepo(t, r.root, "alice", "proj", false)
	c := r.connect(t, k)

	// within the bounds
	if res := run(t, c, upload, true, lsRefs("refs/heads/")); res.err != nil || !strings.Contains(res.out, "refs/heads/main") {
		t.Fatalf("%+v", res)
	}
	// too many pkt-lines
	many := make([]string, 20)
	for i := range many {
		many[i] = "refs/heads/"
	}
	res := run(t, c, upload, true, lsRefs(many...))
	if res.status != 1 || !strings.Contains(res.out, "ERR") {
		t.Fatalf("pkt-line count: %+v", res)
	}
	// too many bytes, in few lines
	res = run(t, c, upload, true, lsRefs(strings.Repeat("a", 500)))
	if res.status != 1 || !strings.Contains(res.out, "ERR") {
		t.Fatalf("request size: %+v", res)
	}
}

func TestHandshakeAndIdleAreBounded(t *testing.T) {
	r := newRig(t, func(s *Server) {
		s.Handshake = 200 * time.Millisecond
		s.Idle = 200 * time.Millisecond
	})
	k := r.user(t, "alice")

	// a TCP client that never starts the handshake is dropped
	nc, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	nc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, nc); err != nil {
		t.Fatalf("the server did not close the idle connection: %v", err)
	}

	// a session that never sends its exec is closed
	c := r.connect(t, k)
	s := newSession(t, c)
	defer s.Close()
	eventually(t, "idle session closed", func() bool { return s.Setenv("GIT_PROTOCOL", "version=2") != nil })
}

func TestConnectionsPerHostAreCapped(t *testing.T) {
	r := newRig(t, func(s *Server) { s.MaxConnsPerHost = 1; s.MaxConns = 4 })
	k := r.user(t, "alice")
	r.connect(t, k)
	if c, err := r.dial(k.Signer); err == nil {
		c.Close()
		t.Fatal("a second connection from one host was served")
	}
}

func TestServeStopsWithItsContext(t *testing.T) {
	r := newRig(t, nil)
	k := r.user(t, "alice")
	gittest.NewRepo(t, r.root, "alice", "proj", true)
	c := r.connect(t, k)
	hold(t, c, upload)
	// the cleanup cancels the context while a session is open; Serve must
	// return (newRig's cleanup fails the test if it errors or hangs)
}
