// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package gitssh

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/gittest"
	"github.com/go-vcs/forge/internal/sshtest"
)

// sshCommand returns the GIT_SSH_COMMAND that signs in with key and trusts only
// the rig's host key (StrictHostKeyChecking=yes against a known_hosts file that
// holds nothing else), reading no user configuration.
func (r *rig) sshCommand(t *testing.T, key sshtest.Key) string {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("no ssh client")
	}
	dir := t.TempDir()
	host, port, err := net.SplitHostPort(r.addr)
	if err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, []byte(fmt.Sprintf("[%s]:%s %s\n", host, port, r.host.Line)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	q := func(p string) string { return "'" + filepath.ToSlash(p) + "'" }
	return strings.Join([]string{
		"ssh", "-F", q(cfg), "-i", q(key.PrivateFile),
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + q(kh), "-o", "PasswordAuthentication=no",
	}, " ")
}

func (r *rig) url(path string) string { return "ssh://git@" + r.addr + "/" + path }

// gitRun runs git with the environment of the tests plus extra, and returns its
// combined output.
func gitRun(dir string, extra []string, args ...string) (string, error) {
	c := exec.Command("git", args...)
	c.Dir = dir
	c.Env = append(gittest.Env(), extra...)
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	done := make(chan error, 1)
	if err := c.Start(); err != nil {
		return "", err
	}
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(60 * time.Second):
		c.Process.Kill()
		<-done
		return out.String(), fmt.Errorf("git %s: timed out", strings.Join(args, " "))
	}
}

func TestGitCloneAndFetchOverSSH(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	r := newRig(t, nil)
	ka := r.user(t, "alice")
	kb := r.user(t, "bob")
	work := gittest.NewRepo(t, r.root, "alice", "proj", false)
	env := func(k sshtest.Key) []string {
		return []string{"GIT_SSH_COMMAND=" + r.sshCommand(t, k), "GIT_SSH_VARIANT=ssh"}
	}
	dest := filepath.Join(t.TempDir(), "clone")

	out, err := gitRun(t.TempDir(), env(ka), "clone", "-q", r.url("alice/proj.git"), dest)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if got, want := gittest.Git(t, dest, "rev-parse", "HEAD"), gittest.Git(t, work, "rev-parse", "HEAD"); got != want {
		t.Fatalf("cloned %s, want %s", got, want)
	}
	if gittest.Git(t, dest, "tag", "-l", "v1") != "v1" {
		t.Fatal("tag v1 missing from the clone")
	}
	if out := gittest.Git(t, dest, "fsck", "--strict"); strings.Contains(out, "error") {
		t.Fatal(out)
	}

	// fetch what was added since
	gittest.Commit(t, work, r.root, "alice", "proj", "later.txt")
	if out, err := gitRun(dest, env(ka), "fetch", "-q", "origin"); err != nil {
		t.Fatalf("fetch: %v\n%s", err, out)
	}
	if got, want := gittest.Git(t, dest, "rev-parse", "origin/main"), gittest.Git(t, work, "rev-parse", "HEAD"); got != want {
		t.Fatalf("fetched %s, want %s", got, want)
	}

	// the other account cannot read it, and learns nothing but "not found"
	out, err = gitRun(t.TempDir(), env(kb), "clone", "-q", r.url("alice/proj.git"), filepath.Join(t.TempDir(), "c"))
	if err == nil || !strings.Contains(out, "repository not found") {
		t.Fatalf("another account's clone: %v\n%s", err, out)
	}
	// a key nobody registered cannot sign in
	out, err = gitRun(t.TempDir(), env(sshtest.NewEd25519(t)), "clone", "-q", r.url("alice/proj.git"), filepath.Join(t.TempDir(), "c"))
	if err == nil || !strings.Contains(out, "Permission denied") {
		t.Fatalf("unknown key: %v\n%s", err, out)
	}
	// push is refused by name
	gittest.Git(t, dest, "commit", "-q", "--allow-empty", "-m", "local")
	out, err = gitRun(dest, env(ka), "push", "origin", "HEAD:refs/heads/new")
	if err == nil || !strings.Contains(out, "push over SSH is not supported yet") {
		t.Fatalf("push: %v\n%s", err, out)
	}
	// protocol version 0 is refused by name
	out, err = gitRun(t.TempDir(), env(ka), "-c", "protocol.version=0", "clone", "-q", r.url("alice/proj.git"), filepath.Join(t.TempDir(), "c"))
	if err == nil || !strings.Contains(out, "version 2 is required") {
		t.Fatalf("protocol v0: %v\n%s", err, out)
	}
}
