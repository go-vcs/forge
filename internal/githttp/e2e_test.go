// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package githttp

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-vcs/forge/internal/gittest"
)

// gitRun runs the real git client in dir; it returns its output and error.
func gitRun(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	c.Env = gittest.Env()
	var b bytes.Buffer
	c.Stdout, c.Stderr = &b, &b
	err := c.Run()
	return b.String(), err
}

func TestRealGitCloneAndFetch(t *testing.T) {
	r := newRig(t, nil)
	work := gittest.NewRepo(t, r.root, "alice", "e2e", true)
	base := r.url
	dir := t.TempDir()
	dst := filepath.Join(dir, "clone")

	if out, err := gitRun(t, dir, "-c", "protocol.version=2", "clone", "-q", base+"/alice/e2e.git", dst); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	want := gittest.Git(t, work, "rev-parse", "HEAD")
	if got := gittest.Git(t, dst, "rev-parse", "HEAD"); got != want {
		t.Fatalf("cloned HEAD %s, want %s", got, want)
	}
	if out, err := gitRun(t, dst, "fsck", "--strict"); err != nil {
		t.Fatalf("fsck: %v\n%s", err, out)
	}

	gittest.Commit(t, work, r.root, "alice", "e2e", "later.txt")
	if out, err := gitRun(t, dst, "-c", "protocol.version=2", "fetch", "-q", "origin"); err != nil {
		t.Fatalf("fetch: %v\n%s", err, out)
	}
	want = gittest.Git(t, work, "rev-parse", "HEAD")
	if got := gittest.Git(t, dst, "rev-parse", "origin/main"); got != want {
		t.Fatalf("fetched origin/main %s, want %s", got, want)
	}

	// a private repository answers as a missing one does
	if out, err := gitRun(t, dir, "clone", "-q", base+"/alice/priv.git", filepath.Join(dir, "p")); err == nil || !strings.Contains(out, "not found") {
		t.Fatalf("private clone: err %v, want \"not found\"\n%s", err, out)
	}
	// push is refused with the reason
	if out, err := gitRun(t, dst, "push", "origin", "HEAD:refs/heads/x"); err == nil || !strings.Contains(out, "milestone 4") {
		t.Fatalf("push: err %v, want the milestone named\n%s", err, out)
	}
	// protocol version 0 is refused, not served
	if out, err := gitRun(t, dir, "-c", "protocol.version=0", "clone", "-q", base+"/alice/e2e.git", filepath.Join(dir, "v0")); err == nil || !strings.Contains(out, "version 2") {
		t.Fatalf("v0 clone: err %v, want version 2 named\n%s", err, out)
	}
}
