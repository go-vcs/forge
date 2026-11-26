// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package gittest makes bare repositories with history for tests, with the real
// git binary.
package gittest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Env is the environment git runs under in tests: no user or system
// configuration, fixed identity and dates.
func Env() []string {
	return append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
		"GIT_TERMINAL_PROMPT=0",
	)
}

// Git runs git in dir and returns its trimmed stdout.
func Git(t testing.TB, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	c.Env = Env()
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return strings.TrimSpace(out.String())
}

// NewRepo creates <root>/<owner>/<name>.git holding three commits on main and
// a tag, and returns the work tree it was made from. A public repository gets
// the git-daemon-export-ok marker.
func NewRepo(t testing.TB, root, owner, name string, public bool) (work string) {
	t.Helper()
	work = filepath.Join(t.TempDir(), "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	Git(t, work, "init", "-q", "-b", "main")
	for _, s := range []string{"one", "two", "three"} {
		if err := os.WriteFile(filepath.Join(work, "f.txt"), []byte(strings.Repeat(s+"\n", 200)), 0o644); err != nil {
			t.Fatal(err)
		}
		Git(t, work, "add", "f.txt")
		Git(t, work, "commit", "-q", "-m", s)
	}
	Git(t, work, "tag", "-a", "-m", "v1", "v1")
	if err := os.MkdirAll(filepath.Join(root, owner), 0o755); err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(root, owner, name+".git")
	Git(t, root, "clone", "-q", "--bare", work, bare)
	if public {
		if err := os.WriteFile(filepath.Join(bare, "git-daemon-export-ok"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return work
}

// Commit adds one commit to work and pushes it to the bare repository at
// <root>/<owner>/<name>.git.
func Commit(t testing.TB, work, root, owner, name, file string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(work, file), []byte(file+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	Git(t, work, "add", file)
	Git(t, work, "commit", "-q", "-m", file)
	Git(t, work, "push", "-q", filepath.Join(root, owner, name+".git"), "main")
}
