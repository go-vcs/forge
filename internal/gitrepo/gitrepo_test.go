// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package gitrepo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-vcs/gitproto"

	"github.com/go-vcs/forge/internal/gittest"
)

func TestParsePathAccepts(t *testing.T) {
	for in, want := range map[string]Name{
		"alice/proj":                        {"alice", "proj"},
		"/alice/proj":                       {"alice", "proj"},
		"alice/proj.git":                    {"alice", "proj"},
		"/alice/proj.git":                   {"alice", "proj"},
		"a/b":                               {"a", "b"},
		"u-1/my_repo.v2":                    {"u-1", "my_repo.v2"},
		"alice/" + strings.Repeat("x", 100): {"alice", strings.Repeat("x", 100)},
	} {
		got, err := ParsePath(in)
		if err != nil || got != want {
			t.Errorf("ParsePath(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
}

func TestParsePathRefuses(t *testing.T) {
	for _, in := range []string{
		"", "alice", "/", "//", "alice/", "/alice/", "alice//proj", "//alice/proj",
		"alice/proj/", "alice/proj/sub", "../alice/proj", "alice/..", "alice/../proj",
		"alice/a..b", "alice/.hidden", "alice/-x", "alice/proj.git.git", "alice/.git",
		"Alice/proj", "alice/Proj", "ali ce/proj", "alice/pr\x00oj", "alice/pr\noj",
		"alice/pr\x7foj", "alice/pröj", "~alice/proj", "alice/proj?x", "alice/proj\\x",
		"-alice/proj", strings.Repeat("a", 40) + "/proj", "alice/" + strings.Repeat("x", 101),
		"alice/" + strings.Repeat("x", MaxPathLen), "C:/alice/proj", "alice/proj%2e",
	} {
		if n, err := ParsePath(in); !errors.Is(err, ErrPath) {
			t.Errorf("ParsePath(%q) = %v, %v; want ErrPath", in, n, err)
		}
	}
	// the length bound itself
	if _, err := ParsePath("alice/" + strings.Repeat("x", 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePath(strings.Repeat("a", MaxPathLen+1)); !errors.Is(err, ErrPath) {
		t.Fatal("a path over MaxPathLen was accepted")
	}
}

func TestNameString(t *testing.T) {
	if got := (Name{"a", "b"}).String(); got != "a/b" {
		t.Fatal(got)
	}
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]*Service{
		"no root":        {},
		"missing root":   {Root: filepath.Join(dir, "missing")},
		"root is a file": {Root: file},
		"negative limit": {Root: dir, Limits: gitproto.Limits{MaxWants: -1}},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (&Service{Root: dir}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRule(t *testing.T) {
	root := t.TempDir()
	gittest.NewRepo(t, root, "alice", "private", false)
	gittest.NewRepo(t, root, "alice", "open", true)
	s := &Service{Root: root, Agent: "x", PackThreads: 1, Limits: gitproto.Limits{MaxWants: 7}}

	for _, c := range []struct {
		name  string
		repo  string
		login string
		ok    bool
	}{
		{"owner reads private", "private", "alice", true},
		{"owner reads public", "open", "alice", true},
		{"stranger reads public", "open", "bob", true},
		{"anonymous reads public", "open", "", true},
		{"stranger refused private", "private", "bob", false},
		{"anonymous refused private", "private", "", false},
		{"missing", "nothing", "alice", false},
	} {
		srv, err := s.Open(Name{"alice", c.repo}, c.login)
		if c.ok && (err != nil || srv == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok && (!errors.Is(err, ErrNotFound) || srv != nil) {
			t.Errorf("%s: got %v, %v; want ErrNotFound", c.name, srv, err)
		}
	}
	// the server carries the service's settings
	srv, err := s.Open(Name{"alice", "open"}, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, ok := srv.Repo.(*gitproto.GitRepo)
	if !ok || repo.Dir != filepath.Join(root, "alice", "open.git") || repo.PackThreads != 1 || srv.Agent != "x" || srv.Limits.MaxWants != 7 {
		t.Fatalf("server %+v repo %+v", srv, repo)
	}
	// an unknown owner
	if _, err := s.Open(Name{"nobody", "open"}, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestOpenRefusesWhatIsNotARepository(t *testing.T) {
	root := t.TempDir()
	gittest.NewRepo(t, root, "alice", "ok", true)
	// a directory without HEAD
	if err := os.MkdirAll(filepath.Join(root, "alice", "empty.git"), 0o755); err != nil {
		t.Fatal(err)
	}
	// the repository is a file
	if err := os.WriteFile(filepath.Join(root, "alice", "file.git"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// HEAD is a directory
	if err := os.MkdirAll(filepath.Join(root, "alice", "headdir.git", "HEAD"), 0o755); err != nil {
		t.Fatal(err)
	}
	// the public marker is a directory
	gittest.NewRepo(t, root, "alice", "markerdir", false)
	if err := os.Mkdir(filepath.Join(root, "alice", "markerdir.git", PublicMarker), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Service{Root: root}
	for _, n := range []string{"empty", "file", "headdir", "markerdir"} {
		if _, err := s.Open(Name{"alice", n}, ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", n, err)
		}
	}
}

func TestOpenDoesNotFollowSymbolicLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	gittest.NewRepo(t, outside, "eve", "loot", true)
	// the owner directory is a link out of the root
	if err := os.Symlink(filepath.Join(outside, "eve"), filepath.Join(root, "eve")); err != nil {
		t.Fatal(err)
	}
	// the repository directory is a link out of the root
	if err := os.MkdirAll(filepath.Join(root, "alice"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "eve", "loot.git"), filepath.Join(root, "alice", "loot.git")); err != nil {
		t.Fatal(err)
	}
	s := &Service{Root: root}
	for _, n := range []Name{{"eve", "loot"}, {"alice", "loot"}} {
		if _, err := s.Open(n, n.Owner); !errors.Is(err, ErrNotFound) {
			t.Errorf("%v: %v", n, err)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := &Limiter{Total: 3, PerKey: 2}
	a1, err := l.Acquire("a")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := l.Acquire("a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Acquire("a"); !errors.Is(err, ErrBusy) {
		t.Fatalf("third session of one key: %v", err)
	}
	b1, err := l.Acquire("b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Acquire("c"); !errors.Is(err, ErrBusy) {
		t.Fatalf("session over the total: %v", err)
	}
	// release is idempotent: a second call must not free a second slot
	a1()
	a1()
	if _, err := l.Acquire("c"); err != nil {
		t.Fatalf("a freed slot was not reusable: %v", err)
	}
	if _, err := l.Acquire("c"); !errors.Is(err, ErrBusy) {
		t.Fatalf("double release freed two slots: %v", err)
	}
	a2()
	b1()
	if l.total != 1 || len(l.keys) != 1 {
		t.Fatalf("after releases: total %d keys %v", l.total, l.keys)
	}
}

func TestWithTimeout(t *testing.T) {
	ctx, cancel := WithTimeout(context.Background(), 0)
	defer cancel()
	d, ok := ctx.Deadline()
	if !ok || time.Until(d) < DefaultRequestDuration-time.Minute || time.Until(d) > DefaultRequestDuration {
		t.Fatalf("default deadline %v", time.Until(d))
	}
	ctx, cancel = WithTimeout(context.Background(), time.Hour)
	defer cancel()
	if d, _ := ctx.Deadline(); time.Until(d) < 59*time.Minute {
		t.Fatalf("explicit deadline %v", time.Until(d))
	}
}
