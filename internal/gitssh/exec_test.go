// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package gitssh

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-vcs/forge/internal/gitrepo"
)

func TestParseExecAccepts(t *testing.T) {
	for in, want := range map[string]gitrepo.Name{
		"git-upload-pack 'alice/proj'":      {Owner: "alice", Repo: "proj"},
		"git-upload-pack '/alice/proj.git'": {Owner: "alice", Repo: "proj"},
		"git-upload-pack 'alice/proj.git'":  {Owner: "alice", Repo: "proj"},
	} {
		got, err := ParseExec(in)
		if err != nil || got != want {
			t.Errorf("ParseExec(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
}

func TestParseExecRefusals(t *testing.T) {
	long := "git-upload-pack '" + strings.Repeat("a", MaxCommandLen) + "'"
	for _, c := range []struct {
		in   string
		want error
	}{
		{"git-receive-pack 'alice/proj'", ErrPush},
		{"git-receive-pack", ErrPush},
		{"git-upload-archive 'alice/proj'", ErrCommand},
		{"", ErrCommand},
		{"sh", ErrCommand},
		{"sh -c id", ErrCommand},
		{"id", ErrCommand},
		{"git upload-pack 'alice/proj'", ErrCommand},
		{"git-upload-packs 'alice/proj'", ErrCommand},
		{"GIT-UPLOAD-PACK 'alice/proj'", ErrCommand},
		{" git-upload-pack 'alice/proj'", ErrCommand},
		{"/usr/bin/git-upload-pack 'alice/proj'", ErrCommand},
		{"git-upload-pack", ErrCommand},
		{"git-upload-pack ", ErrCommand},
		{"git-upload-pack ''", ErrCommand},
		{"git-upload-pack 'a'", gitrepo.ErrPath},
		{"git-upload-pack alice/proj", ErrCommand},
		{"git-upload-pack 'alice/proj", ErrCommand},
		{"git-upload-pack alice/proj'", ErrCommand},
		{`git-upload-pack "alice/proj"`, ErrCommand},
		{"git-upload-pack  'alice/proj'", ErrCommand},
		{"git-upload-pack 'alice/proj' ", ErrCommand},
		{"git-upload-pack 'alice/proj' 'bob/x'", gitrepo.ErrPath},
		{"git-upload-pack 'alice/proj'; id", ErrCommand},
		{"git-upload-pack 'alice/proj'$(id)'", gitrepo.ErrPath},
		{"git-upload-pack 'alice/pr'\\''oj'", gitrepo.ErrPath},
		{`git-upload-pack 'alice/pr\oj'`, gitrepo.ErrPath},
		{"git-upload-pack 'alice/pr!oj'", gitrepo.ErrPath},
		{"git-upload-pack '../alice/proj'", gitrepo.ErrPath},
		{"git-upload-pack 'alice/../bob/proj'", gitrepo.ErrPath},
		{"git-upload-pack '/etc/passwd/shadow'", gitrepo.ErrPath},
		{"git-upload-pack '/'", gitrepo.ErrPath},
		{"git-upload-pack '~alice/proj'", gitrepo.ErrPath},
		{"git-upload-pack 'alice/proj\x00'", gitrepo.ErrPath},
		{"git-upload-pack 'alice/proj\n'", gitrepo.ErrPath},
		{"git-upload-pack\t'alice/proj'", ErrCommand},
		{long, ErrCommand},
	} {
		if n, err := ParseExec(c.in); !errors.Is(err, c.want) {
			t.Errorf("ParseExec(%q) = %v, %v; want %v", c.in, n, err, c.want)
		}
	}
	// the bound itself: one byte over is refused as too long, at the bound it is
	// parsed (and refused for its path)
	at := "git-upload-pack '" + strings.Repeat("a", MaxCommandLen-len("git-upload-pack ''")) + "'"
	if len(at) != MaxCommandLen {
		t.Fatalf("test input is %d bytes", len(at))
	}
	if _, err := ParseExec(at); errors.Is(err, ErrCommand) {
		t.Fatalf("a command of exactly MaxCommandLen bytes was refused as too long: %v", err)
	}
	if _, err := ParseExec(at + "a"); !errors.Is(err, ErrCommand) {
		t.Fatalf("a command one byte over MaxCommandLen: %v", err)
	}
}

func TestPushMessageNamesTheMilestone(t *testing.T) {
	_, err := ParseExec("git-receive-pack 'alice/proj'")
	if err == nil || !strings.Contains(err.Error(), "milestone 4") {
		t.Fatal(err)
	}
}

func TestWantsV2(t *testing.T) {
	for in, want := range map[string]bool{
		"version=2": true, "version=2:object-format=sha1": true, "x=1:version=2": true,
		"": false, "version=1": false, "version=0": false, "version=20": false,
		"xversion=2": false, "version=2x": false, "version = 2": false,
	} {
		if got := wantsV2(in); got != want {
			t.Errorf("wantsV2(%q) = %v", in, got)
		}
	}
}

// FuzzParseExec holds the exec parser to its contract on any input: it never
// panics, and what it accepts is a canonical name that parses back to itself,
// with nothing in the input but the command, the quotes and that name.
func FuzzParseExec(f *testing.F) {
	for _, s := range []string{
		"git-upload-pack 'alice/proj'", "git-upload-pack '/alice/proj.git'", "git-receive-pack 'alice/proj'",
		"sh -c id", "", "git-upload-pack ''", "git-upload-pack '../x/y'", "git-upload-pack 'a/b'\\''c'",
		"git-upload-pack 'alice/proj\x00'", "git-upload-pack 'alice/pr\xc3\xb6j'",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		n, err := ParseExec(in)
		if err != nil {
			return
		}
		again, err := gitrepo.ParsePath(n.String())
		if err != nil || again != n {
			t.Fatalf("%q accepted as %v, which does not parse back (%v)", in, n, err)
		}
		if !strings.HasPrefix(in, "git-upload-pack '") || !strings.HasSuffix(in, "'") || len(in) > MaxCommandLen {
			t.Fatalf("%q accepted", in)
		}
		path := in[len("git-upload-pack '") : len(in)-1]
		if strings.Contains(path, "..") || strings.ContainsAny(path, "'\\!\x00\n ") {
			t.Fatalf("%q accepted with a dangerous path", in)
		}
		if strings.HasSuffix(strings.TrimSuffix(path, ".git"), "/") {
			t.Fatalf("%q accepted with an empty name", in)
		}
	})
}
