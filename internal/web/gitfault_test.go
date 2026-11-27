// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package web_test

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gitview"
	"github.com/go-vcs/forge/internal/web"
)

// The test binary doubles as the git the pages run. It runs the real git,
// except for the command a "fault" file in the repository names: then it exits
// non-zero ("exit"), prints rubbish ("garbage"), prints more than any bound
// ("big"), or claims an object has a huge size ("huge").
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "--no-pager" {
		fakeGit()
	}
	os.Exit(m.Run())
}

func fakeGit() {
	args := os.Args[1:]
	dir := ""
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		if strings.HasPrefix(args[i], "--git-dir=") {
			dir = strings.TrimPrefix(args[i], "--git-dir=")
		}
		if args[i] == "-c" {
			i++
		}
		i++
	}
	key := args[i]
	if key == "cat-file" && i+1 < len(args) && args[i+1] != "--end-of-options" {
		key += " " + args[i+1]
	}
	if b, err := os.ReadFile(filepath.Join(dir, "fault")); err == nil {
		if f := strings.Fields(string(b)); len(f) == 2 || len(f) == 3 {
			want := f[0]
			if len(f) == 3 {
				want += " " + f[1]
			}
			if want == key {
				switch f[len(f)-1] {
				case "exit":
					os.Exit(128)
				case "garbage":
					fmt.Print("not an object id\n")
				case "big":
					fmt.Print(strings.Repeat("a", gitview.MaxRaw+10))
				case "text":
					fmt.Print("hello\n")
				case "hang":
					time.Sleep(time.Minute)
				case "huge":
					fmt.Print("99999999999\n")
				}
				os.Exit(0)
			}
		}
	}
	c := exec.Command("git", args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func (r *repos) fault(t *testing.T, spec string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.root, "alice", "pub.git", "fault"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBrowseGitFailures(t *testing.T) {
	r, _ := newRepos(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(s *web.Server) {
		s.Repos = &gitrepo.Service{Root: r.root, Git: exe}
		s.Limiter = &gitrepo.Limiter{Total: 64, PerKey: 64}
	})
	// a command that does not answer in time is a 504, whichever page waits
	slow := newEnv(t, func(s *web.Server) {
		s.Repos = &gitrepo.Service{Root: r.root, Git: exe}
		s.Limiter = &gitrepo.Limiter{Total: 64, PerKey: 64}
		s.GitTimeout = 3 * time.Second
	})
	r.commit(t, "dir", map[string][]byte{"d/x.txt": []byte("x\n")})
	c := e.anon()
	base := e.ts.URL + "/alice/pub"
	sha := r.head(t, "pub")

	cases := []struct {
		fault string
		url   string
		want  int
	}{
		{"", "/tree/main/d", 200},
		{"", "/blob/main/d/x.txt", 200},
		{"ls-tree exit", "/tree/main", 404},
		{"ls-tree exit", "", 404},
		{"rev-parse exit", "", 200},
		{"rev-parse garbage", "/tree/main", 404},
		{"rev-parse exit", "/tree/main", 404},
		{"rev-parse exit", "/commits/main", 404},
		{"cat-file -t exit", "/tree/main/d", 404},
		{"cat-file -t exit", "/blob/main/f.txt", 404},
		{"cat-file -t exit", "/raw/main/f.txt", 404},
		{"cat-file -s exit", "/blob/main/f.txt", 404},
		{"cat-file -s exit", "/raw/main/f.txt", 404},
		{"cat-file blob exit", "/blob/main/f.txt", 404},
		{"cat-file blob exit", "/raw/main/f.txt", 404},
		{"cat-file -s huge", "/raw/main/f.txt", 413},
		{"cat-file blob big", "/raw/main/f.txt", 413},
		// only the kind of the object decides that a directory is no file
		{"cat-file blob text", "/raw/main/d", 404},
		{"log exit", "/commits/main", 404},
		{"show exit", "/commit/" + sha, 404},
	}
	for _, tc := range cases {
		r.fault(t, tc.fault)
		code, _, b := fetch(t, c, base+tc.url)
		if code != tc.want {
			t.Errorf("%q on %q: %d, want %d", tc.fault, tc.url, code, tc.want)
		}
		if n := strings.Count(b, "</html>"); n != 1 {
			t.Errorf("%q on %q: %d pages in one response", tc.fault, tc.url, n)
		}
	}
	for _, tc := range []struct{ fault, url string }{
		{"rev-parse hang", ""}, {"rev-parse hang", "/tree/main/d"}, {"rev-parse hang", "/commits/main"},
		{"cat-file -t hang", "/raw/main/f.txt"},
	} {
		r.fault(t, tc.fault)
		if code, _, _ := fetch(t, slow.anon(), slow.ts.URL+"/alice/pub"+tc.url); code != http.StatusGatewayTimeout {
			t.Errorf("%q on %q: %d, want 504", tc.fault, tc.url, code)
		}
	}
	r.fault(t, "rev-parse exit")
	if _, _, b := fetch(t, c, base); !strings.Contains(b, "This repository is empty.") {
		t.Error("an unborn HEAD is not shown as an empty repository")
	}
	r.fault(t, "")

	// An error answers with one page, whichever check refuses.
	for _, u := range []string{"/tree/nosuch/f.txt", "/blob/nosuch/f.txt", "/raw/nosuch/f.txt", "/blob/main", "/raw/main",
		"/commits/nosuch", "/tree/main/a%5Cb", "/blob/main/a%5Cb", "/raw/main/a%5Cb"} {
		code, _, b := fetch(t, c, base+u)
		if code != http.StatusNotFound || strings.Count(b, "</html>") != 1 {
			t.Errorf("%s: %d, %d pages", u, code, strings.Count(b, "</html>"))
		}
	}

	// The root of a tree has one crumb: the repository.
	_, _, b := fetch(t, c, base+"/tree/main")
	if n := bytes.Count([]byte(b), []byte(`href="/alice/pub/tree/main"`)); n != 1 {
		t.Errorf("the root page has %d links to itself, want 1", n)
	}
}
