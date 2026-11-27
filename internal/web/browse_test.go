// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package web_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gittest"
	"github.com/go-vcs/forge/internal/gitview"
	"github.com/go-vcs/forge/internal/web"
)

// repos is a root with alice/pub (public) and alice/priv (private).
type repos struct {
	root, work string
}

func newRepos(t *testing.T) (*repos, func(*web.Server)) {
	t.Helper()
	root := t.TempDir()
	r := &repos{root: root, work: gittest.NewRepo(t, root, "alice", "pub", true)}
	gittest.NewRepo(t, root, "alice", "priv", false)
	return r, func(s *web.Server) {
		s.Repos = &gitrepo.Service{Root: root}
		s.Limiter = &gitrepo.Limiter{Total: 64, PerKey: 64}
	}
}

// commit adds files to alice/pub in one commit.
func (r *repos) commit(t *testing.T, msg string, files map[string][]byte) {
	t.Helper()
	for name, b := range files {
		p := filepath.Join(r.work, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gittest.Git(t, r.work, "add", "-A")
	gittest.Git(t, r.work, "commit", "-q", "-m", msg)
	gittest.Git(t, r.work, "push", "-q", filepath.Join(r.root, "alice", "pub.git"), "main")
}

func (r *repos) head(t *testing.T, repo string) string {
	return gittest.Git(t, filepath.Join(r.root, "alice", repo+".git"), "rev-parse", "main")
}

func (e *env) anon() *http.Client {
	return &http.Client{Transport: e.ts.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// fetch returns the status, headers and body of one GET.
func fetch(t *testing.T, c *http.Client, u string) (int, http.Header, string) {
	t.Helper()
	r := get(t, c, u)
	b := body(t, r)
	if r.Header.Get("Content-Security-Policy") != web.CSP {
		t.Errorf("%s: CSP = %q", u, r.Header.Get("Content-Security-Policy"))
	}
	if r.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("%s: no nosniff", u)
	}
	return r.StatusCode, r.Header, b
}

func TestBrowsePublicAnonymous(t *testing.T) {
	r, opt := newRepos(t)
	e := newEnv(t, opt)
	c := e.anon()
	sha := r.head(t, "pub")
	base := e.ts.URL + "/alice/pub"

	code, _, b := fetch(t, c, base)
	if code != 200 || !strings.Contains(b, `href="/alice/pub/blob/HEAD/f.txt"`) {
		t.Fatalf("home: %d\n%s", code, b)
	}
	for _, ref := range []string{"main", "v1", sha, "HEAD"} {
		code, _, b = fetch(t, c, base+"/tree/"+ref)
		if code != 200 || !strings.Contains(b, "f.txt") {
			t.Errorf("tree %s: %d", ref, code)
		}
		code, _, b = fetch(t, c, base+"/blob/"+ref+"/f.txt")
		if code != 200 || !strings.Contains(b, "three") {
			t.Errorf("blob %s: %d", ref, code)
		}
	}
	code, h, b := fetch(t, c, base+"/raw/main/f.txt")
	if code != 200 || h.Get("Content-Type") != "text/plain; charset=utf-8" || b != strings.Repeat("three\n", 200) {
		t.Errorf("raw: %d %q len %d", code, h.Get("Content-Type"), len(b))
	}
	code, _, b = fetch(t, c, base+"/commits/main")
	i3, i2, i1 := strings.Index(b, ">three<"), strings.Index(b, ">two<"), strings.Index(b, ">one<")
	if code != 200 || !(i3 > 0 && i3 < i2 && i2 < i1) {
		t.Errorf("log order: %d %d %d", i3, i2, i1)
	}
	if strings.Contains(b, "example.org") {
		t.Error("the log shows an e-mail address")
	}
	code, _, b = fetch(t, c, base+"/commit/"+sha)
	if code != 200 || !strings.Contains(b, `<span class="del">-two</span>`) || !strings.Contains(b, `<span class="add">&#43;three</span>`) {
		t.Errorf("commit: %d\n%s", code, b)
	}
	if strings.Contains(b, "example.org") {
		t.Error("the commit page shows an e-mail address")
	}
	// the page of a directory sends a file to its blob page, and the other way
	for u, want := range map[string]string{
		base + "/tree/main/f.txt": "/alice/pub/blob/main/f.txt",
	} {
		r := get(t, c, u)
		body(t, r)
		if r.StatusCode != 302 || r.Header.Get("Location") != want {
			t.Errorf("%s: %d %q", u, r.StatusCode, r.Header.Get("Location"))
		}
	}
}

func TestBrowseDirectories(t *testing.T) {
	r, opt := newRepos(t)
	e := newEnv(t, opt)
	r.commit(t, "dirs", map[string][]byte{"d/e/g.txt": []byte("deep\n")})
	c := e.anon()
	base := e.ts.URL + "/alice/pub"
	code, _, b := fetch(t, c, base+"/tree/main/d/e/")
	if code != 200 || !strings.Contains(b, `href="/alice/pub/blob/main/d/e/g.txt"`) || !strings.Contains(b, `href="/alice/pub/tree/main/d">d</a>`) {
		t.Errorf("tree d/e: %d\n%s", code, b)
	}
	resp := get(t, c, base+"/blob/main/d")
	body(t, resp)
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/alice/pub/tree/main/d" {
		t.Errorf("blob of a directory: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, u := range []string{"/raw/main", "/raw/main/d", "/blob/main", "/blob/main/nope.txt", "/tree/main/nope", "/tree/nope"} {
		if code, _, _ := fetch(t, c, base+u); code != 404 {
			t.Errorf("%s: %d", u, code)
		}
	}
}

func TestPrivateRepositoryIsNotFound(t *testing.T) {
	r, opt := newRepos(t)
	e := newEnv(t, opt)
	sha := r.head(t, "priv")
	paths := []string{"", "/tree/main", "/tree/main/f.txt", "/blob/main/f.txt", "/raw/main/f.txt", "/commits/main", "/commit/" + sha}
	anon := e.anon()
	for _, p := range paths {
		code, _, b := fetch(t, anon, e.ts.URL+"/alice/priv"+p)
		_, _, nb := fetch(t, anon, e.ts.URL+"/alice/nope"+p)
		if code != 404 {
			t.Errorf("anonymous %q: %d", p, code)
		}
		if b != nb {
			t.Errorf("%q: a private repository and a missing one answer differently", p)
		}
		if strings.Contains(b, "three") {
			t.Errorf("%q leaks content", p)
		}
	}
	e.signedIn()
	for _, p := range paths {
		want := 200
		if p == "/tree/main/f.txt" { // a file: sent to its blob page
			want = 302
		}
		if code, _, _ := fetch(t, e.b, e.ts.URL+"/alice/priv"+p); code != want {
			t.Errorf("owner %q: %d", p, code)
		}
	}
	// a name the rule does not allow is not even looked up
	for _, u := range []string{"/Alice/pub", "/alice/../pub", "/alice/pub.git", "/alice/.x"} {
		if code, _, _ := fetch(t, anon, e.ts.URL+u); code == 200 {
			t.Errorf("%s: 200", u)
		}
	}
}

func TestBrowseRefusals(t *testing.T) {
	_, opt := newRepos(t)
	e := newEnv(t, opt)
	c := e.anon()
	base := e.ts.URL + "/alice/pub"
	sha := strings.Repeat("a", 40)
	urls := []string{
		"/tree/-x", "/tree/--upload-pack=x", "/tree/main..v1", "/tree/refs%2Fheads%2Fmain", "/tree/main:f.txt", "/tree/main%5E",
		"/tree/HEAD~1", "/tree/@%7Bu%7D", "/tree/" + strings.Repeat("a", 101), "/tree/" + strings.ToUpper(sha),
		"/blob/main/..%2f..%2fetc%2fpasswd", "/blob/main/%2e%2e/f.txt", "/blob/main/f.txt/..", "/blob/main/%00",
		"/blob/main/a%5Cb", "/blob/main/a%0Ab", "/blob/main/%ff", "/blob/main/a%7Fb", "/blob/main/a//b",
		"/blob/main/" + strings.Repeat("a", gitview.MaxPathLen+1),
		"/blob/main/" + strings.Repeat("a/", gitview.MaxDepth+1) + "a",
		"/raw/main/%2e%2e/f.txt", "/raw/--/f.txt",
		"/commit/abc", "/commit/" + strings.Repeat("g", 40), "/commit/main", "/commit/" + sha, "/commit/" + sha[:39],
		"/commits/main?skip=10001", "/commits/main?skip=-1", "/commits/main?skip=x", "/commits/main?skip=99999999999999999999",
		"/commits/-x", "/commits/nope",
	}
	for _, u := range urls {
		code, _, b := fetch(t, c, base+u)
		if code == 200 || code >= 500 {
			t.Errorf("%s: %d", u, code)
		}
		if strings.Contains(b, "root:") || strings.Contains(b, "three") {
			t.Errorf("%s: leaks", u)
		}
	}
}

func TestRawNeverRendersAnything(t *testing.T) {
	r, opt := newRepos(t)
	e := newEnv(t, opt)
	r.commit(t, "files", map[string][]byte{
		"x.html":    []byte("<script>alert(1)</script>"),
		"x.svg":     []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`),
		"x.bin":     {0x89, 'P', 'N', 'G', 0, 1, 2},
		"big.txt":   []byte(strings.Repeat("y", gitview.MaxBlobView+10)),
		"huge.txt":  []byte(strings.Repeat("z", gitview.MaxRaw+10)),
		"latin.txt": {0xe9, 'a', '\n'},
	})
	c := e.anon()
	base := e.ts.URL + "/alice/pub"
	for _, f := range []string{"x.html", "x.svg"} {
		code, h, _ := fetch(t, c, base+"/raw/main/"+f)
		if code != 200 || h.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("%s: %d %q", f, code, h.Get("Content-Type"))
		}
	}
	code, h, _ := fetch(t, c, base+"/raw/main/x.bin")
	if code != 200 || h.Get("Content-Type") != "application/octet-stream" || h.Get("Content-Disposition") != "attachment" {
		t.Errorf("x.bin: %d %v", code, h)
	}
	code, h, _ = fetch(t, c, base+"/raw/main/latin.txt") // not UTF-8: a download
	if code != 200 || h.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("latin.txt: %d %q", code, h.Get("Content-Type"))
	}
	_, _, b := fetch(t, c, base+"/blob/main/x.bin")
	if !strings.Contains(b, "This file is binary") || strings.Contains(b, "PNG") {
		t.Errorf("binary blob page:\n%s", b)
	}
	_, _, b = fetch(t, c, base+"/blob/main/big.txt")
	if !strings.Contains(b, "too large to show") || strings.Contains(b, "yyyy") {
		t.Errorf("a blob over the bound is shown (%d bytes)", len(b))
	}
	if code, _, b = fetch(t, c, base+"/raw/main/big.txt"); code != 200 || len(b) != gitview.MaxBlobView+10 {
		t.Errorf("raw of a big blob: %d len %d", code, len(b))
	}
	if code, _, b = fetch(t, c, base+"/raw/main/huge.txt"); code != http.StatusRequestEntityTooLarge || strings.Contains(b, "zzzz") {
		t.Errorf("raw over the bound: %d", code)
	}
}

func TestBrowseBounds(t *testing.T) {
	r, opt := newRepos(t)
	e := newEnv(t, opt)
	files := map[string][]byte{}
	for i := 0; i < gitview.MaxTreeEntries+1; i++ {
		files[fmt.Sprintf("many/f%05d", i)] = nil
	}
	var big strings.Builder
	for i := 0; big.Len() < 2*gitview.MaxDiff; i++ {
		fmt.Fprintf(&big, "line %d\n", i)
	}
	files["diff.txt"] = []byte(big.String())
	r.commit(t, "bounds", files)
	c := e.anon()
	base := e.ts.URL + "/alice/pub"
	code, _, b := fetch(t, c, base+"/tree/main/many")
	if code != 200 || strings.Count(b, "<tr>") != gitview.MaxTreeEntries || !strings.Contains(b, "The listing is cut") {
		t.Errorf("tree cap: %d, %d rows", code, strings.Count(b, "<tr>"))
	}
	code, _, b = fetch(t, c, base+"/commit/"+r.head(t, "pub"))
	if code != 200 || !strings.Contains(b, "The diff is cut") || len(b) > 10*gitview.MaxDiff {
		t.Errorf("diff cap: %d, %d bytes", code, len(b))
	}
}

func TestLogPaging(t *testing.T) {
	r, opt := newRepos(t)
	e := newEnv(t, opt)
	for i := 0; i < 52; i++ {
		gittest.Git(t, r.work, "commit", "-q", "--allow-empty", "-m", fmt.Sprintf("empty %d", i))
	}
	gittest.Git(t, r.work, "push", "-q", filepath.Join(r.root, "alice", "pub.git"), "main")
	c := e.anon()
	base := e.ts.URL + "/alice/pub/commits/main"
	_, _, b := fetch(t, c, base)
	if n := strings.Count(b, "<tr>"); n != gitview.LogPage || !strings.Contains(b, `href="/alice/pub/commits/main?skip=50"`) || strings.Contains(b, ">Newer<") {
		t.Errorf("first page: %d rows", n)
	}
	_, _, b = fetch(t, c, base+"?skip=50")
	if n := strings.Count(b, "<tr>"); n != 5 || strings.Contains(b, ">Older<") || !strings.Contains(b, `href="/alice/pub/commits/main?skip=0"`) {
		t.Errorf("second page: %d rows", n)
	}
	if code, _, _ := fetch(t, c, base+"?skip=10000"); code != 200 {
		t.Errorf("skip at the bound: %d", code)
	}
}

func TestBrowseBusyAndOff(t *testing.T) {
	_, opt := newRepos(t)
	e := newEnv(t, opt, func(s *web.Server) { s.Limiter = &gitrepo.Limiter{Total: 0, PerKey: 1} })
	r := get(t, e.anon(), e.ts.URL+"/alice/pub")
	body(t, r)
	if r.StatusCode != 503 || r.Header.Get("Retry-After") == "" {
		t.Errorf("a full limiter: %d", r.StatusCode)
	}
	// a repository that does not exist does not take a slot
	if code, _, _ := fetch(t, e.anon(), e.ts.URL+"/alice/nope"); code != 404 {
		t.Errorf("missing repository: %d", code)
	}
	off := newEnv(t)
	if code, _, _ := fetch(t, off.anon(), off.ts.URL+"/alice/pub"); code != 404 {
		t.Errorf("no repositories root: %d", code)
	}
}
