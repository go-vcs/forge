// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package web_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gittest"
	"github.com/go-vcs/forge/internal/web"
)

// FuzzBrowse sends any path under a public repository. Whatever it is, the
// answer is not a server error, carries the security headers, and a page is
// never served as anything a browser would run: HTML pages hold no script, and
// raw is text or a download.
func FuzzBrowse(f *testing.F) {
	root := f.TempDir()
	gittest.NewRepo(f, root, "alice", "pub", true)
	gittest.NewRepo(f, root, "alice", "priv", false)
	h := (&web.Server{Repos: &gitrepo.Service{Root: root}, Limiter: &gitrepo.Limiter{Total: 1 << 20, PerKey: 1 << 20}}).Handler()
	for _, s := range []string{"/alice/pub", "/alice/pub/tree/main/", "/alice/pub/blob/main/f.txt", "/alice/pub/raw/v1/f.txt",
		"/alice/pub/commits/main?skip=50", "/alice/priv/tree/main", "/alice/pub/blob/main/../f.txt", "/alice/pub/tree/-x/",
		"/alice/pub/blob/main/%00", "/alice/pub/commit/main", "/alice/pub.git/tree/main", "/alice/pub/tree/main/f.txt/"} {
		path, q, _ := strings.Cut(s, "?")
		f.Add(path, q)
	}
	f.Fuzz(func(t *testing.T, path, query string) {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		u := &url.URL{Path: path, RawQuery: query}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL, req.RequestURI = u, u.RequestURI()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		res := w.Result()
		if res.StatusCode >= 500 {
			t.Fatalf("%q?%q: %d\n%s", path, query, res.StatusCode, w.Body.String())
		}
		if res.StatusCode == 200 && strings.Contains(path, "/priv") {
			t.Fatalf("%q: a private repository answered 200 to an anonymous reader", path)
		}
		if res.Header.Get("Content-Security-Policy") != web.CSP || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%q: security headers missing", path)
		}
		ct := res.Header.Get("Content-Type")
		switch {
		case strings.HasPrefix(ct, "text/html"):
			if b := strings.ToLower(w.Body.String()); strings.Contains(b, "<script") || strings.Contains(b, " onerror") || strings.Contains(b, "javascript:") {
				t.Fatalf("%q: script in a page", path)
			}
		case ct == "text/plain; charset=utf-8", ct == "application/octet-stream", ct == "text/css; charset=utf-8", strings.HasPrefix(ct, "text/plain"):
		case res.StatusCode >= 300 && res.StatusCode < 400:
		default:
			t.Fatalf("%q: content type %q", path, ct)
		}
	})
}
