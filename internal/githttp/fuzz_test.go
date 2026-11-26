// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package githttp

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gittest"
)

func newHandlerForFuzz(tb testing.TB) *Handler {
	root := tb.TempDir()
	gittest.NewRepo(tb, root, "alice", "pub", true)
	return &Handler{
		Repos:    &gitrepo.Service{Root: root},
		Sessions: &gitrepo.Limiter{Total: 8, PerKey: 8},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// FuzzParsePath: whatever the path, the repository it names is a plain
// owner/name pair, and the endpoint is one of the three.
func FuzzParsePath(f *testing.F) {
	for _, s := range []string{
		"/alice/proj.git/info/refs", "/alice/proj/git-upload-pack", "/alice/proj.git/git-receive-pack",
		"/../alice/proj.git/info/refs", "/alice/proj.git/info/refs/", "//a/b/info/refs", "/a/b\x00/info/refs",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		n, ep, err := ParsePath(p)
		if err != nil {
			return
		}
		if ep != InfoRefs && ep != UploadPack && ep != ReceivePack {
			t.Fatalf("endpoint %d", ep)
		}
		for _, s := range []string{n.Owner, n.Repo} {
			if s == "" || strings.ContainsAny(s, "/\\ \x00") || strings.Contains(s, "..") {
				t.Fatalf("%q gave %+v", p, n)
			}
		}
	})
}

// FuzzRequest: no request line, header or body makes the handler fail
// other than by a status code.
func FuzzRequest(f *testing.F) {
	f.Add(uint8(0), "/alice/pub.git/info/refs", "service=git-upload-pack", "version=2", "")
	f.Add(uint8(1), "/alice/pub.git/git-upload-pack", "", "version=2", "0014command=ls-refs\n0000")
	f.Add(uint8(1), "/x/y/git-receive-pack", "", "", "PACK")
	methods := []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"}
	h := newHandlerForFuzz(f)
	f.Fuzz(func(t *testing.T, m uint8, path, query, proto, body string) {
		req := &http.Request{
			Method: methods[int(m)%len(methods)],
			URL:    &url.URL{Path: path, RawQuery: query},
			Header: http.Header{"Git-Protocol": {proto}, "Content-Type": {typeRequest}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code < 200 || rec.Code > 599 {
			t.Fatalf("status %d", rec.Code)
		}
	})
}
