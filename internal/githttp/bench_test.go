// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package githttp

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gittest"
)

// BenchmarkClone clones the same repository with the real git client through
// this handler and through git http-backend (CGI), both over plain HTTP.
func BenchmarkClone(b *testing.B) {
	git, err := exec.LookPath("git")
	if err != nil {
		b.Skip("no git")
	}
	root := b.TempDir()
	gittest.NewRepo(b, root, "alice", "pub", true)
	forge := httptest.NewServer(&Handler{
		Repos:    &gitrepo.Service{Root: root},
		Sessions: &gitrepo.Limiter{Total: 8, PerKey: 8},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer forge.Close()
	backend := httptest.NewServer(&cgi.Handler{
		Path: git, Args: []string{"http-backend"}, Root: "/",
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"},
	})
	defer backend.Close()
	for _, c := range []struct {
		name string
		h    http.Handler
		url  string
	}{{"forge", nil, forge.URL}, {"git-http-backend", nil, backend.URL}} {
		b.Run(c.name, func(b *testing.B) {
			dir := b.TempDir()
			for i := 0; i < b.N; i++ {
				gittest.Git(b, dir, "-c", "protocol.version=2", "clone", "-q", c.url+"/alice/pub.git", filepath.Join(dir, "c", string(rune('a'+i%26)), "x"+string(rune('a'+i/26%26))))
			}
		})
	}
}
