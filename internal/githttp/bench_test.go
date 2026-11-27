// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package githttp

import (
	"io"
	"log/slog"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gittest"
)

// BenchmarkClone clones the same repository with the real git client through
// this handler and through git http-backend (CGI), both over plain HTTP. The
// two are interleaved, one clone each per iteration with the order
// alternating, and the result carries both times and their ratio.
func BenchmarkClone(b *testing.B) {
	git, err := exec.LookPath("git")
	if err != nil {
		b.Skip("no git")
	}
	root := b.TempDir()
	if src := os.Getenv("FORGE_BENCH_REPO"); src != "" {
		// a large repository: FORGE_BENCH_REPO is a clone to serve as alice/pub
		gittest.Git(b, root, "clone", "-q", "--bare", src, filepath.Join(root, "alice", "pub.git"))
		if err := os.WriteFile(filepath.Join(root, "alice", "pub.git", "git-daemon-export-ok"), nil, 0o644); err != nil {
			b.Fatal(err)
		}
	} else {
		gittest.NewRepo(b, root, "alice", "pub", true)
	}
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

	dir := b.TempDir()
	clone := func(url, tag string, i int) time.Duration {
		dst := filepath.Join(dir, tag, string(rune('a'+i%26)), "x"+string(rune('a'+i/26%26)))
		t0 := time.Now()
		gittest.Git(b, dir, "-c", "protocol.version=2", "clone", "-q", url+"/alice/pub.git", dst)
		return time.Since(t0)
	}
	var forgeT, gitT time.Duration
	var forgeBytes, forgeMallocs uint64
	var m0, m1 runtime.MemStats
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for k := 0; k < 2; k++ {
			if (i+k)%2 == 0 {
				runtime.ReadMemStats(&m0)
				forgeT += clone(forge.URL, "forge", i)
				runtime.ReadMemStats(&m1)
				forgeBytes += m1.TotalAlloc - m0.TotalAlloc
				forgeMallocs += m1.Mallocs - m0.Mallocs
			} else {
				gitT += clone(backend.URL, "backend", i)
			}
		}
	}
	n := float64(b.N)
	b.ReportMetric(float64(forgeT)/n, "forge-ns/op")
	b.ReportMetric(float64(gitT)/n, "git-http-backend-ns/op")
	b.ReportMetric(float64(forgeT)/float64(gitT), "forge/git")
	// Everything the process allocated during a forge clone: the handler plus
	// the Go side of the harness (starting and reaping the git client).
	b.ReportMetric(float64(forgeBytes)/n, "forge-B/op")
	b.ReportMetric(float64(forgeMallocs)/n, "forge-allocs/op")
}
