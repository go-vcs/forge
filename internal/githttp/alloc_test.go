// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package githttp

import (
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gittest"
)

// countWriter is a ResponseWriter that keeps nothing but the byte count.
type countWriter struct {
	h http.Header
	n int64
}

func (c *countWriter) Header() http.Header         { return c.h }
func (c *countWriter) WriteHeader(int)             {}
func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// TestFetchAllocationsDoNotScaleWithThePack serves a fetch of a pack of about
// 4 MiB (incompressible) and asserts the server allocates a small fraction of
// it: the reply is streamed through reused buffers, not copied per frame. Before
// gitproto reused its sideband frame buffer, a fetch allocated about 1.3 times
// the pack in frames alone.
func TestFetchAllocationsDoNotScaleWithThePack(t *testing.T) {
	root := t.TempDir()
	work := gittest.NewRepo(t, root, "alice", "big", true)
	blob := make([]byte, 4<<20)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < len(blob); i += 8 {
		v := rng.Uint64()
		for j := 0; j < 8; j++ {
			blob[i+j] = byte(v >> (8 * j))
		}
	}
	if err := os.WriteFile(filepath.Join(work, "big.bin"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	gittest.Git(t, work, "add", "big.bin")
	gittest.Git(t, work, "commit", "-q", "-m", "big")
	gittest.Git(t, work, "push", "-q", filepath.Join(root, "alice", "big.git"), "main")
	head := gittest.Git(t, work, "rev-parse", "HEAD")

	h := &Handler{
		Repos:    &gitrepo.Service{Root: root},
		Sessions: &gitrepo.Limiter{Total: 8, PerKey: 8},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	body := pkt("command=fetch\n") + pkt("agent=test\n") + delim + pkt("no-progress\n") + pkt("want "+head+"\n") + pkt("done\n") + flush
	serve := func() int64 {
		r := httptest.NewRequest(http.MethodPost, "/alice/big.git/git-upload-pack", strings.NewReader(body))
		r.Header.Set("Git-Protocol", "version=2")
		r.Header.Set("Content-Type", typeRequest)
		w := &countWriter{h: http.Header{}}
		h.ServeHTTP(w, r)
		return w.n
	}
	serve() // warm: first open of the repository
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	sent := serve()
	runtime.ReadMemStats(&after)
	if sent < 4<<20 {
		t.Fatalf("reply is %d bytes, want at least the 4 MiB blob", sent)
	}
	bytes, mallocs := after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs
	t.Logf("reply %d bytes; allocated %d bytes in %d allocations", sent, bytes, mallocs)
	if bytes > uint64(sent)/8 {
		t.Errorf("allocated %d bytes to send %d: more than an eighth of the reply", bytes, sent)
	}
	if mallocs > 600 {
		t.Errorf("%d allocations for one fetch, want at most 600", mallocs)
	}
}
