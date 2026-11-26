// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package githttp

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-vcs/gitproto"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gittest"
)

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

const (
	flush = "0000"
	delim = "0001"
)

func lsRefs(prefixes ...string) string {
	s := pkt("command=ls-refs\n") + pkt("agent=test\n") + delim + pkt("peel\n")
	for _, p := range prefixes {
		s += pkt("ref-prefix " + p + "\n")
	}
	return s + flush
}

type rig struct {
	root string
	url  string
	h    *Handler
}

func newRig(t *testing.T, tweak func(*Handler)) *rig {
	t.Helper()
	root := t.TempDir()
	h := &Handler{
		Repos:    &gitrepo.Service{Root: root},
		Sessions: &gitrepo.Limiter{Total: 8, PerKey: 4},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if tweak != nil {
		tweak(h)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	gittest.NewRepo(t, root, "alice", "pub", true)
	gittest.NewRepo(t, root, "alice", "priv", false)
	return &rig{root: root, url: srv.URL, h: h}
}

func (r *rig) do(t *testing.T, method, path string, hdr map[string]string, body io.Reader) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(method, r.url+path, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

var v2 = map[string]string{"Git-Protocol": "version=2"}

func post(extra map[string]string) map[string]string {
	h := map[string]string{"Git-Protocol": "version=2", "Content-Type": typeRequest}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

func TestParsePath(t *testing.T) {
	ok := map[string]struct {
		n  string
		ep Endpoint
	}{
		"/alice/proj.git/info/refs":        {"alice/proj", InfoRefs},
		"/alice/proj/info/refs":            {"alice/proj", InfoRefs},
		"/alice/proj.git/git-upload-pack":  {"alice/proj", UploadPack},
		"/alice/proj.git/git-receive-pack": {"alice/proj", ReceivePack},
	}
	for in, w := range ok {
		n, ep, err := ParsePath(in)
		if err != nil || n.String() != w.n || ep != w.ep {
			t.Errorf("ParsePath(%q) = %v %v %v", in, n, ep, err)
		}
	}
	for _, in := range []string{
		"", "/", "info/refs", "/info/refs", "/alice/info/refs", "/alice/proj.git", "/alice/proj.git/",
		"/alice/proj.git/HEAD", "/alice/proj.git/objects/info/packs", "/../alice/proj.git/info/refs",
		"/alice/../info/refs", "//alice/proj.git/info/refs", "/alice//proj.git/info/refs",
		"/Alice/proj.git/info/refs", "/alice/pr oj.git/info/refs", "/alice/proj.git/info/refs/x",
		"/alice/proj.git/info/refs\x00", "/alice/proj%2e.git/info/refs", "/alice/a/b.git/info/refs",
		"/" + strings.Repeat("a", MaxPathLen) + "/info/refs", "alice/proj.git/info/refs",
		"/alice/" + strings.Repeat("a", MaxPathLen-len("/alice//info/refs")) + "/info/refs",
	} {
		if n, ep, err := ParsePath(in); !errors.Is(err, ErrRoute) {
			t.Errorf("ParsePath(%q) = %v %v %v, want ErrRoute", in, n, ep, err)
		}
	}
}

func TestAdvertisement(t *testing.T) {
	r := newRig(t, nil)
	code, h, body := r.do(t, "GET", "/alice/pub.git/info/refs?service=git-upload-pack", v2, nil)
	if code != 200 || !strings.HasPrefix(body, "000eversion 2\n") {
		t.Fatalf("%d %q", code, body)
	}
	if h.Get("Content-Type") != typeAdvertisement || h.Get("Cache-Control") != "no-cache" {
		t.Fatalf("headers %v", h)
	}
	if strings.Contains(body, "# service=") {
		t.Fatal("a version 0 preamble was sent")
	}
	// the suffix-less repository name works too, and extra parameters are carried
	if code, _, _ := r.do(t, "GET", "/alice/pub/info/refs?service=git-upload-pack", map[string]string{"Git-Protocol": "foo=1:version=2"}, nil); code != 200 {
		t.Fatalf("code %d", code)
	}
}

func TestRequestAndGzip(t *testing.T) {
	r := newRig(t, nil)
	code, h, body := r.do(t, "POST", "/alice/pub.git/git-upload-pack", post(nil), strings.NewReader(lsRefs("refs/heads/")))
	if code != 200 || !strings.Contains(body, "refs/heads/main") || h.Get("Content-Type") != typeResult {
		t.Fatalf("%d %v %q", code, h, body)
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write([]byte(lsRefs("refs/tags/")))
	zw.Close()
	code, _, body = r.do(t, "POST", "/alice/pub.git/git-upload-pack", post(map[string]string{"Content-Encoding": "gzip"}), &z)
	if code != 200 || !strings.Contains(body, "refs/tags/v1") {
		t.Fatalf("gzip: %d %q", code, body)
	}
}

func TestRefusals(t *testing.T) {
	r := newRig(t, nil)
	info := "/alice/pub.git/info/refs?service=git-upload-pack"
	up := "/alice/pub.git/git-upload-pack"
	for name, c := range map[string]struct {
		method, path string
		hdr          map[string]string
		body         string
		code         int
		msg          string
	}{
		"push advertisement":  {"GET", "/alice/pub.git/info/refs?service=git-receive-pack", v2, "", 403, "milestone 4"},
		"push request":        {"POST", "/alice/pub.git/git-receive-pack", post(nil), "0000", 403, "milestone 4"},
		"dumb protocol":       {"GET", "/alice/pub.git/info/refs", v2, "", 403, "smart HTTP"},
		"another service":     {"GET", "/alice/pub.git/info/refs?service=x", v2, "", 403, "smart HTTP"},
		"extra query":         {"GET", info + "&a=b", v2, "", 403, "smart HTTP"},
		"no protocol header":  {"GET", info, nil, "", 400, "version 2 is required"},
		"protocol v1":         {"GET", info, map[string]string{"Git-Protocol": "version=1"}, "", 400, "version 2 is required"},
		"protocol v2 as part": {"GET", info, map[string]string{"Git-Protocol": "version=22"}, "", 400, "version 2 is required"},
		"post without header": {"POST", up, map[string]string{"Content-Type": typeRequest}, "0000", 400, "version 2 is required"},
		"info by POST":        {"POST", info, v2, "", 405, "use GET"},
		"upload by GET":       {"GET", up, v2, "", 405, "use POST"},
		"wrong content type":  {"POST", up, post(map[string]string{"Content-Type": "text/plain"}), "0000", 415, "Content-Type"},
		"wrong encoding":      {"POST", up, post(map[string]string{"Content-Encoding": "br"}), "0000", 415, "Content-Encoding"},
		"bad gzip":            {"POST", up, post(map[string]string{"Content-Encoding": "gzip"}), "not gzip at all", 400, "gzip"},
		"empty request":       {"POST", up, post(nil), "0000", 400, "empty request"},
		"no body":             {"POST", up, post(nil), "", 400, "empty request"},
		"unknown path":        {"GET", "/alice/pub.git/HEAD", v2, "", 404, "not found"},
		"unknown path no hdr": {"GET", "/alice/pub.git/HEAD", nil, "", 404, "not found"},
		"encoded path":        {"GET", "/alice/pub%2egit/info/refs?service=git-upload-pack", v2, "", 404, "not found"},
	} {
		code, _, body := r.do(t, c.method, c.path, c.hdr, strings.NewReader(c.body))
		if code != c.code || !strings.Contains(body, c.msg) {
			t.Errorf("%s: %d %q, want %d %q", name, code, body, c.code, c.msg)
		}
	}
}

func TestPrivateAndMissingAnswerAlike(t *testing.T) {
	r := newRig(t, nil)
	var first string
	for i, p := range []string{"/alice/priv.git", "/alice/absent.git", "/bob/x.git"} {
		for _, hdr := range []map[string]string{v2, {"Git-Protocol": "version=2", "Authorization": "Bearer x"}} {
			code, _, body := r.do(t, "GET", p+"/info/refs?service=git-upload-pack", hdr, nil)
			if code != 404 {
				t.Fatalf("%s: %d", p, code)
			}
			if i == 0 {
				first = body
			} else if body != first {
				t.Fatalf("%s answers %q, the private repository %q", p, body, first)
			}
		}
		code, _, _ := r.do(t, "POST", p+"/git-upload-pack", post(nil), strings.NewReader(lsRefs()))
		if code != 404 {
			t.Fatalf("%s POST: %d", p, code)
		}
	}
}

func TestBodyAndRequestSizeAreBounded(t *testing.T) {
	r := newRig(t, func(h *Handler) {
		h.MaxBody = 300
		h.Repos.Limits = gitproto.Limits{MaxRequestLines: 6, MaxRequestBytes: 200}
	})
	up := "/alice/pub.git/git-upload-pack"
	// within the bounds
	if code, _, body := r.do(t, "POST", up, post(nil), strings.NewReader(lsRefs("refs/heads/"))); code != 200 || !strings.Contains(body, "refs/heads/main") {
		t.Fatalf("%d %q", code, body)
	}
	// the body as sent is over MaxBody
	big := newRig(t, func(h *Handler) { h.MaxBody = 300 })
	code, _, b := big.do(t, "POST", up, post(nil), strings.NewReader(lsRefs(strings.Repeat("a", 400))))
	if !strings.Contains(b, "ERR") || strings.Contains(b, "refs/") {
		t.Fatalf("a body over MaxBody: %d %q", code, b)
	}
	// too many pkt-lines: gitproto answers with an ERR line
	many := make([]string, 12)
	for i := range many {
		many[i] = "r"
	}
	code, _, body := r.do(t, "POST", up, post(nil), strings.NewReader(lsRefs(many...)))
	if !strings.Contains(body, "ERR") {
		t.Fatalf("pkt-line count: %d %q", code, body)
	}
	// too many bytes in few lines, within MaxBody
	code, _, body = r.do(t, "POST", up, post(nil), strings.NewReader(lsRefs(strings.Repeat("a", 250))))
	if !strings.Contains(body, "ERR") {
		t.Fatalf("request size: %d %q", code, body)
	}
}

func TestGzipBombIsRefused(t *testing.T) {
	r := newRig(t, func(h *Handler) {
		h.Repos.Limits = gitproto.Limits{MaxRequestBytes: 4096}
	})
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	// a few KiB sent, megabytes once inflated: a valid pkt-line stream
	line := pkt("ref-prefix " + strings.Repeat("a", 900) + "\n")
	zw.Write([]byte(pkt("command=ls-refs\n") + delim))
	for i := 0; i < 20000; i++ {
		zw.Write([]byte(line))
	}
	zw.Close()
	if z.Len() > 1<<20 {
		t.Fatalf("test body not small: %d", z.Len())
	}
	code, _, body := r.do(t, "POST", "/alice/pub.git/git-upload-pack", post(map[string]string{"Content-Encoding": "gzip"}), &z)
	if !strings.Contains(body, "ERR") && code == 200 {
		t.Fatalf("an inflated body over the bound was served: %d %.80q", code, body)
	}
}

func TestSessionsAreBounded(t *testing.T) {
	r := newRig(t, func(h *Handler) { h.Sessions = &gitrepo.Limiter{Total: 1, PerKey: 1} })
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", r.url+"/alice/pub.git/git-upload-pack", pr)
	for k, v := range post(nil) {
		req.Header.Set(k, v)
	}
	done := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	// the session is open and waiting for the rest; a server that does not read
	// must fail this test, not hang it
	go pw.Write([]byte(pkt("command=ls-refs\n")))
	t.Cleanup(func() { pw.Close() })
	deadline := time.Now().Add(5 * time.Second)
	var code int
	var hdr http.Header
	for time.Now().Before(deadline) {
		code, hdr, _ = r.do(t, "GET", "/alice/pub.git/info/refs?service=git-upload-pack", v2, nil)
		if code == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code != http.StatusServiceUnavailable || hdr.Get("Retry-After") == "" {
		t.Fatalf("a second session beside a full limiter: %d %v", code, hdr)
	}
	pw.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the first request did not end")
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if code, _, _ = r.do(t, "GET", "/alice/pub.git/info/refs?service=git-upload-pack", v2, nil); code == 200 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the slot was not freed: %d", code)
}

func TestRequestTimeIsBounded(t *testing.T) {
	r := newRig(t, func(h *Handler) { h.RequestTimeout = 300 * time.Millisecond })
	c, err := net.Dial("tcp", strings.TrimPrefix(r.url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	first := pkt("command=ls-refs\n")
	fmt.Fprintf(c, "POST /alice/pub.git/git-upload-pack HTTP/1.1\r\nHost: x\r\nGit-Protocol: version=2\r\n"+
		"Content-Type: %s\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", typeRequest, len(first), first) // then the client stalls
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "ERR") {
		t.Fatalf("a stalled request: %d %q", resp.StatusCode, b)
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 3*time.Second {
		t.Fatalf("cut off after %v, want about 300 ms", d)
	}
}
