//go:build unix

package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/fidotest"
	"github.com/go-vcs/forge/internal/web"
)

func TestWebPortInUseStopsTheOthers(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	args, _, _ := baseArgs(t, a, 0o600)
	args = append(args, "--web-listen", busy.Addr().String())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, _, err := run(t, ctx, args); err == nil || ctx.Err() != nil {
		t.Fatalf("a busy web port: err = %v (ctx %v), want an immediate refusal", err, ctx.Err())
	}
}

// A repositories root the web pages cannot use stops serve before anything
// listens.
func TestWebReposRootAbsent(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	args, _, _ := baseArgs(t, a, 0o600)
	args = append(args, "--web-listen", "127.0.0.1:0", "--repos-root", t.TempDir()+"/nope")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, _, err := run(t, ctx, args)
	if err == nil || ctx.Err() != nil || !strings.Contains(err.Error(), "repositories root") {
		t.Fatalf("an absent repositories root: err = %v (ctx %v)", err, ctx.Err())
	}
}

// The web listener speaks TLS 1.3 only, serves the sign-in page and the
// security headers, and stops cleanly.
func TestServeWeb(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	args, pool, _ := baseArgs(t, a, 0o600)
	args = append(args, "--web-listen", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var out lockedBuf
	done := make(chan error, 1)
	go func() {
		c := RootCmd()
		c.SetArgs(args)
		c.SetOut(&out)
		c.SetErr(&lockedBuf{})
		done <- c.ExecuteContext(ctx)
	}()
	const pfx = "web listening on "
	waitFor(t, &out, pfx)
	line := out.String()
	addr := strings.TrimSpace(strings.SplitN(line[strings.Index(line, pfx)+len(pfx):], "\n", 2)[0])

	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	r, err := cl.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !strings.Contains(string(b), "/login") || r.Header.Get("Content-Security-Policy") != web.CSP {
		t.Fatalf("home: %d %v\n%s", r.StatusCode, r.Header, b)
	}
	// no registration yet: sign-in is unavailable, and says so
	nr := &http.Client{Transport: cl.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if r, err := nr.Get("https://" + addr + "/login"); err != nil || r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("login without a registration: %v %v", r, err)
	}
	// TLS 1.2 is refused
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS12}}}
	if _, err := old.Get("https://" + addr + "/"); err == nil {
		t.Fatal("a TLS 1.2 client was served")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned %v after a clean stop", err)
	}
}
