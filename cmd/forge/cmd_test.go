//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/adminclient"
	"github.com/go-vcs/forge/internal/attest"
	"github.com/go-vcs/forge/internal/fidotest"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// files writes a certificate and its key, returning their paths and a pool
// that trusts the certificate.
func files(t *testing.T, keyMode os.FileMode) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "forge test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(leaf)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	dir := shortDir(t)
	certPath, keyPath = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), keyMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, keyMode); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, pool
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "f")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func stubRoots(a *fidotest.Authenticator) {
	loadRoots = func(string) (attest.Roots, error) { return a, nil }
}

func restoreRoots(t *testing.T) {
	old := loadRoots
	t.Cleanup(func() { loadRoots = old })
}

func baseArgs(t *testing.T, a *fidotest.Authenticator, keyMode os.FileMode) (args []string, pool *x509.CertPool, sock string) {
	t.Helper()
	cert, key, pool := files(t, keyMode)
	dir := shortDir(t)
	sock = filepath.Join(dir, "e.sock")
	return []string{"serve",
		"--db", filepath.Join(dir, "forge.db"),
		"--admin-listen", "127.0.0.1:0",
		"--tls-cert", cert, "--tls-key", key,
		"--enrol-socket", sock,
		"--rp-id", "forge.test",
		"--aaguid", attest.FormatAAGUID(a.AAGUID),
		"--mds-blob", filepath.Join(dir, "blob.jwt"),
	}, pool, sock
}

func run(t *testing.T, ctx context.Context, args []string) (string, string, error) {
	t.Helper()
	var out, errb lockedBuf
	c := RootCmd()
	c.SetArgs(args)
	c.SetOut(&out)
	c.SetErr(&errb)
	err := c.ExecuteContext(ctx)
	return out.String(), errb.String(), err
}

// drop returns args without the flag (and its value).
func drop(args []string, flag string) []string {
	var r []string
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++
			continue
		}
		r = append(r, args[i])
	}
	return r
}

func TestServeRefusals(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	for _, tc := range []struct {
		name string
		mod  func([]string) []string
		want string
	}{
		{"no db", func(a []string) []string { return drop(a, "--db") }, "--db is required"},
		{"no cert", func(a []string) []string { return drop(a, "--tls-cert") }, "--tls-cert is required"},
		{"no socket", func(a []string) []string { return drop(a, "--enrol-socket") }, "--enrol-socket is required"},
		{"no rp", func(a []string) []string { return drop(a, "--rp-id") }, "--rp-id is required"},
		{"no mds blob", func(a []string) []string { return drop(a, "--mds-blob") }, "--mds-blob is required"},
		{"no listen", func(a []string) []string { return append(drop(a, "--admin-listen"), "--admin-listen", "") }, "--admin-listen is required"},
		{"no aaguid", func(a []string) []string { return drop(a, "--aaguid") }, "at least one --aaguid"},
		{"bad aaguid", func(a []string) []string { return append(drop(a, "--aaguid"), "--aaguid", "not-a-uuid") }, "--aaguid"},
		{"no key and no credential", func(a []string) []string { return drop(a, "--tls-key") }, "no systemd credential"},
		{"extra argument", func(a []string) []string { return append(a, "junk") }, "unknown command"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CREDENTIALS_DIRECTORY", "")
			args, _, _ := baseArgs(t, a, 0o600)
			// Bounded: a refusal that went missing would leave a live server.
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_, _, err := run(t, ctx, tc.mod(args))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	t.Run("blob that does not verify", func(t *testing.T) {
		loadRoots = func(string) (attest.Roots, error) { return nil, errors.New("signature chain broken") }
		defer stubRoots(a)
		args, _, _ := baseArgs(t, a, 0o600)
		_, _, err := run(t, t.Context(), args)
		if err == nil || !strings.Contains(err.Error(), "signature chain broken") {
			t.Fatalf("err = %v: an unverified MDS3 blob must stop the server", err)
		}
	})
	t.Run("world-readable key", func(t *testing.T) {
		args, _, _ := baseArgs(t, a, 0o644)
		_, _, err := run(t, t.Context(), args)
		if err == nil {
			t.Fatal("a 0644 TLS key was accepted")
		}
	})
	t.Run("real loader refuses a missing blob", func(t *testing.T) {
		old := verifiedRoots
		if _, err := old(filepath.Join(shortDir(t), "none")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing blob: err = %v, want the read error itself", err)
		}
		bad := filepath.Join(shortDir(t), "blob")
		if err := os.WriteFile(bad, []byte("not a jwt"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := old(bad)
		if err == nil || !strings.Contains(err.Error(), "MDS3 blob") {
			t.Fatalf("err = %v, want a refusal naming the blob", err)
		}
	})
}

func TestCredentialDirectoryKey(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	args, _, _ := baseArgs(t, a, 0o400)
	// Move the key into a credentials directory under the name tls.key.
	var key string
	for i, v := range args {
		if v == "--tls-key" {
			key = args[i+1]
		}
	}
	dir := shortDir(t)
	if err := os.Rename(key, filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	var out lockedBuf
	go func() {
		c := RootCmd()
		c.SetArgs(drop(args, "--tls-key"))
		c.SetOut(&out)
		c.SetErr(&lockedBuf{})
		done <- c.ExecuteContext(ctx)
	}()
	waitFor(t, &out, "enrolment listening")
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned %v after a clean stop", err)
	}
}

func waitFor(t *testing.T, b *lockedBuf, s string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if strings.Contains(b.String(), s) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("never saw %q in %q", s, b.String())
}

func TestServeEndToEnd(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	args, pool, sock := baseArgs(t, a, 0o600)
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
	waitFor(t, &out, "enrolment listening")

	line := out.String()
	const pfx = "admin listening on "
	i := strings.Index(line, pfx)
	if i < 0 {
		t.Fatalf("no admin address in %q", line)
	}
	addr := strings.TrimSpace(strings.SplitN(line[i+len(pfx):], "\n", 2)[0])

	conn, err := adminclient.DialUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cred, err := adminclient.Enrol(ctx, conn, a, "first")
	if err != nil {
		t.Fatal(err)
	}
	if string(cred.CredentialId) != string(a.CredID) {
		t.Fatal("enrolled credential differs from the key's")
	}

	ac, err := adminclient.Dial(addr, &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer ac.Close()
	c := adminclient.New(ac, a, "forge.test", a.CredID)
	if _, err := c.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatal(err)
	}
	// A client that trusts nothing the server presents is refused.
	bad, err := adminclient.Dial(addr, &tls.Config{RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if _, _, err := adminclient.New(bad, a, "forge.test", a.CredID).Nonce(ctx); err == nil {
		t.Fatal("untrusted server accepted")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned %v after a clean stop", err)
	}
}

func TestSecondListenerFailureStopsFirst(t *testing.T) {
	restoreRoots(t)
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	stubRoots(a)
	args, _, _ := baseArgs(t, a, 0o600)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	args = append(drop(args, "--admin-listen"), "--admin-listen", busy.Addr().String())
	if _, _, err := run(t, t.Context(), args); err == nil {
		t.Fatal("listening on a busy port succeeded")
	}
	// A directory that is not private makes the socket refuse.
	args, _, sock := baseArgs(t, a, 0o600)
	if err := os.Chmod(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, t.Context(), args); err == nil {
		t.Fatal("an enrolment socket in a 0755 directory was accepted")
	}
}
