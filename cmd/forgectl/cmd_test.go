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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/adminauth"
	"github.com/go-vcs/forge/internal/adminclient"
	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/attest"
	"github.com/go-vcs/forge/internal/fidotest"
	"github.com/go-vcs/forge/internal/store"
)

const rpID = "forge.test"

type rig struct {
	t      *testing.T
	auth   *fidotest.Authenticator
	st     *store.Store
	addr   string
	sock   string
	caFile string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir, err := os.MkdirTemp("", "f")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	st, err := store.Open(t.Context(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	pol, err := attest.NewPolicy(rpID, [][16]byte{a.AAGUID}, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, auth: a, st: st, sock: filepath.Join(dir, "e.sock")}

	ul, err := adminsrv.ListenUnix(r.sock)
	if err != nil {
		t.Fatal(err)
	}
	es := adminsrv.NewEnrolServer(&adminsrv.Enrol{Store: st, Policy: pol, RPID: rpID})
	go es.Serve(ul)
	t.Cleanup(es.Stop)

	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "forge test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	leaf, _ := x509.ParseCertificate(der)
	r.caFile = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(r.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	nonces := adminauth.NewNonces(time.Now, time.Minute, 256)
	adm := &adminsrv.Admin{
		Store:    st,
		Verifier: &adminauth.Verifier{RPID: rpID, Credentials: st, Nonces: nonces},
		Nonces:   nonces,
		Sessions: adminauth.NewSessions(time.Now, time.Minute, 8, 64),
	}
	srv, err := adminsrv.NewAdminServer(adminsrv.TLSConfig(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}), adm)
	if err != nil {
		t.Fatal(err)
	}
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.addr = tl.Addr().String()
	go srv.Serve(tl)
	t.Cleanup(srv.Stop)

	old := openSigner
	openSigner = func(context.Context) (adminclient.Signer, error) { return a, nil }
	t.Cleanup(func() { openSigner = old })
	return r
}

func (r *rig) run(args ...string) (string, error) {
	r.t.Helper()
	var out, errb bytes.Buffer
	c := RootCmd()
	c.SetArgs(args)
	c.SetOut(&out)
	c.SetErr(&errb)
	err := c.ExecuteContext(r.t.Context())
	return out.String(), err
}

func (r *rig) admin(args ...string) (string, error) {
	return r.run(append([]string{"--server", r.addr, "--ca-file", r.caFile, "--rp-id", rpID,
		"--credential-id", hex.EncodeToString(r.auth.CredID)}, args...)...)
}

func (r *rig) enrol(t *testing.T) string {
	t.Helper()
	out, err := r.run("enrol", "--socket", r.sock, "--rp-id", rpID, "--name", "first")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, hex.EncodeToString(r.auth.CredID)) {
		t.Fatalf("enrol output %q does not show the credential id", out)
	}
	return out
}

func TestWorkflow(t *testing.T) {
	r := newRig(t)
	r.enrol(t)

	for _, step := range []struct {
		args []string
		want string
	}{
		{[]string{"users", "create", "alice", "--display-name", "Alice A"}, "created alice"},
		{[]string{"users", "create", "bob"}, "created bob"},
		{[]string{"users", "list"}, "alice \"Alice A\""},
		{[]string{"identities", "bind", "https://idp.example", "sub-1", "alice"}, "bound https://idp.example sub-1 to alice"},
		{[]string{"identities", "list"}, "https://idp.example sub-1 alice"},
		{[]string{"identities", "list", "--login", "alice"}, "sub-1"},
		{[]string{"identities", "unbind", "https://idp.example", "sub-1"}, "unbound"},
		{[]string{"users", "disable", "bob"}, "disabled bob"},
		{[]string{"credentials", "list"}, "aaguid=" + attest.FormatAAGUID(r.auth.AAGUID)},
	} {
		out, err := r.admin(step.args...)
		if err != nil {
			t.Fatalf("%v: %v", step.args, err)
		}
		if !strings.Contains(out, step.want) {
			t.Fatalf("%v printed %q, want %q", step.args, out, step.want)
		}
	}
	if out, _ := r.admin("identities", "list"); strings.Contains(out, "sub-1") {
		t.Fatalf("unbound identity still listed: %q", out)
	}
	// The last active credential cannot be revoked: add a spare first.
	if _, err := r.st.AddCredential(t.Context(), []byte("spare"), &r.auth.Key.PublicKey, "a", "spare"); err != nil {
		t.Fatal(err)
	}
	out, err := r.admin("credentials", "revoke", hex.EncodeToString(r.auth.CredID))
	if err != nil || !strings.Contains(out, "revoked") {
		t.Fatalf("revoke: %q %v", out, err)
	}
	if _, err := r.admin("users", "list"); err == nil {
		t.Fatal("a revoked key still administers the forge")
	}
}

func TestRefusals(t *testing.T) {
	r := newRig(t)
	r.enrol(t)
	id := hex.EncodeToString(r.auth.CredID)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no server", []string{"users", "list"}, "--server is required"},
		{"no rp", []string{"--server", r.addr, "users", "list"}, "--rp-id is required"},
		{"no credential", []string{"--server", r.addr, "--rp-id", rpID, "users", "list"}, "--credential-id is required"},
		{"credential not hex", []string{"--server", r.addr, "--rp-id", rpID, "--credential-id", "zz", "users", "list"}, "hex"},
		{"unreadable CA", []string{"--server", r.addr, "--rp-id", rpID, "--credential-id", id, "--ca-file", "/nonexistent/ca", "users", "list"}, "no such file"},
		{"CA without a certificate", []string{"--server", r.addr, "--rp-id", rpID, "--credential-id", id, "--ca-file", os.DevNull, "users", "list"}, "no PEM"},
		{"untrusted server", []string{"--server", r.addr, "--rp-id", rpID, "--credential-id", id, "users", "list"}, "certificate"},
		{"email as login", []string{"--server", r.addr, "--ca-file", r.caFile, "--rp-id", rpID, "--credential-id", id, "users", "create", "a@b.example"}, ""},
		{"revoke needs hex", []string{"--server", r.addr, "--ca-file", r.caFile, "--rp-id", rpID, "--credential-id", id, "credentials", "revoke", "xyz"}, "hex"},
		{"enrol needs a name", []string{"enrol", "--socket", r.sock, "--rp-id", rpID}, "--name is required"},
		{"enrol needs a socket", []string{"enrol", "--rp-id", rpID, "--name", "x"}, "--socket is required"},
		{"enrol over a missing socket", []string{"enrol", "--socket", "/nonexistent/s", "--rp-id", rpID, "--name", "x"}, ""},
		{"wrong arity", []string{"identities", "bind", "only-one"}, "accepts 3 arg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.run(tc.args...)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	if us, _ := r.st.ListUsers(t.Context()); len(us) != 0 {
		t.Fatalf("%d users exist after refused calls", len(us))
	}
}

func TestKeyOpenFailureIsReported(t *testing.T) {
	r := newRig(t)
	r.enrol(t)
	openSigner = func(context.Context) (adminclient.Signer, error) { return nil, errors.New("no key attached") }
	for _, args := range [][]string{
		{"users", "list"},
		{"users", "create", "carol"},
		{"enrol", "--socket", r.sock, "--rp-id", rpID, "--name", "x"},
	} {
		if args[0] == "enrol" {
			if _, err := r.run(args...); err == nil || !strings.Contains(err.Error(), "no key attached") {
				t.Fatalf("%v: %v", args, err)
			}
			continue
		}
		if _, err := r.admin(args...); err == nil || !strings.Contains(err.Error(), "no key attached") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestRealKeyPathRefusesWithoutAKey(t *testing.T) {
	// The platform opener must fail cleanly, not hang, when no key is attached
	// or the OS is unsupported.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if s, err := platformSigner(ctx); err == nil && s == nil {
		t.Fatal("nil signer without an error")
	}
}
