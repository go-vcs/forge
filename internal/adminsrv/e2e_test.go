// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminauth"
	"github.com/go-vcs/forge/internal/adminclient"
	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/attest"
	"github.com/go-vcs/forge/internal/fidotest"
	"github.com/go-vcs/forge/internal/store"
)

const rpID = "forge.example"

// forge is a running admin server (TLS 1.3 on loopback) and a running
// enrolment server (Unix socket) over one in-memory store.
type forge struct {
	t     *testing.T
	st    *store.Store
	addr  string
	sock  string
	roots *x509.CertPool
	auth  *fidotest.Authenticator
	enrol *adminsrv.Enrol
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
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
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}, pool
}

// shortDir returns a private 0700 directory with a short path (Unix socket
// paths are limited to about 100 bytes).
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "f")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func newForge(t *testing.T, allowed ...[16]byte) *forge {
	t.Helper()
	st, err := store.Open(t.Context(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	if len(allowed) == 0 {
		allowed = [][16]byte{a.AAGUID}
	}
	pol, err := attest.NewPolicy(rpID, allowed, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &forge{t: t, st: st, auth: a}
	f.enrol = &adminsrv.Enrol{Store: st, Policy: pol, RPID: rpID}

	// Enrolment server on a Unix socket.
	f.sock = filepath.Join(shortDir(t), "e.sock")
	ul, err := adminsrv.ListenUnix(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	es := adminsrv.NewEnrolServer(f.enrol)
	go es.Serve(ul)
	t.Cleanup(es.Stop)

	// Admin server on TLS 1.3.
	cert, pool := selfSigned(t)
	f.roots = pool
	adm := &adminsrv.Admin{
		Store:    st,
		Verifier: &adminauth.Verifier{RPID: rpID, Credentials: st, Nonces: nil},
		Nonces:   adminauth.NewNonces(time.Now, time.Minute, 64, 256),
		Sessions: adminauth.NewSessions(time.Now, time.Minute, 8, 64),
	}
	adm.Verifier.Nonces = adm.Nonces
	srv, err := adminsrv.NewAdminServer(adminsrv.TLSConfig(cert), adm)
	if err != nil {
		t.Fatal(err)
	}
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = tl.Addr().String()
	go srv.Serve(tl)
	t.Cleanup(srv.Stop)
	return f
}

// enrolKey enrols f.auth over the socket.
func (f *forge) enrolKey(name string) (*adminv1.AdminCredential, error) {
	conn, err := adminclient.DialUnix(f.sock)
	if err != nil {
		f.t.Fatal(err)
	}
	defer conn.Close()
	return adminclient.Enrol(f.t.Context(), conn, f.auth, name)
}

func (f *forge) mustEnrol() {
	f.t.Helper()
	if _, err := f.enrolKey("first"); err != nil {
		f.t.Fatal(err)
	}
}

// dial opens a NEW TLS connection (so a new exporter value) and a client on it.
func (f *forge) dial() *adminclient.Client {
	f.t.Helper()
	conn, err := adminclient.Dial(f.addr, &tls.Config{RootCAs: f.roots})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { conn.Close() })
	c := adminclient.New(conn, f.auth, rpID, f.auth.CredID)
	if _, _, err := c.Nonce(f.t.Context()); err != nil { // force the handshake now
		f.t.Fatal(err)
	}
	return c
}

func code(err error) codes.Code { return status.Code(err) }

func (f *forge) wantUsers(n int) {
	f.t.Helper()
	us, err := f.st.ListUsers(f.t.Context())
	if err != nil || len(us) != n {
		f.t.Fatalf("%d users (%v), want %d: a refused call must change nothing", len(us), err, n)
	}
}

// tweak says how a test forges one envelope.
type tweak struct {
	signedMethod string              // method written into the signed challenge
	nonceFrom    *adminclient.Client // connection the nonce is taken from
	exporterFrom *adminclient.Client // connection whose exporter is signed
	credID       []byte
	mutate       func(*adminv1.Envelope)
}

// envelope signs params for method as c's connection would, with the flaws tw asks for.
func (f *forge) envelope(c *adminclient.Client, method string, params proto.Message, tw tweak) *adminv1.Envelope {
	f.t.Helper()
	ctx := f.t.Context()
	nc, ec := c, c
	if tw.nonceFrom != nil {
		nc = tw.nonceFrom
	}
	if tw.exporterFrom != nil {
		ec = tw.exporterFrom
	}
	nonce, _, err := nc.Nonce(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	_, exp, err := ec.Nonce(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	req, err := proto.Marshal(params)
	if err != nil {
		f.t.Fatal(err)
	}
	m := method
	if tw.signedMethod != "" {
		m = tw.signedMethod
	}
	id := f.auth.CredID
	if tw.credID != nil {
		id = tw.credID
	}
	cdh := adminauth.ClientDataHash(m, nonce, req, exp)
	ad, sig, err := f.auth.Assert(ctx, rpID, id, cdh)
	if err != nil {
		f.t.Fatal(err)
	}
	env := &adminv1.Envelope{Nonce: nonce, Request: req, CredentialId: id, AuthenticatorData: ad, Signature: sig}
	if tw.mutate != nil {
		tw.mutate(env)
	}
	return env
}

func createUser(c *adminclient.Client, env *adminv1.Envelope) error {
	_, err := c.Admin.CreateUser(context.Background(), &adminv1.CreateUserRequest{Envelope: env})
	return err
}

var createMethod = adminv1.AdminService_CreateUser_FullMethodName

func params(login string) *adminv1.CreateUserParams {
	return &adminv1.CreateUserParams{Login: login, DisplayName: login}
}

func TestEndToEnd(t *testing.T) {
	f := newForge(t)
	cred, err := f.enrolKey("laptop key")
	if err != nil || cred.Name != "laptop key" || cred.Aaguid != attest.FormatAAGUID(f.auth.AAGUID) {
		t.Fatalf("enrol: %+v %v", cred, err)
	}
	c := f.dial()
	ctx := t.Context()

	if u, err := c.CreateUser(ctx, "alice", "Alice"); err != nil || u.Login != "alice" {
		t.Fatalf("create: %v %v", u, err)
	}
	if _, err := c.CreateUser(ctx, "alice", "again"); code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := c.CreateUser(ctx, "a@b.example", "mail"); code(err) != codes.InvalidArgument {
		t.Fatalf("e-mail login: %v", err)
	}
	if _, err := c.BindIdentity(ctx, "https://idp.example", "sub-1", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BindIdentity(ctx, "https://idp.example", "sub-1", "alice"); code(err) != codes.AlreadyExists {
		t.Fatalf("rebind: %v", err)
	}
	if _, err := c.BindIdentity(ctx, "https://idp.example", "sub-2", "ghost"); code(err) != codes.NotFound {
		t.Fatalf("unknown user: %v", err)
	}

	tok, err := c.OpenSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	us, err := c.Admin.ListUsers(ctx, &adminv1.ListUsersRequest{SessionToken: tok})
	if err != nil || len(us.Users) != 1 || us.Users[0].Login != "alice" {
		t.Fatalf("list users: %v %v", us, err)
	}
	ids, err := c.Admin.ListIdentities(ctx, &adminv1.ListIdentitiesRequest{SessionToken: tok})
	if err != nil || len(ids.Identities) != 1 || ids.Identities[0].Subject != "sub-1" {
		t.Fatalf("list identities: %v %v", ids, err)
	}
	cs, err := c.Admin.ListAdminCredentials(ctx, &adminv1.ListAdminCredentialsRequest{SessionToken: tok})
	if err != nil || len(cs.Credentials) != 1 || cs.Credentials[0].SignCount == 0 {
		t.Fatalf("list credentials: %v %v", cs, err)
	}

	if err := c.UnbindIdentity(ctx, "https://idp.example", "sub-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.UnbindIdentity(ctx, "https://idp.example", "sub-1"); code(err) != codes.NotFound {
		t.Fatalf("unbind twice: %v", err)
	}
	if err := c.DisableUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.st.AuditCount(ctx); n < 8 {
		t.Fatalf("audit rows %d", n)
	}

	// Revoking the only credential ends the key's authority.
	if err := c.RevokeCredential(ctx, cred.CredentialId); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateUser(ctx, "bob", ""); code(err) != codes.Unauthenticated {
		t.Fatalf("revoked credential accepted: %v", err)
	}
}

func TestAccepted(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	if err := createUser(c, f.envelope(c, createMethod, params("ok"), tweak{})); err != nil {
		t.Fatal(err)
	}
	f.wantUsers(1)
}

func TestRefusals(t *testing.T) {
	type tc struct {
		name string
		prep func(f *forge) // before the forged call
		tw   func(a, b *adminclient.Client) tweak
	}
	cases := []tc{
		{name: "wrong method", tw: func(a, b *adminclient.Client) tweak {
			return tweak{signedMethod: adminv1.AdminService_DisableUser_FullMethodName}
		}},
		{name: "altered request bytes", tw: func(a, b *adminclient.Client) tweak {
			return tweak{mutate: func(e *adminv1.Envelope) {
				e.Request, _ = proto.Marshal(params("evil"))
			}}
		}},
		{name: "trailing byte in request", tw: func(a, b *adminclient.Client) tweak {
			return tweak{mutate: func(e *adminv1.Envelope) { e.Request = append(e.Request, 0) }}
		}},
		{name: "other connection's exporter", tw: func(a, b *adminclient.Client) tweak {
			return tweak{exporterFrom: b}
		}},
		{name: "nonce issued to another connection", tw: func(a, b *adminclient.Client) tweak {
			return tweak{nonceFrom: b}
		}},
		{name: "unknown nonce", tw: func(a, b *adminclient.Client) tweak {
			return tweak{mutate: func(e *adminv1.Envelope) { e.Nonce = make([]byte, adminauth.NonceLen) }}
		}},
		{name: "missing nonce", tw: func(a, b *adminclient.Client) tweak {
			return tweak{mutate: func(e *adminv1.Envelope) { e.Nonce = nil }}
		}},
		{name: "UV unset", prep: func(f *forge) { f.auth.NoUV = true }},
		{name: "UP unset", prep: func(f *forge) { f.auth.NoUP = true }},
		{name: "unknown credential", tw: func(a, b *adminclient.Client) tweak {
			return tweak{mutate: func(e *adminv1.Envelope) { e.CredentialId = []byte("not enrolled") }}
		}},
		{name: "counter regression", prep: func(f *forge) { f.auth.FreezeCount = true; f.auth.Counter = 1 }},
		{name: "counter reset to zero", prep: func(f *forge) { f.auth.ZeroCount = true }},
		{name: "signature of another key", tw: func(a, b *adminclient.Client) tweak {
			return tweak{mutate: func(e *adminv1.Envelope) { e.Signature[len(e.Signature)-1] ^= 1 }}
		}},
		{name: "authenticator data altered", tw: func(a, b *adminclient.Client) tweak {
			return tweak{mutate: func(e *adminv1.Envelope) { e.AuthenticatorData[36] ^= 1 }}
		}},
		{name: "authenticator data for another relying party", prep: func(f *forge) { f.auth.WrongRP = "evil.example" }},
		{name: "empty signature", tw: func(a, b *adminclient.Client) tweak {
			return tweak{mutate: func(e *adminv1.Envelope) { e.Signature = nil }}
		}},
		{name: "oversized request", tw: func(a, b *adminclient.Client) tweak {
			return tweak{mutate: func(e *adminv1.Envelope) { e.Request = make([]byte, adminsrv.MaxRequestLen+1) }}
		}},
	}
	reasons := map[string]string{
		"wrong method":                                 "signature does not verify",
		"altered request bytes":                        "signature does not verify",
		"trailing byte in request":                     "signature does not verify",
		"other connection's exporter":                  "signature does not verify",
		"nonce issued to another connection":           "another connection",
		"unknown nonce":                                "nonce unknown",
		"missing nonce":                                "nonce unknown",
		"UV unset":                                     "user verification flag",
		"UP unset":                                     "user presence flag",
		"unknown credential":                           "unknown or revoked credential",
		"counter regression":                           "counter went backwards",
		"counter reset to zero":                        "counter went backwards",
		"signature of another key":                     "signature does not verify",
		"authenticator data altered":                   "signature does not verify",
		"authenticator data for another relying party": "another relying party",
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newForge(t)
			f.mustEnrol()
			// Move the counter up so that a regression is one.
			warm := f.dial()
			for range 3 {
				if _, err := warm.OpenSession(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if c.prep != nil {
				c.prep(f)
			}
			a, b := f.dial(), f.dial()
			var tw tweak
			if c.tw != nil {
				tw = c.tw(a, b)
			}
			err := createUser(a, f.envelope(a, createMethod, params("victim"), tw))
			want := codes.Unauthenticated
			if c.name == "oversized request" {
				want = codes.InvalidArgument
			}
			if code(err) != want {
				t.Fatalf("got %v, want code %v", err, want)
			}
			if r := reasons[c.name]; r != "" && !strings.Contains(err.Error(), r) {
				t.Fatalf("refused for the wrong reason: %v (want %q)", err, r)
			}
			f.wantUsers(0)
		})
	}
}

func TestReplayedNonce(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	env := f.envelope(c, createMethod, params("once"), tweak{})
	if err := createUser(c, env); err != nil {
		t.Fatal(err)
	}
	if err := createUser(c, env); code(err) != codes.Unauthenticated {
		t.Fatalf("replay: %v", err)
	}
	f.wantUsers(1)
}

func TestReplayOnAnotherConnection(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	a, b := f.dial(), f.dial()
	env := f.envelope(a, createMethod, params("x"), tweak{})
	if err := createUser(b, env); code(err) != codes.Unauthenticated {
		t.Fatalf("envelope replayed on another connection: %v", err)
	}
	f.wantUsers(0)
}

func TestRefusedAssertionBurnsTheNonce(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	good := f.envelope(c, createMethod, params("x"), tweak{})
	bad := proto.Clone(good).(*adminv1.Envelope)
	bad.Signature = append([]byte(nil), good.Signature...)
	bad.Signature[len(bad.Signature)-1] ^= 1
	if err := createUser(c, bad); code(err) != codes.Unauthenticated {
		t.Fatalf("bad: %v", err)
	}
	if err := createUser(c, good); code(err) != codes.Unauthenticated {
		t.Fatalf("the nonce of a refused call must be spent: %v", err)
	}
}

func TestNilEnvelope(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	if _, err := c.Admin.CreateUser(t.Context(), &adminv1.CreateUserRequest{}); code(err) != codes.InvalidArgument {
		t.Fatalf("nil envelope: %v", err)
	}
}

func TestGarbageParametersAfterValidSignature(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	// Sign bytes that are not a CreateUserParams message: the signature is
	// valid, parsing must still refuse.
	nonce, exp, _ := c.Nonce(t.Context())
	req := []byte{0xff, 0xff, 0xff}
	ad, sig, err := f.auth.Assert(t.Context(), rpID, f.auth.CredID, adminauth.ClientDataHash(createMethod, nonce, req, exp))
	if err != nil {
		t.Fatal(err)
	}
	env := &adminv1.Envelope{Nonce: nonce, Request: req, CredentialId: f.auth.CredID, AuthenticatorData: ad, Signature: sig}
	if err := createUser(c, env); code(err) != codes.InvalidArgument {
		t.Fatalf("got %v", err)
	}
}

func TestSessionsAreBoundToTheirConnection(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	a, b := f.dial(), f.dial()
	tok, err := a.OpenSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Admin.ListUsers(t.Context(), &adminv1.ListUsersRequest{SessionToken: tok}); code(err) != codes.Unauthenticated {
		t.Fatalf("session used on another connection: %v", err)
	}
	if _, err := a.Admin.ListUsers(t.Context(), &adminv1.ListUsersRequest{SessionToken: tok}); err != nil {
		t.Fatalf("session on its own connection: %v", err)
	}
	for _, bad := range [][]byte{nil, []byte("junk"), make([]byte, 32)} {
		if _, err := a.Admin.ListUsers(t.Context(), &adminv1.ListUsersRequest{SessionToken: bad}); code(err) != codes.Unauthenticated {
			t.Fatalf("token %x: %v", bad, err)
		}
		if _, err := a.Admin.ListIdentities(t.Context(), &adminv1.ListIdentitiesRequest{SessionToken: bad}); code(err) != codes.Unauthenticated {
			t.Fatalf("token %x: %v", bad, err)
		}
		if _, err := a.Admin.ListAdminCredentials(t.Context(), &adminv1.ListAdminCredentialsRequest{SessionToken: bad}); code(err) != codes.Unauthenticated {
			t.Fatalf("token %x: %v", bad, err)
		}
	}
}

func TestSessionOpenNeedsAnAssertion(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	f.auth.NoUV = true
	if _, err := c.OpenSession(t.Context()); code(err) != codes.Unauthenticated {
		t.Fatalf("session opened without UV: %v", err)
	}
}

func TestNoncesAreBounded(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	var last error
	for range 100 {
		if _, err := c.Admin.GetNonce(t.Context(), &adminv1.GetNonceRequest{}); err != nil {
			last = err
			break
		}
	}
	if code(last) != codes.ResourceExhausted {
		t.Fatalf("nonce flood was not stopped: %v", last)
	}
}

// ---- transport ----

func TestPlainTLS12Refused(t *testing.T) {
	f := newForge(t)
	conn, err := grpc.NewClient(f.addr, grpc.WithTransportCredentials(tlsCreds(&tls.Config{RootCAs: f.roots, MaxVersion: tls.VersionTLS12})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := adminv1.NewAdminServiceClient(conn).GetNonce(ctx, &adminv1.GetNonceRequest{}); err == nil {
		t.Fatal("a TLS 1.2 client was served")
	}
}

func TestInsecureClientRefused(t *testing.T) {
	f := newForge(t)
	conn, err := grpc.NewClient(f.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := adminv1.NewAdminServiceClient(conn).GetNonce(ctx, &adminv1.GetNonceRequest{}); err == nil {
		t.Fatal("a cleartext client was served")
	}
}

func TestUntrustedServerRefusedByClient(t *testing.T) {
	f := newForge(t)
	conn, err := adminclient.Dial(f.addr, &tls.Config{RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := adminv1.NewAdminServiceClient(conn).GetNonce(ctx, &adminv1.GetNonceRequest{}); err == nil {
		t.Fatal("connected to a server with an untrusted certificate")
	}
}

func TestNewAdminServerRefusesWeakTLS(t *testing.T) {
	if _, err := adminsrv.NewAdminServer(nil, &adminsrv.Admin{}); err == nil {
		t.Fatal("nil config")
	}
	if _, err := adminsrv.NewAdminServer(&tls.Config{MinVersion: tls.VersionTLS12}, &adminsrv.Admin{}); err == nil {
		t.Fatal("TLS 1.2 config")
	}
}

func TestExporterWithoutTLS(t *testing.T) {
	if _, err := adminsrv.Exporter(context.Background()); code(err) != codes.Unauthenticated {
		t.Fatalf("no peer: %v", err)
	}
}

// ---- enrolment ----

func TestEnrolmentNotReachableOnTheAdminServer(t *testing.T) {
	f := newForge(t)
	c := f.dial()
	_, err := adminv1.NewEnrolServiceClient(c.Conn).BeginEnrol(t.Context(), &adminv1.BeginEnrolRequest{})
	if code(err) != codes.Unimplemented {
		t.Fatalf("EnrolService is served on the network: %v", err)
	}
	if _, err := adminv1.NewEnrolServiceClient(c.Conn).FinishEnrol(t.Context(), &adminv1.FinishEnrolRequest{}); code(err) != codes.Unimplemented {
		t.Fatalf("FinishEnrol is served on the network: %v", err)
	}
}

func TestEnrolmentOverTCPRefusedEvenIfMounted(t *testing.T) {
	f := newForge(t)
	// Mount the enrolment server on a TCP listener by mistake: it must refuse.
	srv := adminsrv.NewEnrolServer(f.enrol)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := adminclient.Enrol(t.Context(), conn, f.auth, "tcp"); code(err) != codes.PermissionDenied {
		t.Fatalf("enrolment over TCP: %v", err)
	}
	if _, err := adminv1.NewEnrolServiceClient(conn).FinishEnrol(t.Context(), &adminv1.FinishEnrolRequest{}); code(err) != codes.PermissionDenied {
		t.Fatalf("FinishEnrol over TCP: %v", err)
	}
	if n, _ := f.st.ActiveCredentialCount(t.Context()); n != 0 {
		t.Fatalf("%d credentials stored", n)
	}
}

func TestEnrolmentAAGUIDNotAllowlisted(t *testing.T) {
	f := newForge(t, [16]byte{0xde, 0xad})
	if _, err := f.enrolKey("k"); code(err) != codes.PermissionDenied {
		t.Fatalf("got %v", err)
	}
	if n, _ := f.st.ActiveCredentialCount(t.Context()); n != 0 {
		t.Fatalf("%d credentials stored", n)
	}
}

func TestEnrolmentFlawedAuthenticators(t *testing.T) {
	flaws := map[string]func(a *fidotest.Authenticator){
		"UV unset":            func(a *fidotest.Authenticator) { a.NoUV = true },
		"backup eligible":     func(a *fidotest.Authenticator) { a.Backup = true },
		"bad attestation":     func(a *fidotest.Authenticator) { a.BadAttestSig = true },
		"no certificate":      func(a *fidotest.Authenticator) { a.NoX5C = true },
		"wrong relying party": func(a *fidotest.Authenticator) { a.WrongRP = "evil.example" },
	}
	for name, flaw := range flaws {
		t.Run(name, func(t *testing.T) {
			f := newForge(t)
			flaw(f.auth)
			if _, err := f.enrolKey("k"); code(err) != codes.PermissionDenied {
				t.Fatalf("got %v", err)
			}
			if n, _ := f.st.ActiveCredentialCount(t.Context()); n != 0 {
				t.Fatalf("%d credentials stored", n)
			}
		})
	}
}

func TestEnrolmentChallengeIsSingleUseAndBoundToTheName(t *testing.T) {
	f := newForge(t)
	conn, err := adminclient.DialUnix(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	e := adminv1.NewEnrolServiceClient(conn)
	ctx := t.Context()
	b, err := e.BeginEnrol(ctx, &adminv1.BeginEnrolRequest{})
	if err != nil || b.RpId != rpID || len(b.Challenge) != adminauth.NonceLen {
		t.Fatalf("begin: %v %v", b, err)
	}
	// Attestation made for the name "one", presented under the name "two".
	format, ad, stmt, err := f.auth.Make(ctx, b.RpId, b.UserHandle, "one", adminauth.EnrolClientDataHash(b.Challenge, "one"))
	if err != nil {
		t.Fatal(err)
	}
	req := &adminv1.FinishEnrolRequest{Challenge: b.Challenge, Name: "two", AuthenticatorData: ad, AttestationFormat: format, AttestationStatement: stmt}
	if _, err := e.FinishEnrol(ctx, req); code(err) != codes.PermissionDenied {
		t.Fatalf("renamed enrolment: %v", err)
	}
	// The challenge is spent by that refusal.
	req.Name = "one"
	if _, err := e.FinishEnrol(ctx, req); code(err) != codes.FailedPrecondition {
		t.Fatalf("reused challenge: %v", err)
	}
	// Unknown and malformed challenges.
	for _, ch := range [][]byte{nil, []byte("short"), make([]byte, adminauth.NonceLen)} {
		r := &adminv1.FinishEnrolRequest{Challenge: ch, Name: "x", AuthenticatorData: ad, AttestationFormat: format, AttestationStatement: stmt}
		if _, err := e.FinishEnrol(ctx, r); code(err) != codes.FailedPrecondition {
			t.Fatalf("challenge %x: %v", ch, err)
		}
	}
	// Invalid name, oversized input.
	if _, err := e.FinishEnrol(ctx, &adminv1.FinishEnrolRequest{Challenge: b.Challenge, Name: ""}); code(err) != codes.InvalidArgument {
		t.Fatalf("empty name: %v", err)
	}
	if _, err := e.FinishEnrol(ctx, &adminv1.FinishEnrolRequest{Challenge: b.Challenge, Name: "x", AttestationStatement: make([]byte, 17<<10)}); code(err) != codes.InvalidArgument {
		t.Fatalf("oversized statement: %v", err)
	}
	if _, err := e.FinishEnrol(ctx, &adminv1.FinishEnrolRequest{Challenge: b.Challenge, Name: "x", AuthenticatorData: make([]byte, attest.MaxAuthDataLen+1)}); code(err) != codes.InvalidArgument {
		t.Fatalf("oversized authenticator data: %v", err)
	}
}

func TestEnrolmentChallengeExpires(t *testing.T) {
	f := newForge(t)
	now := time.Now()
	f.enrol.Now = func() time.Time { return now }
	conn, err := adminclient.DialUnix(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	e := adminv1.NewEnrolServiceClient(conn)
	b, err := e.BeginEnrol(t.Context(), &adminv1.BeginEnrolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	format, ad, stmt, _ := f.auth.Make(t.Context(), b.RpId, b.UserHandle, "k", adminauth.EnrolClientDataHash(b.Challenge, "k"))
	now = now.Add(adminsrv.ChallengeTTL + time.Second)
	_, err = e.FinishEnrol(t.Context(), &adminv1.FinishEnrolRequest{Challenge: b.Challenge, Name: "k", AuthenticatorData: ad, AttestationFormat: format, AttestationStatement: stmt})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("expired challenge: %v", err)
	}
}

func TestEnrolmentChallengesAreBounded(t *testing.T) {
	f := newForge(t)
	conn, err := adminclient.DialUnix(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	e := adminv1.NewEnrolServiceClient(conn)
	var last error
	for range adminsrv.MaxOpenChallenges + 1 {
		if _, last = e.BeginEnrol(t.Context(), &adminv1.BeginEnrolRequest{}); last != nil {
			break
		}
	}
	if code(last) != codes.ResourceExhausted {
		t.Fatalf("open enrolments are not bounded: %v", last)
	}
}

func TestASecondKeyCanBeEnrolled(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	// A second enrolment of a NEW credential works (a second key is normal).
	f.auth.Key = nil
	if _, err := f.enrolKey("second"); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.st.ActiveCredentialCount(t.Context()); n != 2 {
		t.Fatalf("%d credentials", n)
	}
}

// ---- Unix socket ----

func TestListenUnix(t *testing.T) {
	dir := shortDir(t)
	p := filepath.Join(dir, "s")
	l, err := adminsrv.ListenUnix(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v %v", fi.Mode(), err)
	}
	l.Close()

	// A stale socket is replaced.
	l, err = adminsrv.ListenUnix(p)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	l.Close()
}

func TestListenUnixRefusals(t *testing.T) {
	t.Run("directory open to others", func(t *testing.T) {
		d := shortDir(t)
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := adminsrv.ListenUnix(filepath.Join(d, "s")); err == nil {
			t.Fatal("0755 directory accepted")
		}
		if err := os.Chmod(d, 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := adminsrv.ListenUnix(filepath.Join(d, "s")); err == nil {
			t.Fatal("0750 directory accepted")
		}
	})
	t.Run("missing directory", func(t *testing.T) {
		if _, err := adminsrv.ListenUnix(filepath.Join(shortDir(t), "nope", "s")); err == nil {
			t.Fatal("missing directory accepted")
		}
	})
	t.Run("path is a file", func(t *testing.T) {
		d := shortDir(t)
		p := filepath.Join(d, "s")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := adminsrv.ListenUnix(p); err == nil {
			t.Fatal("a regular file was replaced")
		}
		if b, _ := os.ReadFile(p); string(b) != "x" {
			t.Fatal("the file was damaged")
		}
	})
	t.Run("directory is a file", func(t *testing.T) {
		d := shortDir(t)
		p := filepath.Join(d, "f")
		os.WriteFile(p, nil, 0o600)
		if _, err := adminsrv.ListenUnix(filepath.Join(p, "s")); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestLoadTLSRefusesOpenKey(t *testing.T) {
	cert, _ := selfSigned(t)
	d := shortDir(t)
	certFile, keyFile := filepath.Join(d, "c.pem"), filepath.Join(d, "k.pem")
	writePEM(t, certFile, keyFile, cert)
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := adminsrv.LoadTLS(certFile, keyFile); err == nil {
		t.Fatal("a world-readable key was loaded")
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adminsrv.LoadTLS(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0o400); err != nil { // what systemd credentials look like
		t.Fatal(err)
	}
	if _, err := adminsrv.LoadTLS(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := adminsrv.LoadTLS(certFile, filepath.Join(d, "missing")); err == nil {
		t.Fatal("missing key accepted")
	}
}

func TestResolveFile(t *testing.T) {
	if p, err := adminsrv.ResolveFile("/some/path", "tls.key"); err != nil || p != "/some/path" {
		t.Fatalf("explicit: %q %v", p, err)
	}
	d := shortDir(t)
	if err := os.WriteFile(filepath.Join(d, "tls.key"), []byte("k"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv(adminsrv.CredentialsEnv, d)
	if p, err := adminsrv.ResolveFile("", "tls.key"); err != nil || p != filepath.Join(d, "tls.key") {
		t.Fatalf("credential: %q %v", p, err)
	}
	// A credential name cannot climb out of the directory.
	if p, err := adminsrv.ResolveFile("", "../../etc/passwd"); err == nil {
		t.Fatalf("escaped the credentials directory: %q", p)
	}
	if _, err := adminsrv.ResolveFile("", "absent"); err == nil {
		t.Fatal("absent credential accepted")
	}
	if _, err := adminsrv.ResolveFile("", ""); err == nil {
		t.Fatal("empty credential name accepted")
	}
	t.Setenv(adminsrv.CredentialsEnv, "")
	if _, err := adminsrv.ResolveFile("", "tls.key"); err == nil {
		t.Fatal("no directory accepted")
	}
}
