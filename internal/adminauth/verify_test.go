// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminauth_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/adminauth"
	"github.com/go-vcs/forge/internal/fidotest"
)

const rpID = "forge.example.org"

type fakeCreds struct {
	mu sync.Mutex
	c  map[string]*adminauth.Credential
}

func (f *fakeCreds) ActiveCredential(_ context.Context, id []byte) (adminauth.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.c[string(id)]
	if !ok {
		return adminauth.Credential{}, adminauth.ErrUnknownCredential
	}
	return *c, nil
}

func (f *fakeCreds) AdvanceCounter(_ context.Context, id []byte, n uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.c[string(id)]
	if c.SignCount != 0 && n < c.SignCount {
		return adminauth.ErrCounterRegression
	}
	c.SignCount = n
	return nil
}

type env struct {
	v      *adminauth.Verifier
	auth   *fidotest.Authenticator
	creds  *fakeCreds
	nonces *adminauth.Nonces
	clock  *time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	clock := &now
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	if _, _, _, err := a.Make(context.Background(), rpID, nil, "k", [32]byte{}); err != nil {
		t.Fatal(err)
	}
	creds := &fakeCreds{c: map[string]*adminauth.Credential{
		string(a.CredID): {ID: a.CredID, PublicKey: &a.Key.PublicKey},
	}}
	n := adminauth.NewNonces(func() time.Time { return *clock }, time.Minute, 4, 16)
	return &env{
		v:    &adminauth.Verifier{RPID: rpID, Credentials: creds, Nonces: n},
		auth: a, creds: creds, nonces: n, clock: clock,
	}
}

var exporterA = bytes.Repeat([]byte{0xA1}, 32)
var exporterB = bytes.Repeat([]byte{0xB2}, 32)

const method = "/govcs.forge.admin.v1.AdminService/CreateUser"

// call issues a nonce on exporter, has the authenticator sign for
// (signMethod, signRequest, signExporter), and returns the Input as it would
// arrive for (method, request) on exporter.
func (e *env) call(t *testing.T, exporter []byte, signMethod string, signRequest, signExporter []byte) adminauth.Input {
	t.Helper()
	nonce, _, err := e.nonces.Issue(exporter)
	if err != nil {
		t.Fatal(err)
	}
	cdh := adminauth.ClientDataHash(signMethod, nonce, signRequest, signExporter)
	ad, sig, err := e.auth.Assert(context.Background(), rpID, e.auth.CredID, cdh)
	if err != nil {
		t.Fatal(err)
	}
	return adminauth.Input{
		Method: method, Nonce: nonce, Request: []byte("request-bytes"), Exporter: exporter,
		Assertion: adminauth.Assertion{CredentialID: e.auth.CredID, AuthenticatorData: ad, Signature: sig},
	}
}

func (e *env) good(t *testing.T) adminauth.Input {
	return e.call(t, exporterA, method, []byte("request-bytes"), exporterA)
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

func TestAcceptsAGoodAssertion(t *testing.T) {
	e := newEnv(t)
	c, err := e.v.Verify(context.Background(), e.good(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.SignCount != 1 {
		t.Fatalf("counter %d", c.SignCount)
	}
}

func TestRefusesAWrongMethod(t *testing.T) {
	e := newEnv(t)
	in := e.call(t, exporterA, "/govcs.forge.admin.v1.AdminService/DisableUser", []byte("request-bytes"), exporterA)
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrBadSignature)
}

func TestRefusesAlteredRequestBytes(t *testing.T) {
	e := newEnv(t)
	in := e.good(t)
	in.Request = []byte("request-bytez")
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrBadSignature)
}

func TestRefusesAReplayedNonce(t *testing.T) {
	e := newEnv(t)
	in := e.good(t)
	if _, err := e.v.Verify(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrNonceUnknown)
}

func TestAFailedAttemptBurnsTheNonce(t *testing.T) {
	e := newEnv(t)
	in := e.good(t)
	bad := in
	bad.Request = []byte("other")
	wantErr(t, mustFail(e.v.Verify(context.Background(), bad)), adminauth.ErrBadSignature)
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrNonceUnknown)
}

func TestRefusesAnExpiredNonce(t *testing.T) {
	e := newEnv(t)
	in := e.good(t)
	*e.clock = e.clock.Add(time.Minute)
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrNonceExpired)
}

func TestRefusesANonceUsedOnAnotherConnection(t *testing.T) {
	e := newEnv(t)
	in := e.good(t) // nonce issued on, and signed for, connection A
	in.Exporter = exporterB
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrNonceOtherConnection)
}

func TestRefusesAnotherConnectionsExporterInTheSignature(t *testing.T) {
	e := newEnv(t)
	// The nonce is B's and the call arrives on B, but the key signed with A's
	// exporter: a relay from another connection.
	in := e.call(t, exporterB, method, []byte("request-bytes"), exporterA)
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrBadSignature)
}

func TestRefusesUnsetUV(t *testing.T) {
	e := newEnv(t)
	e.auth.NoUV = true
	wantErr(t, mustFail(e.v.Verify(context.Background(), e.good(t))), adminauth.ErrNotVerified)
}

func TestRefusesUnsetUP(t *testing.T) {
	e := newEnv(t)
	e.auth.NoUP = true
	wantErr(t, mustFail(e.v.Verify(context.Background(), e.good(t))), adminauth.ErrNotPresent)
}

func TestRefusesAnotherRelyingParty(t *testing.T) {
	e := newEnv(t)
	e.auth.WrongRP = "evil.example.org"
	wantErr(t, mustFail(e.v.Verify(context.Background(), e.good(t))), adminauth.ErrRPIDMismatch)
}

func TestRefusesAnUnknownCredential(t *testing.T) {
	e := newEnv(t)
	in := e.good(t)
	in.CredentialID = bytes.Repeat([]byte{9}, 32)
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrUnknownCredential)
}

func TestRefusesACounterRegression(t *testing.T) {
	e := newEnv(t)
	e.auth.Counter = 10
	if _, err := e.v.Verify(context.Background(), e.good(t)); err != nil {
		t.Fatal(err)
	}
	e.auth.Counter = 5
	e.auth.FreezeCount = true
	wantErr(t, mustFail(e.v.Verify(context.Background(), e.good(t))), adminauth.ErrCounterRegression)
}

func TestRefusesAZeroCounterAfterANonZeroOne(t *testing.T) {
	e := newEnv(t)
	if _, err := e.v.Verify(context.Background(), e.good(t)); err != nil {
		t.Fatal(err)
	}
	e.auth.ZeroCount = true
	wantErr(t, mustFail(e.v.Verify(context.Background(), e.good(t))), adminauth.ErrCounterRegression)
}

func TestAcceptsACounterThatNeverMoves(t *testing.T) {
	// An authenticator that keeps no counter reports zero for ever.
	e := newEnv(t)
	e.auth.ZeroCount = true
	for range 3 {
		if _, err := e.v.Verify(context.Background(), e.good(t)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRefusesOversizedFields(t *testing.T) {
	e := newEnv(t)
	in := e.good(t)
	in.Signature = make([]byte, adminauth.MaxSignatureLen+1)
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrMalformed)
	in = e.good(t)
	in.AuthenticatorData = make([]byte, adminauth.MaxAuthDataLen+1)
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrMalformed)
	in = e.good(t)
	in.CredentialID = nil
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrMalformed)
}

func TestRefusesTruncatedAuthenticatorData(t *testing.T) {
	e := newEnv(t)
	in := e.good(t)
	in.AuthenticatorData = in.AuthenticatorData[:20]
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrMalformed)
}

func TestRefusesAShortNonce(t *testing.T) {
	e := newEnv(t)
	in := e.good(t)
	in.Nonce = in.Nonce[:8]
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrNonceUnknown)
}

func mustFail(_ adminauth.Credential, err error) error { return err }

func TestClientDataHashFieldsDoNotRunTogether(t *testing.T) {
	a := adminauth.ClientDataHash("ab", []byte("c"), nil, nil)
	b := adminauth.ClientDataHash("a", []byte("bc"), nil, nil)
	if a == b {
		t.Fatal("field boundaries are ambiguous")
	}
	if adminauth.ClientDataHash(method, []byte{1}, []byte{2}, []byte{3}) == adminauth.ClientDataHash(method, []byte{1}, []byte{2}, []byte{4}) {
		t.Fatal("exporter is not covered")
	}
	if adminauth.EnrolClientDataHash([]byte{1}, "x") == adminauth.EnrolClientDataHash([]byte{1}, "y") {
		t.Fatal("name is not covered")
	}
}

func TestNonceBounds(t *testing.T) {
	e := newEnv(t)
	for range 4 {
		if _, _, err := e.nonces.Issue(exporterA); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := e.nonces.Issue(exporterA); !errors.Is(err, adminauth.ErrTooManyNonces) {
		t.Fatalf("per-connection bound: %v", err)
	}
	// Another connection still gets nonces until the global bound.
	for i := range 12 {
		x := bytes.Repeat([]byte{byte(i)}, 32)
		if _, _, err := e.nonces.Issue(x); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := e.nonces.Issue(exporterB); !errors.Is(err, adminauth.ErrTooManyNonces) {
		t.Fatalf("global bound: %v", err)
	}
	*e.clock = e.clock.Add(2 * time.Minute) // expiry frees the room
	if _, _, err := e.nonces.Issue(exporterB); err != nil {
		t.Fatal(err)
	}
}

func TestSessions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := adminauth.NewSessions(func() time.Time { return now }, time.Minute, 2, 4)
	tok, _, err := s.Open(exporterA)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Check(tok, exporterA); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(tok, exporterA); err != nil { // not single-use
		t.Fatal(err)
	}
	wantErr(t, s.Check(tok, exporterB), adminauth.ErrSessionOtherConn)
	wantErr(t, s.Check(make([]byte, 32), exporterA), adminauth.ErrSessionInvalid)
	wantErr(t, s.Check(tok[:5], exporterA), adminauth.ErrSessionInvalid)
	if _, _, err := s.Open(exporterA); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Open(exporterA); !errors.Is(err, adminauth.ErrTooManySessions) {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	wantErr(t, s.Check(tok, exporterA), adminauth.ErrSessionInvalid)
}
