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
	if (c.SignCount != 0 || n != 0) && n <= c.SignCount {
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

func newEnv(t testing.TB) *env {
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
	n := adminauth.NewNonces(func() time.Time { return *clock }, time.Minute, 16)
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
func (e *env) call(t testing.TB, exporter []byte, signMethod string, signRequest, signExporter []byte) adminauth.Input {
	t.Helper()
	nonce, _ := e.nonces.Issue(exporter)
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

func (e *env) good(t testing.TB) adminauth.Input {
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

// A refused assertion does not spend its nonce: the nonce is stateless, so
// there is nothing to burn, and it is bound to the connection and expires.
func TestAFailedAttemptDoesNotSpendTheNonce(t *testing.T) {
	e := newEnv(t)
	in := e.good(t)
	bad := in
	bad.Request = []byte("other")
	wantErr(t, mustFail(e.v.Verify(context.Background(), bad)), adminauth.ErrBadSignature)
	if _, err := e.v.Verify(context.Background(), in); err != nil {
		t.Fatalf("the right assertion after a refused one: %v", err)
	}
	// ... and it is spent by the accepted one.
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrNonceUnknown)
}

func TestRefusesAForgedNonce(t *testing.T) {
	e := newEnv(t)
	in := e.good(t)
	for i := range in.Nonce {
		f := append([]byte(nil), in.Nonce...)
		f[i] ^= 1
		in2 := in
		in2.Nonce = f
		if err := mustFail(e.v.Verify(context.Background(), in2)); !errors.Is(err, adminauth.ErrNonceUnknown) && !errors.Is(err, adminauth.ErrNonceExpired) {
			t.Fatalf("byte %d flipped: %v", i, err)
		}
	}
	// A nonce of another store (another key) is a forgery.
	other := adminauth.NewNonces(func() time.Time { return *e.clock }, time.Minute, 16)
	n, _ := other.Issue(exporterA)
	in.Nonce = n
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrNonceUnknown)
}

func TestRefusesAFutureIssueTimeEdit(t *testing.T) {
	// Moving the issue time forward to stretch the lifetime breaks the MAC.
	e := newEnv(t)
	in := e.good(t)
	in.Nonce = append([]byte(nil), in.Nonce...)
	in.Nonce[7]++
	*e.clock = e.clock.Add(time.Minute)
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrNonceUnknown)
}

func TestSpendIsAtomicAndChecksTheNonce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	n := adminauth.NewNonces(func() time.Time { return now }, time.Minute, 4)
	nonce, _ := n.Issue(exporterA)
	wantErr(t, n.Spend(nonce[:10], exporterA), adminauth.ErrNonceUnknown)
	wantErr(t, n.Spend(nonce, exporterB), adminauth.ErrNonceUnknown)
	if err := n.Check(nonce, exporterA); err != nil {
		t.Fatal(err)
	}
	if err := n.Spend(nonce, exporterA); err != nil {
		t.Fatal(err)
	}
	wantErr(t, n.Spend(nonce, exporterA), adminauth.ErrNonceUnknown)
	wantErr(t, n.Check(nonce, exporterA), adminauth.ErrNonceUnknown)
	now = now.Add(time.Minute)
	wantErr(t, n.Spend(nonce, exporterA), adminauth.ErrNonceExpired)
}

func TestOnlyAcceptedNoncesAreRemembered(t *testing.T) {
	e := newEnv(t)
	for range 1000 {
		e.nonces.Issue(exporterA) // issued, never used: stores nothing
	}
	// 16 accepted calls fit; the 17th needs room that expiry has not freed.
	e.auth.ZeroCount = true
	for range 16 {
		if _, err := e.v.Verify(context.Background(), e.good(t)); err != nil {
			t.Fatal(err)
		}
	}
	wantErr(t, mustFail(e.v.Verify(context.Background(), e.good(t))), adminauth.ErrNonceStoreFull)
	*e.clock = e.clock.Add(time.Minute) // expiry frees the room
	if _, err := e.v.Verify(context.Background(), e.good(t)); err != nil {
		t.Fatal(err)
	}
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
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrNonceUnknown)
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

// WebAuthn L3 7.2: the counter must be greater than the stored one when either
// is non-zero; an equal non-zero value is a replay or a clone.
func TestRefusesAnEqualNonZeroCounter(t *testing.T) {
	e := newEnv(t)
	e.auth.Counter = 10
	if _, err := e.v.Verify(context.Background(), e.good(t)); err != nil {
		t.Fatal(err)
	}
	e.auth.Counter = 10
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
	// A flood of nonces, from many connections, never refuses another one and
	// never stops a legitimate call: issuing stores nothing.
	for i := range 5000 {
		x := bytes.Repeat([]byte{byte(i), byte(i >> 8)}, 16)
		n, _ := e.nonces.Issue(x)
		if len(n) != adminauth.TokenLen {
			t.Fatalf("nonce length %d", len(n))
		}
	}
	if _, err := e.v.Verify(context.Background(), e.good(t)); err != nil {
		t.Fatalf("a legitimate call after a nonce flood: %v", err)
	}
}

func TestSessions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := adminauth.NewSessions(func() time.Time { return now }, time.Minute, 2, 4)
	check := func(tok, exp []byte) error { _, err := s.Check(tok, exp); return err }
	tok, _, err := s.Open(exporterA, []byte("cred-1"))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.Check(tok, exporterA)
	if err != nil || string(owner) != "cred-1" {
		t.Fatalf("Check = %q, %v; the session must name the credential that opened it", owner, err)
	}
	if err := check(tok, exporterA); err != nil { // not single-use
		t.Fatal(err)
	}
	wantErr(t, check(tok, exporterB), adminauth.ErrSessionOtherConn)
	wantErr(t, check(make([]byte, 32), exporterA), adminauth.ErrSessionInvalid)
	wantErr(t, check(tok[:5], exporterA), adminauth.ErrSessionInvalid)
	if _, _, err := s.Open(exporterA, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Open(exporterA, nil); !errors.Is(err, adminauth.ErrTooManySessions) {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	wantErr(t, check(tok, exporterA), adminauth.ErrSessionInvalid)
}
