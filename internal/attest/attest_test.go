// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package attest_test

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-authn/fido/mds"
	"github.com/go-vcs/forge/internal/attest"
	"github.com/go-vcs/forge/internal/fidotest"
)

const rp = "forge.example"

var cdh = sha256.Sum256([]byte("challenge"))

func policy(t *testing.T, a *fidotest.Authenticator, allow ...[16]byte) *attest.Policy {
	t.Helper()
	if len(allow) == 0 {
		allow = [][16]byte{a.AAGUID}
	}
	p, err := attest.NewPolicy(rp, allow, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func make1(t *testing.T, a *fidotest.Authenticator) (string, []byte, []byte) {
	t.Helper()
	f, ad, st, err := a.Make(t.Context(), rp, nil, "x", cdh)
	if err != nil {
		t.Fatal(err)
	}
	return f, ad, st
}

func wantErr(t *testing.T, p *attest.Policy, f string, ad, st []byte, want error) {
	t.Helper()
	_, err := p.Verify(f, ad, st, cdh)
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

func TestGoodAttestation(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	f, ad, st := make1(t, a)
	r, err := policy(t, a).Verify(f, ad, st, cdh)
	if err != nil {
		t.Fatal(err)
	}
	if r.AAGUID != attest.FormatAAGUID(a.AAGUID) || string(r.CredentialID) != string(a.CredID) {
		t.Fatalf("result %+v", r)
	}
	if !r.PublicKey.Equal(&a.Key.PublicKey) {
		t.Fatal("wrong public key")
	}
}

func TestAAGUIDNotOnAllowlist(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	other := [16]byte{1}
	f, ad, st := make1(t, a)
	wantErr(t, policy(t, a, other), f, ad, st, attest.ErrAAGUIDNotListed)
}

func TestFormatNotPacked(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	_, ad, st := make1(t, a)
	for _, f := range []string{"none", "fido-u2f", "", "packed "} {
		wantErr(t, policy(t, a), f, ad, st, attest.ErrFormat)
	}
}

func TestSelfAttestationRefused(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	a.NoX5C = true
	f, ad, st := make1(t, a)
	wantErr(t, policy(t, a), f, ad, st, attest.ErrFormat)
}

func TestBackupRefused(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	a.Backup = true
	f, ad, st := make1(t, a)
	wantErr(t, policy(t, a), f, ad, st, attest.ErrBackupEligible)
}

func TestUVUnsetRefused(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	a.NoUV = true
	f, ad, st := make1(t, a)
	wantErr(t, policy(t, a), f, ad, st, attest.ErrNotVerified)
}

func TestUPUnsetRefused(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	a.NoUP = true
	f, ad, st := make1(t, a)
	wantErr(t, policy(t, a), f, ad, st, attest.ErrNotPresent)
}

func TestWrongRPRefused(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	a.WrongRP = "evil.example"
	f, ad, st := make1(t, a)
	wantErr(t, policy(t, a), f, ad, st, attest.ErrRPIDMismatch)
}

func TestBadAttestationSignature(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	a.BadAttestSig = true
	f, ad, st := make1(t, a)
	wantErr(t, policy(t, a), f, ad, st, attest.ErrBadSignature)
}

func TestWrongChallenge(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	f, ad, st := make1(t, a)
	other := sha256.Sum256([]byte("another"))
	if _, err := policy(t, a).Verify(f, ad, st, other); !errors.Is(err, attest.ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestChainNotRootedInMetadata(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	b := fidotest.New(fidotest.YubiKeyBioAAGUID) // same model, other root
	f, ad, st := make1(t, a)
	p, err := attest.NewPolicy(rp, [][16]byte{a.AAGUID}, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantErr(t, p, f, ad, st, attest.ErrChain)
}

func TestExpiredLeafRefused(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	f, ad, st := make1(t, a)
	p, err := attest.NewPolicy(rp, [][16]byte{a.AAGUID}, a, func() time.Time { return time.Now().AddDate(10, 0, 0) })
	if err != nil {
		t.Fatal(err)
	}
	wantErr(t, p, f, ad, st, attest.ErrChain)
}

func TestLeafAAGUIDMismatch(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	other := [16]byte{9, 9}
	a.LeafAAGUID = &other
	a.Reissue()
	f, ad, st := make1(t, a)
	_, err := policy(t, a).Verify(f, ad, st, cdh)
	if !errors.Is(err, attest.ErrAAGUIDExtMismatch) || !errors.Is(err, attest.ErrCertificate) {
		t.Fatalf("got %v", err)
	}
}

func TestLeafWithoutAAGUIDExtensionIsRefused(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	a.LeafNoExt = true
	a.Reissue()
	f, ad, st := make1(t, a)
	_, err := policy(t, a).Verify(f, ad, st, cdh)
	if !errors.Is(err, attest.ErrAAGUIDExtMissing) || !errors.Is(err, attest.ErrCertificate) {
		t.Fatalf("got %v", err)
	}
}

func TestLeafAAGUIDExtensionOfTheWrongSizeIsRefused(t *testing.T) {
	for _, n := range []int{0, 15, 17} {
		a := fidotest.New(fidotest.YubiKeyBioAAGUID)
		v, err := asn1.Marshal(make([]byte, n))
		if err != nil {
			t.Fatal(err)
		}
		a.LeafExtValue = v
		a.Reissue()
		f, ad, st := make1(t, a)
		_, err = policy(t, a).Verify(f, ad, st, cdh)
		if !errors.Is(err, attest.ErrAAGUIDExtMalformed) || !errors.Is(err, attest.ErrCertificate) {
			t.Fatalf("%d bytes: got %v", n, err)
		}
	}
}

func TestLeafWrongOU(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	a.LeafOU = "Something Else"
	a.Reissue()
	f, ad, st := make1(t, a)
	wantErr(t, policy(t, a), f, ad, st, attest.ErrCertificate)
}

func TestUnknownModel(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	f, ad, st := make1(t, a)
	other := fidotest.New([16]byte{7})
	p, err := attest.NewPolicy(rp, [][16]byte{a.AAGUID}, other, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantErr(t, p, f, ad, st, attest.ErrUnknownModel)
}

func TestMalformedInputs(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	f, ad, st := make1(t, a)
	p := policy(t, a)
	wantErr(t, p, f, nil, st, attest.ErrMalformed)
	wantErr(t, p, f, make([]byte, attest.MaxAuthDataLen+1), st, attest.ErrMalformed)
	wantErr(t, p, f, ad[:20], st, attest.ErrMalformed)
	wantErr(t, p, f, ad, nil, attest.ErrMalformed)
	wantErr(t, p, f, ad, make([]byte, attest.MaxStatementLen+1), attest.ErrMalformed)
	wantErr(t, p, f, ad, []byte{0xff, 0x00}, attest.ErrMalformed)
	wantErr(t, p, f, ad[:len(ad)-3], st, attest.ErrMalformed)
}

func TestAuthDataWithoutCredential(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	f, ad, st := make1(t, a)
	// A 37-byte header whose AT flag is cleared carries no credential.
	h := append([]byte(nil), ad[:37]...)
	h[32] &^= 0x40
	wantErr(t, policy(t, a), f, h, st, attest.ErrNoCredential)
}

func TestStatementStrictness(t *testing.T) {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	f, ad, _ := make1(t, a)
	p := policy(t, a)
	bad := func(m map[string]any) []byte {
		b, err := enc.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// Unknown key (ecdaaKeyId), no chain, too long a chain, junk certificate.
	wantErr(t, p, f, ad, bad(map[string]any{"alg": -7, "sig": []byte{1}, "ecdaaKeyId": []byte{1}}), attest.ErrMalformed)
	wantErr(t, p, f, ad, bad(map[string]any{"alg": -7, "sig": []byte{1}}), attest.ErrFormat)
	c := []byte("not a certificate")
	wantErr(t, p, f, ad, bad(map[string]any{"alg": -7, "sig": []byte{1}, "x5c": [][]byte{c}}), attest.ErrCertificate)
	wantErr(t, p, f, ad, bad(map[string]any{"alg": -7, "sig": []byte{1}, "x5c": [][]byte{c, c, c, c, c}}), attest.ErrMalformed)
	// Wrong algorithm in the statement.
	_, _, st := make1(t, a)
	_, _, chain, err := attest.ParseStatement(st)
	if err != nil || len(chain) != 1 {
		t.Fatalf("parse: %v %d", err, len(chain))
	}
	wantErr(t, p, f, ad, bad(map[string]any{"alg": -257, "sig": []byte{1}, "x5c": [][]byte{chain[0].Raw}}), attest.ErrAlgorithm)
}

func TestNewPolicyRefusesWeakening(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	if _, err := attest.NewPolicy(rp, nil, a, nil); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	if _, err := attest.NewPolicy(rp, [][16]byte{{1}}, nil, nil); err == nil {
		t.Fatal("nil roots accepted")
	}
	if _, err := attest.NewPolicy("", [][16]byte{{1}}, a, nil); err == nil {
		t.Fatal("empty rp accepted")
	}
}

func TestAAGUIDText(t *testing.T) {
	s := attest.FormatAAGUID(fidotest.YubiKeyBioAAGUID)
	if s != "9dd8d593-2213-438a-a6d8-b97f13d51c27" {
		t.Fatal(s)
	}
	for _, in := range []string{s, "9dd8d5932213438aa6d8b97f13d51c27", "9DD8D593-2213-438A-A6D8-B97F13D51C27"} {
		got, err := attest.ParseAAGUID(in)
		if err != nil || got != fidotest.YubiKeyBioAAGUID {
			t.Fatalf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "xyz", s[:35], s + "0"} {
		if _, err := attest.ParseAAGUID(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}

// blobFor is a verified blob holding a's model; rootsFor serves from it while
// it is current.
func blobFor(t *testing.T, a *fidotest.Authenticator, status string) *mds.Blob {
	t.Helper()
	return verifiedBlob(t, entryFor(a, status))
}

func rootsFor(t *testing.T, a *fidotest.Authenticator, status string) attest.MDSRoots {
	t.Helper()
	return attest.MDSRoots{Blob: blobFor(t, a, status), Now: at(blobSigned)}
}

func entryFor(a *fidotest.Authenticator, status string) mds.Entry {
	e := mds.Entry{
		AAGUID: attest.FormatAAGUID(a.AAGUID),
		MetadataStatement: &mds.Statement{
			Description:                 "test key",
			AttestationRootCertificates: []string{base64.StdEncoding.EncodeToString(a.Root().Raw)},
		},
	}
	if status != "" {
		e.StatusReports = []mds.StatusReport{{Status: "FIDO_CERTIFIED_L1"}, {Status: status}}
	}
	return e
}

func TestMDSRoots(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	id := attest.FormatAAGUID(a.AAGUID)

	rs, err := rootsFor(t, a, "").Roots(id)
	if err != nil || len(rs) != 1 || !rs[0].Equal(a.Root()) {
		t.Fatalf("roots: %v %v", rs, err)
	}
	// Through a policy, end to end.
	f, ad, st := make1(t, a)
	p, err := attest.NewPolicy(rp, [][16]byte{a.AAGUID}, rootsFor(t, a, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(f, ad, st, cdh); err != nil {
		t.Fatal(err)
	}

	if _, err := rootsFor(t, a, "").Roots("00000000-0000-0000-0000-000000000000"); !errors.Is(err, attest.ErrUnknownModel) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := (attest.MDSRoots{}).Roots(id); !errors.Is(err, attest.ErrUnknownModel) {
		t.Fatalf("no blob: %v", err)
	}
	for _, s := range []string{"REVOKED", "ATTESTATION_KEY_COMPROMISE", "USER_VERIFICATION_BYPASS", "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE"} {
		if _, err := rootsFor(t, a, s).Roots(id); !errors.Is(err, attest.ErrModelRevoked) {
			t.Fatalf("%s: %v", s, err)
		}
	}
	// A status that is not terminal is not a refusal.
	if _, err := rootsFor(t, a, "UPDATE_AVAILABLE").Roots(id); err != nil {
		t.Fatalf("update available: %v", err)
	}
}
