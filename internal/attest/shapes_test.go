// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package attest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-vcs/forge/internal/attest"
	"github.com/go-vcs/forge/internal/fidotest"
)

func wantMsg(t *testing.T, err error, is error, msg string) {
	t.Helper()
	if !errors.Is(err, is) {
		t.Fatalf("got %v, want %v", err, is)
	}
	if !strings.Contains(err.Error(), msg) {
		t.Fatalf("error %q does not say %q", err, msg)
	}
}

func TestSizeBoundsAnswerWithTheirOwnMessage(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	f, _, st := make1(t, a)
	p := policy(t, a)

	_, err := p.Verify(f, nil, st, cdh)
	wantMsg(t, err, attest.ErrMalformed, "authenticator data size")
	_, err = p.Verify(f, make([]byte, attest.MaxAuthDataLen+1), st, cdh)
	wantMsg(t, err, attest.ErrMalformed, "authenticator data size")

	_, _, _, err = attest.ParseStatement(nil)
	wantMsg(t, err, attest.ErrMalformed, "statement size")

	// An oversize statement that is otherwise well formed.
	_, _, chain, err := attest.ParseStatement(st)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	big, err := enc.Marshal(map[string]any{"alg": -7, "sig": make([]byte, attest.MaxStatementLen), "x5c": [][]byte{chain[0].Raw}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = attest.ParseStatement(big)
	wantMsg(t, err, attest.ErrMalformed, "statement size")
}

func TestAKeyThatIsNotAPointIsRefused(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	f, ad, st := make1(t, a)
	ad[len(ad)-1] ^= 1 // the last byte of y
	_, err := policy(t, a).Verify(f, ad, st, cdh)
	wantMsg(t, err, attest.ErrAlgorithm, "not on P-256")
}

type rootsFunc func(string) ([]*x509.Certificate, error)

func (f rootsFunc) Roots(id string) ([]*x509.Certificate, error) { return f(id) }

func TestTheRootListDecidesBeforeTheChainIsLooked(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	f, ad, st := make1(t, a)
	boom := errors.New("boom")
	p, err := attest.NewPolicy(rp, [][16]byte{a.AAGUID}, rootsFunc(func(string) ([]*x509.Certificate, error) { return nil, boom }), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(f, ad, st, cdh); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the lookup's own error", err)
	}
	p, err = attest.NewPolicy(rp, [][16]byte{a.AAGUID}, rootsFunc(func(string) ([]*x509.Certificate, error) { return nil, nil }), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Verify(f, ad, st, cdh)
	wantMsg(t, err, attest.ErrUnknownModel, "lists no attestation roots")
}

func TestLeafShapesAreRefused(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	octet := func(a *fidotest.Authenticator) []byte {
		b, err := asn1.Marshal(a.AAGUID[:])
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []struct {
		name string
		msg  string
		set  func(a *fidotest.Authenticator)
	}{
		{"a CA", "a CA certificate", func(a *fidotest.Authenticator) { a.LeafCA = true }},
		{"no basic constraints", "no basic constraints", func(a *fidotest.Authenticator) { a.LeafNoBasic = true }},
		{"a critical AAGUID extension", "critical", func(a *fidotest.Authenticator) { a.LeafCritical = true }},
		{"an extension that is not an octet string", "not an OCTET STRING", func(a *fidotest.Authenticator) { a.LeafExtValue = []byte{0xff} }},
		{"an extension with trailing bytes", "not an OCTET STRING", func(a *fidotest.Authenticator) { a.LeafExtValue = append(octet(a), 0) }},
		{"a P-384 key", "not P-256", func(a *fidotest.Authenticator) { a.LeafPublicKey = &p384.PublicKey }},
		{"an Ed25519 key", "not P-256", func(a *fidotest.Authenticator) { a.LeafPublicKey = edPub }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := fidotest.New(fidotest.YubiKeyBioAAGUID)
			c.set(a)
			a.Reissue()
			f, ad, st := make1(t, a)
			_, err := policy(t, a).Verify(f, ad, st, cdh)
			wantMsg(t, err, attest.ErrCertificate, c.msg)
		})
	}
}

func TestALeafThatIsNotVersion3IsRefused(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	a.TamperLeaf(func(tbs []byte) []byte {
		v3 := []byte{0xa0, 0x03, 0x02, 0x01, 0x02}
		i := bytes.Index(tbs, v3)
		if i < 0 || i > 8 {
			t.Fatalf("no version field at the start of %x", tbs[:16])
		}
		tbs[i+4] = 1 // version 2
		return tbs
	})
	f, ad, st := make1(t, a)
	_, err := policy(t, a).Verify(f, ad, st, cdh)
	wantMsg(t, err, attest.ErrCertificate, "version 2")
}

func TestAAGUIDWithNonHexDigitsIsRefused(t *testing.T) {
	if _, err := attest.ParseAAGUID(strings.Repeat("zz", 16)); err == nil {
		t.Fatal("accepted")
	}
}
