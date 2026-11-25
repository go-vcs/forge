// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package fidotest is a software FIDO2 authenticator for tests, so that CI
// needs no hardware. It produces authenticator data, ES256 assertions and
// "packed" attestations with an x5c chain, written from WebAuthn and CTAP2, and
// each of its flaws (no UV, wrong relying party, backup flags, ...) can be
// switched on to exercise the matching refusal.
//
// It is not linked into the shipped binaries: only tests import it.
package fidotest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-authn/fido"
	"github.com/go-vcs/forge/internal/attest"
)

// YubiKeyBioAAGUID is the AAGUID of the target key.
var YubiKeyBioAAGUID = [16]byte{0x9d, 0xd8, 0xd5, 0x93, 0x22, 0x13, 0x43, 0x8a, 0xa6, 0xd8, 0xb9, 0x7f, 0x13, 0xd5, 0x1c, 0x27}

var oidAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// Authenticator is a software authenticator holding at most one credential.
type Authenticator struct {
	AAGUID  [16]byte
	Key     *ecdsa.PrivateKey
	CredID  []byte
	Counter uint32

	// Flaws, all off by default.
	NoUV, NoUP   bool
	Backup       bool   // set BE and BS
	WrongRP      string // hash this relying party id instead
	FreezeCount  bool   // do not advance Counter
	ZeroCount    bool   // report counter 0
	BadAttestSig bool
	NoX5C        bool
	LeafAAGUID   *[16]byte // AAGUID extension value override
	LeafOU       string    // subject OU override

	// Leaf certificate shapes, applied by Reissue.
	LeafCA        bool             // mark the leaf a CA
	LeafNoBasic   bool             // omit basic constraints
	LeafCritical  bool             // mark the AAGUID extension critical
	LeafExtValue  []byte           // raw AAGUID extension value override
	LeafPublicKey crypto.PublicKey // certify this key instead of the signing one

	caKey   *ecdsa.PrivateKey
	caCert  *x509.Certificate
	leafKey *ecdsa.PrivateKey
	// Chain is DER of the attestation leaf (and nothing else: the root is
	// the trust anchor, held by the relying party).
	leafDER []byte
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func serial() *big.Int { return must(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))) }

// New returns an authenticator of the model aaguid with a fresh attestation
// root and leaf.
func New(aaguid [16]byte) *Authenticator {
	a := &Authenticator{AAGUID: aaguid}
	a.caKey = must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Test FIDO Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der := must(x509.CreateCertificate(rand.Reader, tmpl, tmpl, &a.caKey.PublicKey, a.caKey))
	a.caCert = must(x509.ParseCertificate(der))
	a.leaf()
	return a
}

// leaf (re)creates the attestation certificate from the current knobs.
func (a *Authenticator) leaf() {
	a.leafKey = must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	ou := "Authenticator Attestation"
	if a.LeafOU != "" {
		ou = a.LeafOU
	}
	id := a.AAGUID
	if a.LeafAAGUID != nil {
		id = *a.LeafAAGUID
	}
	ext := must(asn1.Marshal(id[:]))
	if a.LeafExtValue != nil {
		ext = a.LeafExtValue
	}
	var pub crypto.PublicKey = &a.leafKey.PublicKey
	if a.LeafPublicKey != nil {
		pub = a.LeafPublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{Country: []string{"SE"}, Organization: []string{"Test"}, OrganizationalUnit: []string{ou}, CommonName: "Test attestation"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		BasicConstraintsValid: !a.LeafNoBasic,
		IsCA:                  a.LeafCA,
		ExtraExtensions:       []pkix.Extension{{Id: oidAAGUID, Critical: a.LeafCritical, Value: ext}},
	}
	a.leafDER = must(x509.CreateCertificate(rand.Reader, tmpl, a.caCert, pub, a.caKey))
}

// TamperLeaf rewrites the to-be-signed bytes of the attestation certificate
// with f and signs the result with the root, to build a certificate that
// x509.CreateCertificate would refuse to make (an old version, say).
func (a *Authenticator) TamperLeaf(f func(tbs []byte) []byte) {
	c := must(x509.ParseCertificate(a.leafDER))
	var parts struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}
	must(asn1.Unmarshal(c.Raw, &parts))
	tbs := f(append([]byte(nil), c.RawTBSCertificate...))
	d := sha256.Sum256(tbs)
	parts.TBS = asn1.RawValue{FullBytes: tbs}
	parts.Sig = asn1.BitString{Bytes: must(ecdsa.SignASN1(rand.Reader, a.caKey, d[:])), BitLength: 0}
	parts.Sig.BitLength = len(parts.Sig.Bytes) * 8
	a.leafDER = must(asn1.Marshal(parts))
}

// Reissue makes a new attestation leaf after a knob that shapes it changed.
func (a *Authenticator) Reissue() { a.leaf() }

// Root is the attestation trust anchor.
func (a *Authenticator) Root() *x509.Certificate { return a.caCert }

// Roots implements [attest.Roots] for this authenticator's model only.
func (a *Authenticator) Roots(aaguid string) ([]*x509.Certificate, error) {
	if aaguid != attest.FormatAAGUID(a.AAGUID) {
		return nil, attest.ErrUnknownModel
	}
	return []*x509.Certificate{a.caCert}, nil
}

func (a *Authenticator) flags(attested bool) byte {
	var f byte
	if !a.NoUP {
		f |= byte(fido.FlagUP)
	}
	if !a.NoUV {
		f |= byte(fido.FlagUV)
	}
	if a.Backup {
		f |= byte(fido.FlagBE | fido.FlagBS)
	}
	if attested {
		f |= byte(fido.FlagAT)
	}
	return f
}

func (a *Authenticator) header(rpID string, attested bool) []byte {
	if a.WrongRP != "" {
		rpID = a.WrongRP
	}
	h := sha256.Sum256([]byte(rpID))
	b := append([]byte(nil), h[:]...)
	b = append(b, a.flags(attested))
	var c [4]byte
	cnt := a.Counter
	if a.ZeroCount {
		cnt = 0
	}
	binary.BigEndian.PutUint32(c[:], cnt)
	return append(b, c[:]...)
}

func sign(k *ecdsa.PrivateKey, authData []byte, cdh [32]byte) []byte {
	d := sha256.Sum256(append(append([]byte(nil), authData...), cdh[:]...))
	return must(ecdsa.SignASN1(rand.Reader, k, d[:]))
}

// Assert implements adminclient.Signer.
func (a *Authenticator) Assert(_ context.Context, rpID string, credentialID []byte, cdh [32]byte) ([]byte, []byte, error) {
	if a.Key == nil || string(credentialID) != string(a.CredID) {
		return nil, nil, errors.New("fidotest: no such credential")
	}
	if !a.FreezeCount {
		a.Counter++
	}
	ad := a.header(rpID, false)
	return ad, sign(a.Key, ad, cdh), nil
}

// Make implements adminclient.Signer: it creates the credential.
func (a *Authenticator) Make(_ context.Context, rpID string, _ []byte, _ string, cdh [32]byte) (string, []byte, []byte, error) {
	a.Key = must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	a.CredID = make([]byte, 32)
	must(rand.Read(a.CredID))
	pub := must(a.Key.PublicKey.Bytes())
	cose := must(cbor.CTAP2EncOptions().EncMode())
	ck := must(cose.Marshal(map[int64]any{1: 2, 3: fido.AlgES256, -1: 1, -2: pub[1:33], -3: pub[33:]}))
	ad := a.header(rpID, true)
	ad = append(ad, a.AAGUID[:]...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(a.CredID)))
	ad = append(ad, a.CredID...)
	ad = append(ad, ck...)

	sig := sign(a.leafKey, ad, cdh)
	if a.BadAttestSig {
		sig[len(sig)-1] ^= 1
	}
	stmt := map[string]any{"alg": fido.AlgES256, "sig": sig}
	if !a.NoX5C {
		stmt["x5c"] = [][]byte{a.leafDER}
	}
	return "packed", ad, must(cose.Marshal(stmt)), nil
}
