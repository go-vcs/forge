// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package attest verifies the attestation of an admin credential at enrolment.
//
// Only the "packed" format with an x5c chain is accepted, chained to the roots
// that FIDO MDS3 lists for the model, and only for allowlisted AAGUIDs. There
// is no "none" format, no self attestation and no switch that turns a check
// off: a Policy cannot even be built without an allowlist and a root source.
//
// This is the WebAuthn Level 3 section 8.2 "packed" verification procedure. It
// lives here because go-authn/fido leaves the attestation statement as raw
// CBOR; it may move there later.
package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-authn/fido"
	"github.com/go-authn/fido/mds"
)

// Errors Verify returns; each has a test.
var (
	ErrFormat          = errors.New("attestation format not accepted (only packed with x5c)")
	ErrMalformed       = errors.New("malformed attestation")
	ErrRPIDMismatch    = errors.New("authenticator data is for another relying party")
	ErrNotPresent      = errors.New("user presence flag not set")
	ErrNotVerified     = errors.New("user verification flag not set")
	ErrNoCredential    = errors.New("no attested credential data")
	ErrBackupEligible  = errors.New("credential is backup eligible or backed up (not hardware bound)")
	ErrAAGUIDNotListed = errors.New("AAGUID is not on the allowlist")
	ErrUnknownModel    = errors.New("AAGUID unknown to the FIDO metadata service")
	ErrCertificate     = errors.New("attestation certificate rejected")
	ErrChain           = errors.New("attestation certificate does not chain to the metadata roots")
	ErrBadSignature    = errors.New("attestation signature does not verify")
	ErrAlgorithm       = errors.New("credential key algorithm is not ES256")
)

// Bounds on attestation input.
const (
	MaxAuthDataLen  = 4096
	MaxStatementLen = 16384
	MaxChainLen     = 4
	MaxCredIDLen    = 1024
)

// Roots yields the trust anchors for a model.
type Roots interface {
	// Roots returns the attestation roots for the AAGUID (canonical dashed
	// lowercase), or an error wrapping ErrUnknownModel.
	Roots(aaguid string) ([]*x509.Certificate, error)
}

// Policy decides which attestations are accepted.
type Policy struct {
	rpID  string
	allow map[[16]byte]bool
	roots Roots
	now   func() time.Time
}

// NewPolicy builds a policy. The allowlist must not be empty and roots must be
// set: there is deliberately no way to disable either.
func NewPolicy(rpID string, allow [][16]byte, roots Roots, now func() time.Time) (*Policy, error) {
	if rpID == "" {
		return nil, errors.New("attest: relying party id is empty")
	}
	if len(allow) == 0 {
		return nil, errors.New("attest: the AAGUID allowlist is empty")
	}
	if roots == nil {
		return nil, errors.New("attest: no metadata root source")
	}
	if now == nil {
		now = time.Now
	}
	m := make(map[[16]byte]bool, len(allow))
	for _, a := range allow {
		m[a] = true
	}
	return &Policy{rpID: rpID, allow: m, roots: roots, now: now}, nil
}

// Result is a verified credential.
type Result struct {
	AAGUID       string
	CredentialID []byte
	PublicKey    *ecdsa.PublicKey
}

// FormatAAGUID renders 16 bytes as the canonical dashed lowercase form.
func FormatAAGUID(a [16]byte) string {
	s := fmt.Sprintf("%x", a[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

// ParseAAGUID reads the dashed or plain hex form.
func ParseAAGUID(s string) ([16]byte, error) {
	var out [16]byte
	n, ok := mds.NormalizeAAGUID(s)
	if !ok {
		return out, fmt.Errorf("attest: %q is not an AAGUID", s)
	}
	// NormalizeAAGUID has accepted exactly 32 hex digits, so this cannot fail.
	b, _ := hex.DecodeString(strings.ReplaceAll(n, "-", ""))
	copy(out[:], b)
	return out, nil
}

// statement is the packed attestation statement. Unknown keys (such as
// ecdaaKeyId) are errors.
type statement struct {
	Alg int64    `cbor:"alg"`
	Sig []byte   `cbor:"sig"`
	X5C [][]byte `cbor:"x5c"`
}

var stmtDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:   4,
		MaxArrayElements:  16, // library minimum; MaxChainLen is enforced below
		MaxMapPairs:       16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		IndefLength:       cbor.IndefLengthForbidden,
	}.DecMode()
	if err != nil {
		panic("attest: " + err.Error())
	}
	return m
}()

// ParseStatement decodes a packed attestation statement.
func ParseStatement(b []byte) (alg int64, sig []byte, chain []*x509.Certificate, err error) {
	if len(b) == 0 || len(b) > MaxStatementLen {
		return 0, nil, nil, fmt.Errorf("%w: statement size", ErrMalformed)
	}
	var s statement
	if err := stmtDec.Unmarshal(b, &s); err != nil {
		return 0, nil, nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(s.X5C) == 0 {
		return 0, nil, nil, fmt.Errorf("%w: no x5c (self attestation is not accepted)", ErrFormat)
	}
	if len(s.X5C) > MaxChainLen {
		return 0, nil, nil, fmt.Errorf("%w: x5c holds %d certificates", ErrMalformed, len(s.X5C))
	}
	for i, der := range s.X5C {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("%w: x5c[%d]: %v", ErrCertificate, i, err)
		}
		chain = append(chain, c)
	}
	return s.Alg, s.Sig, chain, nil
}

// oidAAGUID is id-fido-gen-ce-aaguid.
var oidAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// Verify checks an attestation object's parts against the challenge hash cdh
// and returns the credential it attests. Every check must pass.
func (p *Policy) Verify(format string, authData, attStmt []byte, cdh [32]byte) (Result, error) {
	if format != "packed" {
		return Result{}, fmt.Errorf("%w: %q", ErrFormat, format)
	}
	if len(authData) == 0 || len(authData) > MaxAuthDataLen {
		return Result{}, fmt.Errorf("%w: authenticator data size", ErrMalformed)
	}
	ad, err := fido.ParseAuthData(authData)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	want := sha256.Sum256([]byte(p.rpID))
	if subtle.ConstantTimeCompare(ad.RPIDHash[:], want[:]) != 1 {
		return Result{}, ErrRPIDMismatch
	}
	if !ad.Flags.Has(fido.FlagUP) {
		return Result{}, ErrNotPresent
	}
	if !ad.Flags.Has(fido.FlagUV) {
		return Result{}, ErrNotVerified
	}
	if !ad.Flags.Has(fido.FlagAT) || len(ad.CredentialID) == 0 || len(ad.CredentialID) > MaxCredIDLen {
		return Result{}, ErrNoCredential
	}
	if ad.Flags.Has(fido.FlagBE) || ad.Flags.Has(fido.FlagBS) {
		return Result{}, ErrBackupEligible
	}
	if !p.allow[ad.AAGUID] {
		return Result{}, fmt.Errorf("%w: %s", ErrAAGUIDNotListed, FormatAAGUID(ad.AAGUID))
	}
	pub, err := ad.PublicKey()
	if err != nil { // PublicKey decodes only P-256 with ES256
		return Result{}, fmt.Errorf("%w: %v", ErrAlgorithm, err)
	}

	alg, sig, chain, err := ParseStatement(attStmt)
	if err != nil {
		return Result{}, err
	}
	if alg != fido.AlgES256 {
		return Result{}, fmt.Errorf("%w: statement alg %d", ErrAlgorithm, alg)
	}
	leaf := chain[0]
	if err := checkLeaf(leaf, ad.AAGUID); err != nil {
		return Result{}, err
	}
	// The root list is looked up only after the allowlist, and what it says is
	// what the chain must end in.
	aaguid := FormatAAGUID(ad.AAGUID)
	roots, err := p.roots.Roots(aaguid)
	if err != nil {
		return Result{}, err
	}
	if len(roots) == 0 {
		return Result{}, fmt.Errorf("%w: %s lists no attestation roots", ErrUnknownModel, aaguid)
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		CurrentTime:   p.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrChain, err)
	}
	lpub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || lpub.Curve != elliptic.P256() {
		return Result{}, fmt.Errorf("%w: attestation key is not P-256", ErrCertificate)
	}
	signed := make([]byte, 0, len(authData)+len(cdh))
	signed = append(signed, authData...)
	signed = append(signed, cdh[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(lpub, digest[:], sig) {
		return Result{}, ErrBadSignature
	}
	return Result{AAGUID: aaguid, CredentialID: append([]byte(nil), ad.CredentialID...), PublicKey: pub}, nil
}

// checkLeaf applies the requirements of WebAuthn 8.2.1 on the attestation
// certificate: version 3, subject OU "Authenticator Attestation", not a CA, and
// the AAGUID extension, when present, equal to the AAGUID in the authenticator
// data.
func checkLeaf(c *x509.Certificate, aaguid [16]byte) error {
	if c.Version != 3 {
		return fmt.Errorf("%w: version %d", ErrCertificate, c.Version)
	}
	if !hasOU(c.Subject, "Authenticator Attestation") {
		return fmt.Errorf("%w: subject OU is not \"Authenticator Attestation\"", ErrCertificate)
	}
	if c.BasicConstraintsValid && c.IsCA {
		return fmt.Errorf("%w: a CA certificate", ErrCertificate)
	}
	if !c.BasicConstraintsValid {
		return fmt.Errorf("%w: no basic constraints", ErrCertificate)
	}
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidAAGUID) {
			continue
		}
		var v []byte
		if rest, err := asn1.Unmarshal(e.Value, &v); err != nil || len(rest) != 0 {
			return fmt.Errorf("%w: AAGUID extension is not an OCTET STRING", ErrCertificate)
		}
		if e.Critical {
			return fmt.Errorf("%w: AAGUID extension is critical", ErrCertificate)
		}
		if !bytes.Equal(v, aaguid[:]) {
			return fmt.Errorf("%w: AAGUID extension differs from the authenticator data", ErrCertificate)
		}
	}
	return nil
}

func hasOU(n pkix.Name, want string) bool {
	for _, ou := range n.OrganizationalUnit {
		if ou == want {
			return true
		}
	}
	return false
}
