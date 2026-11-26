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
// The WebAuthn Level 3 section 8.2 "packed" verification procedure is
// go-authn/webauthn's; this package adds forge's policy around it.
package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-authn/fido"
	"github.com/go-authn/fido/mds"
	"github.com/go-authn/webauthn"
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
	// The three AAGUID extension rules; each error also wraps ErrCertificate.
	ErrAAGUIDExtMissing   = errors.New("attestation certificate has no AAGUID extension")
	ErrAAGUIDExtMalformed = errors.New("AAGUID extension is not an OCTET STRING of 16 bytes")
	ErrAAGUIDExtMismatch  = errors.New("AAGUID extension differs from the authenticator data")
	ErrChain              = errors.New("attestation certificate does not chain to the metadata roots")
	ErrBadSignature       = errors.New("attestation signature does not verify")
	ErrAlgorithm          = errors.New("credential key algorithm is not ES256")
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

// Verify checks an attestation object's parts against the challenge hash cdh
// and returns the credential it attests. Every check must pass.
//
// The statement and certificate rules, the flags, the signature over
// authData || cdh and the AAGUID extension are go-authn/webauthn's
// VerifyAttestationStatement; what stays here is what only forge decides: the
// packed-with-x5c-only format, the allowlist, hardware-bound ES256 keys, the
// bounds, and the choice of roots.
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
	if !ad.Flags.Has(fido.FlagAT) || len(ad.CredentialID) == 0 || len(ad.CredentialID) > MaxCredIDLen {
		return Result{}, ErrNoCredential
	}
	if ad.Flags.Has(fido.FlagBE) || ad.Flags.Has(fido.FlagBS) {
		return Result{}, ErrBackupEligible
	}
	if !p.allow[ad.AAGUID] {
		return Result{}, fmt.Errorf("%w: %s", ErrAAGUIDNotListed, FormatAAGUID(ad.AAGUID))
	}
	pub, err := ad.PublicKey() // decodes only P-256 with ES256
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrAlgorithm, err)
	}
	// forge's own bounds: one to MaxChainLen certificates, ES256, no extra keys.
	alg, _, _, err := ParseStatement(attStmt)
	if err != nil {
		return Result{}, err
	}
	if alg != fido.AlgES256 {
		return Result{}, fmt.Errorf("%w: statement alg %d", ErrAlgorithm, alg)
	}
	cred, att, err := webauthn.VerifyAttestationStatement(p.rpID, format, authData, attStmt, cdh,
		webauthn.Policy{RequireUV: true, RequireAAGUIDExtension: true})
	if err != nil {
		return Result{}, mapErr(err)
	}
	if att.Type != webauthn.AttestationBasic || len(att.TrustPath) == 0 || cred.AAGUID != ad.AAGUID {
		return Result{}, fmt.Errorf("%w: not a packed x5c attestation", ErrFormat)
	}
	if lpub, ok := att.TrustPath[0].PublicKey.(*ecdsa.PublicKey); !ok || lpub.Curve != elliptic.P256() {
		return Result{}, fmt.Errorf("%w: attestation key is not P-256", ErrCertificate)
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
	if err := att.VerifyTrustPath(roots, p.now()); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrChain, err)
	}
	return Result{AAGUID: aaguid, CredentialID: append([]byte(nil), ad.CredentialID...), PublicKey: pub}, nil
}

// mapErr turns the library's sentinels into forge's, which stay the public
// contract. The AAGUID extension errors keep ErrCertificate as before.
func mapErr(err error) error {
	to := func(s error) error { return fmt.Errorf("%w: %v", s, err) }
	switch {
	case errors.Is(err, webauthn.ErrAAGUIDExtensionMissing):
		return fmt.Errorf("%w: %w: %v", ErrCertificate, ErrAAGUIDExtMissing, err)
	case errors.Is(err, webauthn.ErrAAGUIDExtensionMalformed):
		return fmt.Errorf("%w: %w: %v", ErrCertificate, ErrAAGUIDExtMalformed, err)
	case errors.Is(err, webauthn.ErrAAGUIDExtensionMismatch):
		return fmt.Errorf("%w: %w: %v", ErrCertificate, ErrAAGUIDExtMismatch, err)
	case errors.Is(err, webauthn.ErrSignature):
		return to(ErrBadSignature)
	case errors.Is(err, webauthn.ErrRPIDHash):
		return to(ErrRPIDMismatch)
	case errors.Is(err, webauthn.ErrUserPresence):
		return to(ErrNotPresent)
	case errors.Is(err, webauthn.ErrUserVerification):
		return to(ErrNotVerified)
	case errors.Is(err, webauthn.ErrBackup):
		return to(ErrBackupEligible)
	case errors.Is(err, webauthn.ErrAlgorithm), errors.Is(err, webauthn.ErrKey):
		// The credential key and the statement alg were checked as ES256 before
		// the call, so what is left is the attestation key not fitting alg.
		return fmt.Errorf("%w: attestation key is not P-256: %v", ErrCertificate, err)
	case errors.Is(err, webauthn.ErrAttestation):
		return to(ErrCertificate)
	}
	return to(ErrMalformed)
}
