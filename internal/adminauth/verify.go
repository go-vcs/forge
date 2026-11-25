// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/go-authn/fido"
)

// Errors Verify returns. Each is a distinct refusal and each has a test.
var (
	ErrUnknownCredential = errors.New("unknown or revoked credential")
	ErrMalformed         = errors.New("malformed assertion")
	ErrRPIDMismatch      = errors.New("authenticator data is for another relying party")
	ErrNotPresent        = errors.New("user presence flag not set")
	ErrNotVerified       = errors.New("user verification flag not set")
	ErrBadSignature      = errors.New("signature does not verify")
	ErrCounterRegression = errors.New("signature counter went backwards")
)

// IsRefusal reports whether err is one of this package's refusals: a verdict
// on what the caller sent, whose reason the caller may be told. Any other error
// Verify returns is a failure of the server's own storage; it says nothing
// about the assertion and its text is not for the peer, who at that point has
// proved nothing.
func IsRefusal(err error) bool {
	for _, r := range []error{
		ErrNonceUnknown, ErrNonceExpired, ErrNonceOtherConnection,
		ErrUnknownCredential, ErrMalformed, ErrRPIDMismatch, ErrNotPresent,
		ErrNotVerified, ErrBadSignature, ErrCounterRegression,
	} {
		if errors.Is(err, r) {
			return true
		}
	}
	return false
}

// Size bounds on what an assertion may carry; larger input is refused before
// any cryptography.
const (
	MaxCredentialIDLen = 1024
	MaxAuthDataLen     = 512
	MaxSignatureLen    = 160
)

// Credential is an enrolled admin credential.
type Credential struct {
	ID        []byte
	PublicKey *ecdsa.PublicKey
	SignCount uint32
	AAGUID    string
	Name      string
}

// Credentials is the storage the verifier needs.
type Credentials interface {
	// ActiveCredential returns the credential, or ErrUnknownCredential when it
	// does not exist or is revoked.
	ActiveCredential(ctx context.Context, id []byte) (Credential, error)
	// AdvanceCounter records the counter of an accepted assertion atomically,
	// and returns ErrCounterRegression when it is lower than the stored one
	// (or zero while the stored one is not).
	AdvanceCounter(ctx context.Context, id []byte, count uint32) error
}

// Assertion is what the authenticator returned for one call.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
}

// Input is everything one verification depends on.
type Input struct {
	Method   string // full gRPC method name, as the server received the call
	Nonce    []byte
	Request  []byte // the serialized parameters, as received
	Exporter []byte // exporter value of the connection the call arrived on
	Assertion
}

// Verifier checks assertions.
type Verifier struct {
	RPID        string
	Credentials Credentials
	Nonces      *Nonces
}

// Verify accepts the assertion only if every check passes, and returns the
// credential that signed. The nonce is spent first, whatever follows.
func (v *Verifier) Verify(ctx context.Context, in Input) (Credential, error) {
	if len(in.CredentialID) == 0 || len(in.CredentialID) > MaxCredentialIDLen ||
		len(in.AuthenticatorData) > MaxAuthDataLen || len(in.Signature) > MaxSignatureLen {
		// Still burn the nonce: a caller who sends junk learns nothing and keeps nothing.
		_ = v.Nonces.Consume(in.Nonce, in.Exporter)
		return Credential{}, fmt.Errorf("%w: field size", ErrMalformed)
	}
	if err := v.Nonces.Consume(in.Nonce, in.Exporter); err != nil {
		return Credential{}, err
	}
	cred, err := v.Credentials.ActiveCredential(ctx, in.CredentialID)
	if err != nil {
		return Credential{}, err
	}
	ad, err := fido.ParseAuthData(in.AuthenticatorData)
	if err != nil {
		return Credential{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	want := sha256.Sum256([]byte(v.RPID))
	if subtle.ConstantTimeCompare(ad.RPIDHash[:], want[:]) != 1 {
		return Credential{}, ErrRPIDMismatch
	}
	if !ad.Flags.Has(fido.FlagUP) {
		return Credential{}, ErrNotPresent
	}
	if !ad.Flags.Has(fido.FlagUV) {
		return Credential{}, ErrNotVerified
	}
	cdh := ClientDataHash(in.Method, in.Nonce, in.Request, in.Exporter)
	signed := make([]byte, 0, len(in.AuthenticatorData)+len(cdh))
	signed = append(signed, in.AuthenticatorData...)
	signed = append(signed, cdh[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(cred.PublicKey, digest[:], in.Signature) {
		return Credential{}, ErrBadSignature
	}
	// A stored counter of zero means the authenticator keeps none. Once it
	// has been seen non-zero it must never go down, and zero is down.
	if cred.SignCount != 0 && ad.SignCount < cred.SignCount {
		return Credential{}, ErrCounterRegression
	}
	if err := v.Credentials.AdvanceCounter(ctx, in.CredentialID, ad.SignCount); err != nil {
		return Credential{}, err
	}
	cred.SignCount = ad.SignCount
	return cred, nil
}
