// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminclient

import (
	"context"
	"errors"

	"github.com/go-authn/fido"
)

// FIDOSigner signs with a hardware key through go-authn/fido. It asks for user
// verification ("uv": true), which on a key with built-in verification (a
// YubiKey Bio's fingerprint) needs no PIN token. A key that can only verify by
// PIN is refused by the key itself and the error says so.
type FIDOSigner struct{ Key *fido.Key }

// Assert implements [Signer].
func (s FIDOSigner) Assert(ctx context.Context, rpID string, credentialID []byte, cdh [32]byte) ([]byte, []byte, error) {
	a, err := s.Key.GetAssertion(ctx, fido.GetAssertionRequest{
		RPID:           rpID,
		ClientDataHash: cdh[:],
		Allow:          []fido.Credential{{Type: "public-key", ID: credentialID}},
		Options:        map[string]bool{"uv": true},
	})
	if err != nil {
		return nil, nil, err
	}
	return a.AuthData, a.Signature, nil
}

// Make implements [Signer].
func (s FIDOSigner) Make(ctx context.Context, rpID string, userHandle []byte, name string, cdh [32]byte) (string, []byte, []byte, error) {
	a, err := s.Key.MakeCredential(ctx, fido.MakeCredentialRequest{
		ClientDataHash: cdh[:],
		RP:             fido.RelyingParty{ID: rpID, Name: "go-vcs forge"},
		User:           fido.User{ID: userHandle, Name: name, DisplayName: name},
		Algorithms:     []int64{fido.AlgES256},
		Options:        map[string]bool{"uv": true, "rk": false},
	})
	if err != nil {
		return "", nil, nil, err
	}
	if len(a.Statement) == 0 {
		return "", nil, nil, errors.New("adminclient: the key returned no attestation statement")
	}
	return a.Format, a.AuthData, []byte(a.Statement), nil
}
