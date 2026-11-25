// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package attest_test

import (
	"testing"

	"github.com/go-vcs/forge/internal/attest"
	"github.com/go-vcs/forge/internal/fidotest"
)

// FuzzParseStatement: arbitrary bytes must never panic the statement parser,
// and a chain it returns is never longer than the bound.
func FuzzParseStatement(f *testing.F) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	_, _, st, _ := a.Make(f.Context(), rp, nil, "x", cdh)
	f.Add(st)
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte{0xbf, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, chain, err := attest.ParseStatement(b)
		if err == nil && (len(chain) == 0 || len(chain) > attest.MaxChainLen) {
			t.Fatalf("chain of %d certificates accepted", len(chain))
		}
	})
}

// FuzzAttestationVerify: arbitrary authenticator data and statements must
// never panic Verify, and whatever it accepts must be a credential of the
// allowlisted model with a key.
func FuzzAttestationVerify(f *testing.F) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	p, err := attest.NewPolicy(rp, [][16]byte{a.AAGUID}, a, nil)
	if err != nil {
		f.Fatal(err)
	}
	_, ad, st, _ := a.Make(f.Context(), rp, nil, "x", cdh)
	f.Add(ad, st)
	f.Add(ad[:37], st)
	f.Add(ad, []byte{0xa0})
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, authData, stmt []byte) {
		r, err := p.Verify("packed", authData, stmt, cdh)
		if err != nil {
			return
		}
		if r.AAGUID != attest.FormatAAGUID(a.AAGUID) || r.PublicKey == nil || len(r.CredentialID) == 0 {
			t.Fatalf("accepted a credential that is not of the allowlisted model: %+v", r)
		}
	})
}
