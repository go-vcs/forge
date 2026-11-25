// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fidotest_test

import (
	"context"
	"testing"

	"github.com/go-vcs/forge/internal/fidotest"
)

func TestAssertRefusesAnotherCredential(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	if _, _, _, err := a.Make(context.Background(), "rp.example", nil, "k", [32]byte{}); err != nil {
		t.Fatal(err)
	}
	other := append([]byte(nil), a.CredID...)
	other[0] ^= 1
	if ad, sig, err := a.Assert(context.Background(), "rp.example", other, [32]byte{}); err == nil || ad != nil || sig != nil {
		t.Fatalf("Assert for another credential = %v, %v, %v; want a refusal", ad, sig, err)
	}
	if ad, _, err := a.Assert(context.Background(), "rp.example", a.CredID, [32]byte{}); err != nil || len(ad) != 37 {
		t.Fatalf("Assert for its own credential = %d bytes, %v", len(ad), err)
	}
}

func TestAssertRefusesBeforeAnyCredentialExists(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	if _, _, err := a.Assert(context.Background(), "rp.example", nil, [32]byte{}); err == nil {
		t.Fatal("Assert before Make succeeded")
	}
}
