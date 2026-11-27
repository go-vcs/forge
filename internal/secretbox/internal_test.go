// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package secretbox

import (
	"errors"
	"testing"
)

func TestSealFailsWhenTheGeneratorFails(t *testing.T) {
	b, err := New(make([]byte, KeyLen))
	if err != nil {
		t.Fatal(err)
	}
	old := randRead
	t.Cleanup(func() { randRead = old })
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	if s, err := b.Seal([]byte("x"), "p"); err == nil || s != nil {
		t.Fatalf("Seal with no entropy = %v, %v", s, err)
	}
}
