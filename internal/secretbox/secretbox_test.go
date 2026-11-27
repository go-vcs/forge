// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package secretbox_test

import (
	"bytes"
	"testing"

	"github.com/go-vcs/forge/internal/secretbox"
)

func TestRoundTripAndRefusals(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("a %d-byte key panicked: %v", n, r)
				}
			}()
			if _, err := secretbox.New(make([]byte, n)); err == nil {
				t.Errorf("key of %d bytes accepted", n)
			}
		}()
	}
	b, err := secretbox.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s1, _ := b.Seal([]byte("hello"), "p")
	s2, _ := b.Seal([]byte("hello"), "p")
	if bytes.Equal(s1, s2) {
		t.Fatal("two seals are equal: the nonce is reused")
	}
	if p, err := b.Open(s1, "p"); err != nil || string(p) != "hello" {
		t.Fatalf("open = %q %v", p, err)
	}
	if _, err := b.Open(s1, "q"); err != secretbox.ErrOpen {
		t.Fatalf("other purpose: %v", err)
	}
	bad := append([]byte(nil), s1...)
	bad[len(bad)-1] ^= 1
	if _, err := b.Open(bad, "p"); err != secretbox.ErrOpen {
		t.Fatalf("tampered: %v", err)
	}
	for n := range len(s1) {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("a %d-byte input panicked: %v", n, r)
				}
			}()
			if _, err := b.Open(s1[:n], "p"); err != secretbox.ErrOpen {
				t.Errorf("short %d: %v", n, err)
			}
		}()
	}
	other, _ := secretbox.New(bytes.Repeat([]byte{8}, 32))
	if _, err := other.Open(s1, "p"); err != secretbox.ErrOpen {
		t.Fatalf("other key: %v", err)
	}
	if p, err := b.Open(mustSeal(t, b, nil), "p"); err != nil || len(p) != 0 {
		t.Fatalf("empty: %q %v", p, err)
	}
}

func mustSeal(t *testing.T, b *secretbox.Box, p []byte) []byte {
	t.Helper()
	s, err := b.Seal(p, "p")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
