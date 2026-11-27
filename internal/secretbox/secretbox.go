// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package secretbox encrypts the few secrets the forge stores (the OIDC client
// secret) at rest: AES-256-GCM, a fresh random nonce per seal, and additional
// data naming what the secret is, so a ciphertext copied into another row or
// purpose does not open.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeyLen is the key length in bytes.
const KeyLen = 32

// ErrOpen is the one answer for every reason a box does not open.
var ErrOpen = errors.New("secretbox: cannot open")

// Box seals and opens with one key.
type Box struct{ aead cipher.AEAD }

// New returns a Box for a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("secretbox: key is %d bytes, want %d", len(key), KeyLen)
	}
	// Neither call can fail for a 32-byte key (aes: only the length is checked;
	// GCM: only the block size, 16 for AES).
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	return &Box{aead: g}, nil
}

// randRead is replaced by a test: the system generator does not fail.
var randRead = rand.Read

// Seal returns nonce || ciphertext, bound to purpose.
func (b *Box) Seal(plain []byte, purpose string) ([]byte, error) {
	n := make([]byte, b.aead.NonceSize(), b.aead.NonceSize()+len(plain)+b.aead.Overhead())
	if _, err := randRead(n); err != nil {
		return nil, err
	}
	return b.aead.Seal(n, n, plain, []byte(purpose)), nil
}

// Open reverses Seal for the same purpose.
func (b *Box) Open(sealed []byte, purpose string) ([]byte, error) {
	ns := b.aead.NonceSize()
	if len(sealed) < ns+b.aead.Overhead() {
		return nil, ErrOpen
	}
	p, err := b.aead.Open(nil, sealed[:ns], sealed[ns:], []byte(purpose))
	if err != nil {
		return nil, ErrOpen
	}
	return p, nil
}
