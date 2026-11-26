// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package gitssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/go-vcs/forge/internal/sshtest"
)

func writeKey(t *testing.T, name string, key any, pass string, mode os.FileMode) string {
	t.Helper()
	var blk *pem.Block
	var err error
	if pass == "" {
		blk, err = ssh.MarshalPrivateKey(key, "")
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte(pass))
	}
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadHostKey(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := writeKey(t, "host", ed, "", 0o600)
	s, err := LoadHostKey(p)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ssh.NewSignerFromKey(ed)
	if ssh.FingerprintSHA256(s.PublicKey()) != ssh.FingerprintSHA256(want.PublicKey()) {
		t.Fatal("another key was loaded")
	}
}

func TestLoadHostKeyRefusals(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if _, err := LoadHostKey(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing file was accepted: the key must never be generated")
	}
	if _, err := LoadHostKey(writeKey(t, "ecdsa", ec, "", 0o600)); err == nil {
		t.Error("an ECDSA host key was accepted")
	}
	if _, err := LoadHostKey(writeKey(t, "pass", ed, "pw", 0o600)); err == nil {
		t.Error("a passphrase-protected host key was accepted")
	}
	garbage := filepath.Join(t.TempDir(), "garbage")
	if err := os.WriteFile(garbage, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostKey(garbage); err == nil {
		t.Error("garbage was accepted")
	}
	// a public key is not a host key
	pub := filepath.Join(t.TempDir(), "pub")
	if err := os.WriteFile(pub, []byte(sshtest.NewEd25519(t).Line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostKey(pub); err == nil {
		t.Error("a public key was accepted")
	}
}

func TestLoadHostKeyChecksTheFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the owner-only and symbolic-link checks are POSIX")
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	open := writeKey(t, "open", ed, "", 0o644)
	if _, err := LoadHostKey(open); err == nil {
		t.Error("a group- and world-readable host key was accepted")
	}
	good := writeKey(t, "good", ed, "", 0o600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostKey(link); err == nil {
		t.Error("a symbolic link was accepted")
	}
}
