// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package sshtest makes SSH keys for tests.
package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Key is a test key pair.
type Key struct {
	Signer ssh.Signer
	// Line is the authorized_keys line, without a comment.
	Line string
	// Fingerprint is the SHA256 fingerprint.
	Fingerprint string
	// PrivateFile is an OpenSSH private key file in a temporary directory,
	// mode 0600, for GIT_SSH_COMMAND -i.
	PrivateFile string
}

// NewEd25519 makes an ed25519 key and writes its private file.
func NewEd25519(t testing.TB) Key {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(file, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	return Key{
		Signer: signer, Line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
		Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), PrivateFile: file,
	}
}

// SKLine returns an authorized_keys line for a made-up sk-ssh-ed25519 key (it
// has no private half: it can be registered, not used to sign in).
func SKLine(t testing.TB) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.ParsePublicKey(ssh.Marshal(struct{ Name, Key, App string }{ssh.KeyAlgoSKED25519, string(pub), "ssh:"}))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}
