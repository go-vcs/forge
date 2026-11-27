// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-vcs/forge/internal/adminsrv"
)

func TestLoadSealer(t *testing.T) {
	t.Setenv(adminsrv.CredentialsEnv, "")
	if b, err := loadSealer(""); b != nil || err != nil {
		t.Fatalf("no key anywhere = %v, %v", b, err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "k")
	if err := os.WriteFile(good, bytes.Repeat([]byte{5}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := loadSealer(good); b == nil || err != nil {
		t.Fatalf("explicit key = %v, %v", b, err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSealer(short); err == nil {
		t.Fatal("a short key was accepted")
	}
	open := filepath.Join(dir, "open")
	if err := os.WriteFile(open, bytes.Repeat([]byte{5}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	// refused when READ, not merely when its content is judged
	if _, err := loadSealer(open); err == nil || strings.Contains(err.Error(), "secrets key ") {
		t.Fatalf("a world-readable key = %v", err)
	}
	if _, err := loadSealer(filepath.Join(dir, "absent")); err == nil || strings.Contains(err.Error(), "secrets key ") {
		t.Fatalf("a missing key file = %v", err)
	}
	// a credentials directory with the credential, and without it
	cred := t.TempDir()
	t.Setenv(adminsrv.CredentialsEnv, cred)
	if b, err := loadSealer(""); b != nil || err != nil {
		t.Fatalf("credentials dir without secrets.key = %v, %v", b, err)
	}
	if err := os.WriteFile(filepath.Join(cred, "secrets.key"), bytes.Repeat([]byte{6}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := loadSealer(""); b == nil || err != nil {
		t.Fatalf("credential = %v, %v", b, err)
	}
	if err := os.WriteFile(filepath.Join(cred, "secrets.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSealer(""); err == nil {
		t.Fatal("a short credential was accepted")
	}
}
