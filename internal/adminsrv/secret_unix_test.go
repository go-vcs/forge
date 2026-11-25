// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/go-vcs/forge/internal/adminsrv"
)

func secretFixture(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	cert, _ := selfSigned(t)
	d := shortDir(t)
	certFile, keyFile = filepath.Join(d, "c.pem"), filepath.Join(d, "k.pem")
	writePEM(t, certFile, keyFile, cert)
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestLoadTLSRefusesAKeyOwnedBySomeoneElse(t *testing.T) {
	certFile, keyFile := secretFixture(t)
	if _, err := adminsrv.LoadTLS(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	defer adminsrv.UseEuid(os.Geteuid() + 1)()
	if _, err := adminsrv.LoadTLS(certFile, keyFile); err == nil {
		t.Fatal("a key owned by another user was loaded")
	}
}

func TestLoadTLSRefusesASymlinkedKey(t *testing.T) {
	certFile, keyFile := secretFixture(t)
	link := filepath.Join(filepath.Dir(keyFile), "link.pem")
	if err := os.Symlink(keyFile, link); err != nil {
		t.Fatal(err)
	}
	if _, err := adminsrv.LoadTLS(certFile, link); err == nil {
		t.Fatal("a symlink to a valid key was loaded")
	}
}

func TestLoadTLSRefusesANonRegularKey(t *testing.T) {
	certFile, _ := secretFixture(t)
	d := shortDir(t)
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := adminsrv.LoadTLS(certFile, d); err == nil {
		t.Fatal("a directory was accepted as a key")
	}
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adminsrv.LoadTLS(certFile, fifo); err == nil {
		t.Fatal("a FIFO was accepted as a key")
	}
}

func TestLoadTLSRefusesAnOversizedKey(t *testing.T) {
	certFile, _ := secretFixture(t)
	big := filepath.Join(shortDir(t), "big.pem")
	if err := os.WriteFile(big, make([]byte, 1<<20+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adminsrv.LoadTLS(certFile, big); err == nil {
		t.Fatal("an oversized key file was read")
	}
}
