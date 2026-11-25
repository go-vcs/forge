// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv_test

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// loadSays fails unless LoadTLS refuses with an error that says want: a guard
// is held by the reason it gives, not by the fact that something failed.
func loadSays(t *testing.T, name, certFile, keyFile, want string) {
	t.Helper()
	_, err := adminsrv.LoadTLS(certFile, keyFile)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: got %v, want a refusal saying %q", name, err, want)
	}
}

func TestLoadTLSRefusesAKeyOwnedBySomeoneElse(t *testing.T) {
	certFile, keyFile := secretFixture(t)
	if _, err := adminsrv.LoadTLS(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	defer adminsrv.UseEuid(os.Geteuid() + 1)()
	loadSays(t, "other owner", certFile, keyFile, "not owned by this user")
}

func TestLoadTLSRefusesASymlinkedOrMissingKey(t *testing.T) {
	certFile, keyFile := secretFixture(t)
	link := filepath.Join(filepath.Dir(keyFile), "link.pem")
	if err := os.Symlink(keyFile, link); err != nil {
		t.Fatal(err)
	}
	loadSays(t, "symlink", certFile, link, "symbolic links are refused")
	loadSays(t, "missing", certFile, filepath.Join(filepath.Dir(keyFile), "none.pem"), "key file")
}

func TestLoadTLSRefusesANonRegularKey(t *testing.T) {
	certFile, _ := secretFixture(t)
	d := shortDir(t)
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	loadSays(t, "directory", certFile, d, "not a regular file")
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	loadSays(t, "FIFO", certFile, fifo, "not a regular file")
}

func TestLoadTLSRefusesAnOversizedKey(t *testing.T) {
	certFile, _ := secretFixture(t)
	big := filepath.Join(shortDir(t), "big.pem")
	if err := os.WriteFile(big, make([]byte, 1<<20+1), 0o600); err != nil {
		t.Fatal(err)
	}
	loadSays(t, "oversized", certFile, big, "larger than")
}

func TestLoadTLSReportsAFailedRead(t *testing.T) {
	certFile, keyFile := secretFixture(t)
	defer adminsrv.UseReadAll(func(io.Reader) ([]byte, error) { return nil, errors.New("injected read failure") })()
	loadSays(t, "read", certFile, keyFile, "injected read failure")
}

func TestLoadTLSReportsAMissingCertificate(t *testing.T) {
	certFile, keyFile := secretFixture(t)
	_, err := adminsrv.LoadTLS(certFile+".none", keyFile)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want the missing certificate reported", err)
	}
}
