// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"google.golang.org/grpc/credentials"
)

func tlsCreds(c *tls.Config) credentials.TransportCredentials { return credentials.NewTLS(c) }

func writePEM(t *testing.T, certFile, keyFile string, cert tls.Certificate) {
	t.Helper()
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	kb, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	k := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
	if err := os.WriteFile(certFile, c, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, k, 0o600); err != nil {
		t.Fatal(err)
	}
}
