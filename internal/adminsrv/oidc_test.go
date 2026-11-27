// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv_test

import (
	"bytes"
	"database/sql"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/secretbox"
)

const (
	issuer = "https://login.mesocentre.plateau-de-saclay.net"
	cbURL  = "https://forge.example/auth/callback"
)

func (f *forge) sealedColumn() []byte {
	f.t.Helper()
	db, err := sql.Open("sqlite", "file:"+f.db)
	if err != nil {
		f.t.Fatal(err)
	}
	defer db.Close()
	var b []byte
	if err := db.QueryRow(`SELECT secret_sealed FROM oidc_client WHERE id = 1`).Scan(&b); err != nil {
		f.t.Fatal(err)
	}
	return b
}

func TestOIDCClientSecretIsSealedAndNeverReturned(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	key := bytes.Repeat([]byte{7}, secretbox.KeyLen)
	box, err := secretbox.New(key)
	if err != nil {
		t.Fatal(err)
	}
	f.adm.Seal = box
	c := f.dial()
	ctx := t.Context()
	tok, _ := c.OpenSession(ctx)

	r, err := c.Admin.GetOIDCClient(ctx, &adminv1.GetOIDCClientRequest{SessionToken: tok})
	if err != nil || r.Client != nil {
		t.Fatalf("unset: %v %v", r, err)
	}
	if _, err := c.Admin.GetOIDCClient(ctx, &adminv1.GetOIDCClientRequest{}); code(err) != codes.Unauthenticated {
		t.Fatalf("get without session = %v", err)
	}
	if _, err := c.Admin.SetOIDCClient(ctx, &adminv1.SetOIDCClientRequest{}); code(err) != codes.InvalidArgument {
		t.Fatalf("set without envelope = %v", err)
	}

	secret := []byte("s3cr3t-value")
	if err := c.SetOIDCClient(ctx, issuer, "forge", cbURL, secret); err != nil {
		t.Fatal(err)
	}
	r, err = c.Admin.GetOIDCClient(ctx, &adminv1.GetOIDCClientRequest{SessionToken: tok})
	if err != nil || r.Client.GetClientId() != "forge" || !r.Client.HasSecret || r.Client.Issuer != issuer || r.Client.RedirectUri != cbURL {
		t.Fatalf("get = %v %v", r, err)
	}
	if strings.Contains(r.String(), string(secret)) {
		t.Fatal("the secret came back")
	}
	sealed := f.sealedColumn()
	if bytes.Contains(sealed, secret) {
		t.Fatal("secret stored in clear")
	}
	got, err := box.Open(sealed, adminsrv.OIDCSecretPurpose)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open = %q %v", got, err)
	}
	if _, err := box.Open(sealed, "another purpose"); err == nil {
		t.Fatal("sealed secret opens for another purpose")
	}
}

func TestOIDCClientRefusals(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	ctx := t.Context()
	// no sealing key: a secret is refused, never stored in clear
	wantStatus(t, "no key", c.SetOIDCClient(ctx, issuer, "forge", cbURL, []byte("x")), codes.FailedPrecondition, "secrets key")
	// a public client needs no key
	if err := c.SetOIDCClient(ctx, issuer, "forge", cbURL, nil); err != nil {
		t.Fatal(err)
	}
	box, _ := secretbox.New(bytes.Repeat([]byte{1}, secretbox.KeyLen))
	f.adm.Seal = box
	for name, tc := range map[string]struct{ iss, id, cb string }{
		"http issuer":     {"http://login.example", "forge", cbURL},
		"empty client id": {issuer, "", cbURL},
		"http callback":   {issuer, "forge", "http://forge.example/cb"},
		"fragment":        {issuer, "forge", cbURL + "#x"},
		"userinfo":        {issuer, "forge", "https://u:p@forge.example/cb"},
		"relative":        {issuer, "forge", "/auth/callback"},
	} {
		wantStatus(t, name, c.SetOIDCClient(ctx, tc.iss, tc.id, tc.cb, []byte("x")), codes.InvalidArgument, "")
	}
	wantStatus(t, "huge secret", c.SetOIDCClient(ctx, issuer, "forge", cbURL, bytes.Repeat([]byte("a"), 2048)), codes.InvalidArgument, "too long")
	f.rawExec(`DROP TABLE oidc_client`)
	tok, _ := c.OpenSession(ctx)
	_, err := c.Admin.GetOIDCClient(ctx, &adminv1.GetOIDCClientRequest{SessionToken: tok})
	wantStatus(t, "storage", err, codes.Internal, "internal error")
}
