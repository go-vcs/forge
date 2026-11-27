// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv_test

import (
	"bytes"
	"database/sql"
	"errors"
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

func TestOIDCCallsRefuseWithoutAProperEnvelope(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	ctx := t.Context()
	// an envelope signed for another method is refused as unauthenticated
	env := f.envelope(c, createMethod, &adminv1.SetOIDCClientParams{Issuer: issuer, ClientId: "forge", RedirectUri: cbURL}, tweak{})
	if _, err := c.Admin.SetOIDCClient(ctx, &adminv1.SetOIDCClientRequest{Envelope: env}); code(err) != codes.Unauthenticated {
		t.Fatalf("envelope signed for CreateUser accepted: %v", err)
	}
	// unparseable parameters are refused as such
	env = f.envelope(c, adminv1.AdminService_SetOIDCClient_FullMethodName, nil, tweak{rawReq: []byte{0xff, 0xff}})
	_, err := c.Admin.SetOIDCClient(ctx, &adminv1.SetOIDCClientRequest{Envelope: env})
	wantStatus(t, "bad parameters", err, codes.InvalidArgument, "bad parameters")
	tok, _ := c.OpenSession(ctx)
	if r, err := c.Admin.GetOIDCClient(ctx, &adminv1.GetOIDCClientRequest{SessionToken: tok}); err != nil || r.Client != nil {
		t.Fatalf("a refused call registered a client: %v %v", r, err)
	}
}

func TestSealStatusAndNilBox(t *testing.T) {
	wantStatus(t, "no key", adminsrv.SealStatus(secretbox.ErrNoKey), codes.FailedPrecondition, "secrets key")
	wantStatus(t, "other", adminsrv.SealStatus(errors.New("entropy")), codes.Internal, "internal error")
	if _, err := (*secretbox.Box)(nil).Seal([]byte("x"), "p"); !errors.Is(err, secretbox.ErrNoKey) {
		t.Fatalf("nil box = %v", err)
	}
}

// A call refused before it is authorized writes no outcome row, and does not panic.
func TestFinishWithoutAnAct(t *testing.T) {
	f := newForge(t)
	before, _ := f.st.AuditCount(t.Context())
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("finish panicked: %v", r)
		}
	}()
	f.adm.Finish(t.Context(), errors.New("refused"))
	if after, _ := f.st.AuditCount(t.Context()); after != before {
		t.Fatalf("audit rows %d -> %d", before, after)
	}
}
