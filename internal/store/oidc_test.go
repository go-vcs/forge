// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-vcs/forge/internal/store"
)

func TestOIDCClientRoundTrip(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	if _, err := s.GetOIDCClient(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unset = %v", err)
	}
	c := store.OIDCClient{Issuer: "https://i.example", ClientID: "a", RedirectURI: "https://f.example/cb", SecretSealed: []byte{1, 2}}
	if err := s.SetOIDCClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	c2 := store.OIDCClient{Issuer: "https://j.example", ClientID: "b", RedirectURI: "http://127.0.0.1:8080/cb"}
	if err := s.SetOIDCClient(ctx, c2); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetOIDCClient(ctx)
	if err != nil || got.ClientID != "b" || got.Issuer != "https://j.example" || got.SecretSealed != nil || !got.UpdatedAt.Equal(epoch) {
		t.Fatalf("got %+v %v (a second set replaces the first, secret included)", got, err)
	}
	for _, bad := range []store.OIDCClient{
		{Issuer: "http://i", ClientID: "a", RedirectURI: "https://f/cb"},
		{Issuer: "https://i", ClientID: "", RedirectURI: "https://f/cb"},
		{Issuer: "https://i", ClientID: "a", RedirectURI: ""},
		{Issuer: "https://i", ClientID: "a", RedirectURI: "http://f.example/cb"},
		{Issuer: "https://i", ClientID: "a", RedirectURI: "https://f.example/cb#x"},
		{Issuer: "https://i", ClientID: "a", RedirectURI: "https://u@f.example/cb"},
		{Issuer: "https://i", ClientID: "a", RedirectURI: "/cb"},
		{Issuer: "https://i", ClientID: "a", RedirectURI: "https:opaque"},
	} {
		if err := s.SetOIDCClient(ctx, bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%+v accepted: %v", bad, err)
		}
	}
}

// A sign-in never creates an account and is never matched by anything but
// (issuer, subject).
func TestLoginForIdentity(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	if _, err := s.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatal(err)
	}
	const iss = "https://i.example"
	if _, err := s.LoginForIdentity(ctx, iss, "sub-1"); !errors.Is(err, store.ErrNotAuthorized) {
		t.Fatalf("unbound = %v", err)
	}
	if _, err := s.BindIdentity(ctx, iss, "sub-1", "alice"); err != nil {
		t.Fatal(err)
	}
	if l, err := s.LoginForIdentity(ctx, iss, "sub-1"); err != nil || l != "alice" {
		t.Fatalf("bound = %q %v", l, err)
	}
	// same subject at another issuer, another subject at this one: not bound
	if _, err := s.LoginForIdentity(ctx, "https://other.example", "sub-1"); !errors.Is(err, store.ErrNotAuthorized) {
		t.Fatalf("other issuer = %v", err)
	}
	if _, err := s.LoginForIdentity(ctx, iss, "alice"); !errors.Is(err, store.ErrNotAuthorized) {
		t.Fatalf("login as subject = %v", err)
	}
	if err := s.DisableUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoginForIdentity(ctx, iss, "sub-1"); !errors.Is(err, store.ErrNotAuthorized) {
		t.Fatalf("disabled = %v", err)
	}
	n, err := s.ListUsers(ctx)
	if err != nil || len(n) != 1 {
		t.Fatalf("accounts after sign-in attempts: %v %v", n, err)
	}
}

func TestOIDCStatementsFail(t *testing.T) {
	ctx := t.Context()
	s, _ := withKey(t, `DROP TABLE oidc_client`)
	if _, err := s.GetOIDCClient(ctx); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get on a missing table = %v", err)
	}
	if err := s.SetOIDCClient(ctx, store.OIDCClient{Issuer: "https://i", ClientID: "a", RedirectURI: "https://f.example/cb"}); err == nil {
		t.Fatal("Set on a missing table succeeded")
	}
	s, _ = withKey(t, `DROP TABLE identities`)
	if _, err := s.LoginForIdentity(ctx, "https://i", "s"); err == nil || errors.Is(err, store.ErrNotAuthorized) {
		t.Fatalf("LoginForIdentity on a missing table = %v: a storage failure must not read as a refusal", err)
	}
}

func TestOIDCRedirectURILength(t *testing.T) {
	s := open(t)
	long := "https://f.example/" + strings.Repeat("a", store.MaxRedirectURILen)
	if err := s.SetOIDCClient(t.Context(), store.OIDCClient{Issuer: "https://i", ClientID: "a", RedirectURI: long}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("long redirect URI = %v", err)
	}
}
