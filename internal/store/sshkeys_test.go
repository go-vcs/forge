// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store_test

import (
	"errors"
	"testing"

	"github.com/go-vcs/forge/internal/sshtest"
	"github.com/go-vcs/forge/internal/store"
)

func TestSSHKeyLifecycle(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	if _, err := s.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "bob", "Bob"); err != nil {
		t.Fatal(err)
	}
	k := sshtest.NewEd25519(t)
	got, err := s.AddSSHKey(ctx, "alice", k.Line+" laptop")
	if err != nil || got.Key.Fingerprint != k.Fingerprint || got.Login != "alice" || !got.CreatedAt.Equal(epoch) {
		t.Fatalf("AddSSHKey = %+v, %v", got, err)
	}
	// A key belongs to one account: a second registration is refused, for the
	// same user or another.
	for _, login := range []string{"alice", "bob"} {
		if _, err := s.AddSSHKey(ctx, login, k.Line); !errors.Is(err, store.ErrExists) {
			t.Fatalf("second registration for %s = %v, want ErrExists", login, err)
		}
	}
	if _, err := s.AddSSHKey(ctx, "ghost", sshtest.NewEd25519(t).Line); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown user = %v", err)
	}
	if _, err := s.AddSSHKey(ctx, "Bad Login", k.Line); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad login = %v", err)
	}
	if _, err := s.AddSSHKey(ctx, "bob", `command="x" `+k.Line); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("options accepted: %v", err)
	}

	all, err := s.ListSSHKeys(ctx, "")
	if err != nil || len(all) != 1 || all[0].Key.Comment != "laptop" {
		t.Fatalf("ListSSHKeys = %+v, %v", all, err)
	}
	if bobs, err := s.ListSSHKeys(ctx, "bob"); err != nil || len(bobs) != 0 {
		t.Fatalf("bob's keys = %+v, %v", bobs, err)
	}

	if login, err := s.AuthenticateSSHKey(ctx, k.Fingerprint); err != nil || login != "alice" {
		t.Fatalf("AuthenticateSSHKey = %q, %v", login, err)
	}
	if _, err := s.AuthenticateSSHKey(ctx, "SHA256:nope"); !errors.Is(err, store.ErrNotAuthorized) {
		t.Fatalf("unknown key = %v", err)
	}
	// A disabled account's key no longer authenticates.
	if err := s.DisableUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateSSHKey(ctx, k.Fingerprint); !errors.Is(err, store.ErrNotAuthorized) {
		t.Fatalf("disabled account's key = %v", err)
	}
	if _, err := s.AddSSHKey(ctx, "alice", sshtest.NewEd25519(t).Line); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("key added for a disabled account: %v", err)
	}

	if err := s.RemoveSSHKey(ctx, k.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveSSHKey(ctx, k.Fingerprint); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("remove twice = %v", err)
	}
}

func TestPolicyRequireSKKeys(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	if _, err := s.CreateUser(ctx, "alice", ""); err != nil {
		t.Fatal(err)
	}
	if p, err := s.GetPolicy(ctx); err != nil || p.RequireSKKeys {
		t.Fatalf("default policy = %+v, %v", p, err)
	}
	plain := sshtest.NewEd25519(t)
	if _, err := s.AddSSHKey(ctx, "alice", plain.Line); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPolicy(ctx, store.Policy{RequireSKKeys: true}); err != nil {
		t.Fatal(err)
	}
	if p, err := s.GetPolicy(ctx); err != nil || !p.RequireSKKeys {
		t.Fatalf("policy after set = %+v, %v", p, err)
	}
	// The policy refuses new plain keys, and stops the old one authenticating,
	// without deleting it.
	if _, err := s.AddSSHKey(ctx, "alice", sshtest.NewEd25519(t).Line); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("plain key under the policy = %v", err)
	}
	if _, err := s.AuthenticateSSHKey(ctx, plain.Fingerprint); !errors.Is(err, store.ErrNotAuthorized) {
		t.Fatalf("plain key authenticated under the policy: %v", err)
	}
	sk, err := s.AddSSHKey(ctx, "alice", sshtest.SKLine(t))
	if err != nil || !sk.Key.SecurityKey {
		t.Fatalf("sk key refused under the policy: %+v %v", sk, err)
	}
	if login, err := s.AuthenticateSSHKey(ctx, sk.Key.Fingerprint); err != nil || login != "alice" {
		t.Fatalf("sk key = %q %v", login, err)
	}
	// Relaxing the policy brings the plain key back.
	if err := s.SetPolicy(ctx, store.Policy{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateSSHKey(ctx, plain.Fingerprint); err != nil {
		t.Fatalf("plain key after relaxing = %v", err)
	}
	if ks, _ := s.ListSSHKeys(ctx, "alice"); len(ks) != 2 {
		t.Fatalf("%d keys, want 2", len(ks))
	}
}

func TestSSHKeyStoreFailures(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	if _, err := s.CreateUser(ctx, "alice", ""); err != nil {
		t.Fatal(err)
	}
	line := sshtest.NewEd25519(t).Line
	s.Close() // every statement now fails
	wantErr(t, "GetPolicy", func() error { _, e := s.GetPolicy(ctx); return e }(), "closed")
	wantErr(t, "SetPolicy", s.SetPolicy(ctx, store.Policy{}), "closed")
	wantErr(t, "AddSSHKey", func() error { _, e := s.AddSSHKey(ctx, "alice", line); return e }(), "closed")
	wantErr(t, "ListSSHKeys", func() error { _, e := s.ListSSHKeys(ctx, ""); return e }(), "closed")
	wantErr(t, "RemoveSSHKey", s.RemoveSSHKey(ctx, "SHA256:x"), "closed")
	wantErr(t, "AuthenticateSSHKey", func() error { _, e := s.AuthenticateSSHKey(ctx, "SHA256:x"); return e }(), "closed")
}
