// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store_test

import (
	"errors"
	"path/filepath"
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

// withKey returns a store on a file database holding alice and one key, after
// stmts ran on it behind the store's back.
func withKey(t *testing.T, stmts string) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "forge.db")
	s, err := store.Open(t.Context(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(t.Context(), "alice", ""); err != nil {
		t.Fatal(err)
	}
	k := sshtest.NewEd25519(t)
	if _, err := s.AddSSHKey(t.Context(), "alice", k.Line); err != nil {
		t.Fatal(err)
	}
	s.Close()
	rawExec(t, path, stmts)
	s, err = store.Open(t.Context(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, k.Fingerprint
}

// Each statement of the key store has its own failure path: a table that is
// gone, or a row that cannot be read, is an error naming the cause, never a
// success and never a refusal that looks like a policy decision.
func TestSSHKeyStatementsFailOneByOne(t *testing.T) {
	ctx := t.Context()
	fresh := sshtest.NewEd25519(t).Line
	t.Run("policy unreadable on add", func(t *testing.T) {
		s := damaged(t, `DROP TABLE settings`)
		if _, err := s.CreateUser(ctx, "alice", ""); err != nil {
			t.Fatal(err)
		}
		_, err := s.AddSSHKey(ctx, "alice", fresh)
		wantErr(t, "AddSSHKey", err, "settings")
	})
	t.Run("user lookup fails on add", func(t *testing.T) {
		s := damaged(t, `DROP TABLE users`)
		_, err := s.AddSSHKey(ctx, "alice", fresh)
		wantErr(t, "AddSSHKey", err, "no such table: users")
	})
	t.Run("insert fails on add", func(t *testing.T) {
		s := damaged(t, `DROP TABLE ssh_keys`)
		if _, err := s.CreateUser(ctx, "alice", ""); err != nil {
			t.Fatal(err)
		}
		_, err := s.AddSSHKey(ctx, "alice", fresh)
		wantErr(t, "AddSSHKey", err, "ssh_keys")
	})
	t.Run("unreadable row", func(t *testing.T) {
		s, _ := withKey(t, `CREATE TABLE k2(id INTEGER PRIMARY KEY, user_id, fingerprint, key_type, blob, comment, created_at);
			INSERT INTO k2 SELECT id, user_id, fingerprint, key_type, blob, comment, 'yesterday' FROM ssh_keys;
			DROP TABLE ssh_keys; ALTER TABLE k2 RENAME TO ssh_keys;`)
		_, err := s.ListSSHKeys(ctx, "")
		wantErr(t, "ListSSHKeys", err, "Scan")
	})
	t.Run("stored blob is not a key", func(t *testing.T) {
		s, _ := withKey(t, `UPDATE ssh_keys SET blob = x'00'`)
		_, err := s.ListSSHKeys(ctx, "")
		wantErr(t, "ListSSHKeys", err, "invalid ssh public key")
	})
	t.Run("lookup fails on authenticate", func(t *testing.T) {
		s := damaged(t, `DROP TABLE ssh_keys`)
		_, err := s.AuthenticateSSHKey(ctx, "SHA256:x")
		wantErr(t, "AuthenticateSSHKey", err, "ssh_keys")
		if errors.Is(err, store.ErrNotAuthorized) {
			t.Fatal("a storage failure must not read as a refusal")
		}
	})
	t.Run("policy unreadable on authenticate", func(t *testing.T) {
		s, fp := withKey(t, `DROP TABLE settings`)
		_, err := s.AuthenticateSSHKey(ctx, fp)
		wantErr(t, "AuthenticateSSHKey", err, "settings")
		if errors.Is(err, store.ErrNotAuthorized) {
			t.Fatal("a storage failure must not read as a refusal")
		}
	})
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
