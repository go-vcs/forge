// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/adminauth"
	"github.com/go-vcs/forge/internal/store"
)

var epoch = time.Unix(1_800_000_000, 0).UTC()

func open(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.Context(), ":memory:", func() time.Time { return epoch })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func key(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

func TestMigrationsIdempotentAndPersistent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "forge.db")
	s, err := store.Open(ctx, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := store.SchemaVersion()
	if err != nil || want < 1 {
		t.Fatalf("schema version %d %v", want, err)
	}
	if v, _ := s.Version(ctx); v != want {
		t.Fatalf("version %d, want %d", v, want)
	}
	if _, err := s.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = store.Open(ctx, path, nil) // second open must not re-run or lose data
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	us, err := s.ListUsers(ctx)
	if err != nil || len(us) != 1 || us[0].Login != "alice" {
		t.Fatalf("users %v %v", us, err)
	}
}

func TestFutureSchemaRefused(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "forge.db")
	s, err := store.Open(ctx, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (999, 0)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := store.Open(ctx, path, nil); !errors.Is(err, store.ErrFutureSchema) {
		t.Fatalf("got %v", err)
	}
}

func TestOpenBadPath(t *testing.T) {
	if _, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "no", "such", "dir", "x.db"), nil); err == nil {
		t.Fatal("opened a database in a missing directory")
	}
}

func TestCredentialLifecycle(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	pub := key(t)
	c, err := s.AddCredential(ctx, []byte("id1"), pub, "aaguid", "yubikey")
	if err != nil || c.Name != "yubikey" || !c.CreatedAt.Equal(epoch) {
		t.Fatalf("add: %+v %v", c, err)
	}
	if _, err := s.AddCredential(ctx, []byte("id1"), key(t), "a", "dup"); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	got, err := s.ActiveCredential(ctx, []byte("id1"))
	if err != nil || !got.PublicKey.Equal(pub) || got.AAGUID != "aaguid" || got.Name != "yubikey" || got.SignCount != 0 {
		t.Fatalf("active: %+v %v", got, err)
	}
	if n, _ := s.ActiveCredentialCount(ctx); n != 1 {
		t.Fatalf("count %d", n)
	}
	if _, err := s.ActiveCredential(ctx, []byte("nope")); !errors.Is(err, adminauth.ErrUnknownCredential) {
		t.Fatalf("unknown: %v", err)
	}

	if err := s.RevokeCredential(ctx, []byte("id1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveCredential(ctx, []byte("id1")); !errors.Is(err, adminauth.ErrUnknownCredential) {
		t.Fatalf("revoked credential still active: %v", err)
	}
	if err := s.RevokeCredential(ctx, []byte("id1")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	if err := s.RevokeCredential(ctx, []byte("zzz")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
	if n, _ := s.ActiveCredentialCount(ctx); n != 0 {
		t.Fatalf("count after revoke %d", n)
	}
	list, err := s.ListCredentials(ctx)
	if err != nil || len(list) != 1 || list[0].RevokedAt.IsZero() || !list[0].RevokedAt.Equal(epoch) {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := s.AdvanceCounter(ctx, []byte("id1"), 5); !errors.Is(err, adminauth.ErrCounterRegression) {
		t.Fatalf("counter on revoked credential: %v", err)
	}
}

func TestCredentialValidation(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	pub := key(t)
	if _, err := s.AddCredential(ctx, []byte("x"), pub, "a", ""); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("empty name: %v", err)
	}
	if _, err := s.AddCredential(ctx, []byte("x"), pub, "a", strings.Repeat("n", store.MaxNameLen+1)); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("long name: %v", err)
	}
	if _, err := s.AddCredential(ctx, []byte("x"), pub, "a", "bad\x00name"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("control char: %v", err)
	}
	if _, err := s.AddCredential(ctx, []byte("x"), pub, "a", "bad\xffname"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("invalid utf-8: %v", err)
	}
	if _, err := s.AddCredential(ctx, []byte("x"), nil, "a", "n"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("nil key: %v", err)
	}
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := s.AddCredential(ctx, []byte("x"), &k384.PublicKey, "a", "n"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("P-384 key: %v", err)
	}
	if _, err := s.AddCredential(ctx, nil, pub, "a", "n"); err == nil {
		t.Fatal("empty credential id accepted")
	}
	if _, err := s.AddCredential(ctx, make([]byte, 1025), pub, "a", "n"); err == nil {
		t.Fatal("oversized credential id accepted")
	}
}

func TestCounter(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	id := []byte("c")
	if _, err := s.AddCredential(ctx, id, key(t), "a", "n"); err != nil {
		t.Fatal(err)
	}
	// A counter that never moves (stays 0) is allowed.
	for range 2 {
		if err := s.AdvanceCounter(ctx, id, 0); err != nil {
			t.Fatalf("zero while zero: %v", err)
		}
	}
	steps := []struct {
		n  uint32
		ok bool
	}{{5, true}, {5, true}, {6, true}, {4, false}, {0, false}, {6, true}, {4294967295, true}, {1, false}}
	for _, st := range steps {
		err := s.AdvanceCounter(ctx, id, st.n)
		if st.ok && err != nil {
			t.Fatalf("%d: %v", st.n, err)
		}
		if !st.ok && !errors.Is(err, adminauth.ErrCounterRegression) {
			t.Fatalf("%d: got %v, want regression", st.n, err)
		}
	}
	c, err := s.ActiveCredential(ctx, id)
	if err != nil || c.SignCount != 4294967295 {
		t.Fatalf("stored counter %d %v", c.SignCount, err)
	}
	if err := s.AdvanceCounter(ctx, []byte("other"), 1); !errors.Is(err, adminauth.ErrCounterRegression) {
		t.Fatalf("unknown credential: %v", err)
	}
}

func TestUsers(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	u, err := s.CreateUser(ctx, "alice", "Alice A.")
	if err != nil || u.Login != "alice" || u.DisplayName != "Alice A." || !u.DisabledAt.IsZero() {
		t.Fatalf("create: %+v %v", u, err)
	}
	if _, err := s.CreateUser(ctx, "alice", "again"); !errors.Is(err, store.ErrExists) {
		t.Fatalf("dup: %v", err)
	}
	if _, err := s.CreateUser(ctx, "bob", ""); err != nil { // empty display name is allowed
		t.Fatal(err)
	}
	for _, bad := range []string{"", "Alice", "a@b.example", "-lead", "has space", "x_y", strings.Repeat("a", 40), "é"} {
		if _, err := s.CreateUser(ctx, bad, "x"); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("login %q: %v", bad, err)
		}
		if err := store.ValidLogin(bad); err == nil {
			t.Fatalf("ValidLogin(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"a", "0", "a-b", strings.Repeat("a", 39)} {
		if err := store.ValidLogin(ok); err != nil {
			t.Fatalf("ValidLogin(%q): %v", ok, err)
		}
	}
	if _, err := s.CreateUser(ctx, "carol", strings.Repeat("d", store.MaxDisplayNameLen+1)); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("long display: %v", err)
	}
	if err := s.DisableUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableUser(ctx, "bob"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("disable twice: %v", err)
	}
	if err := s.DisableUser(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("disable unknown: %v", err)
	}
	us, err := s.ListUsers(ctx)
	if err != nil || len(us) != 2 || us[0].Login != "alice" || us[1].Login != "bob" || !us[0].DisabledAt.IsZero() || us[1].DisabledAt.IsZero() {
		t.Fatalf("list: %+v %v", us, err)
	}
}

const issuer = "https://accounts.example"

func TestIdentities(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	for _, l := range []string{"alice", "bob"} {
		if _, err := s.CreateUser(ctx, l, l); err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.BindIdentity(ctx, issuer, "sub-1", "alice")
	if err != nil || id.Login != "alice" || id.Issuer != issuer || id.Subject != "sub-1" {
		t.Fatalf("bind: %+v %v", id, err)
	}
	// The same pair, to anyone, is refused; the same subject at another issuer is a different identity.
	if _, err := s.BindIdentity(ctx, issuer, "sub-1", "bob"); !errors.Is(err, store.ErrExists) {
		t.Fatalf("rebind: %v", err)
	}
	if _, err := s.BindIdentity(ctx, "https://other.example", "sub-1", "bob"); err != nil {
		t.Fatalf("other issuer: %v", err)
	}
	if _, err := s.BindIdentity(ctx, issuer, "sub-2", "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	if err := s.DisableUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindIdentity(ctx, issuer, "sub-3", "bob"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("disabled user: %v", err)
	}
	// An e-mail address is neither an issuer, a subject-as-login nor a login.
	if _, err := s.BindIdentity(ctx, issuer, "sub-4", "alice@example.org"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("e-mail as login: %v", err)
	}
	if _, err := s.BindIdentity(ctx, "alice@example.org", "x", "alice"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("e-mail as issuer: %v", err)
	}
	all, err := s.ListIdentities(ctx, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("list all: %+v %v", all, err)
	}
	mine, err := s.ListIdentities(ctx, "alice")
	if err != nil || len(mine) != 1 || mine[0].Subject != "sub-1" {
		t.Fatalf("list alice: %+v %v", mine, err)
	}
	if err := s.UnbindIdentity(ctx, issuer, "sub-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.UnbindIdentity(ctx, issuer, "sub-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unbind twice: %v", err)
	}
	if _, err := s.BindIdentity(ctx, issuer, "sub-1", "alice"); err != nil { // unbind then bind is the rebinding path
		t.Fatalf("bind after unbind: %v", err)
	}
}

func TestIdentityValidation(t *testing.T) {
	bad := []string{"", "http://x.example", "https://", "ftp://x", "https://u:p@x.example", "https://x.example?q=1", "https://x.example#f", "https://x .example", "https://x.example/\x00", strings.Repeat("https://x", 100)}
	for _, b := range bad {
		if err := store.ValidIssuer(b); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("issuer %q: %v", b, err)
		}
	}
	for _, g := range []string{"https://accounts.example", "https://accounts.example/realms/x"} {
		if err := store.ValidIssuer(g); err != nil {
			t.Fatalf("issuer %q: %v", g, err)
		}
	}
	for _, b := range []string{"", strings.Repeat("s", store.MaxSubjectLen+1), "a\nb"} {
		if err := store.ValidSubject(b); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("subject %q: %v", b, err)
		}
	}
	if err := store.ValidSubject(strings.Repeat("s", store.MaxSubjectLen)); err != nil {
		t.Fatal(err)
	}
}

func TestAudit(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	if n, _ := s.AuditCount(ctx); n != 0 {
		t.Fatal(n)
	}
	for _, o := range []string{store.OutcomeAttempt, store.OutcomeSuccess, store.OutcomeFailure} {
		if err := s.Audit(ctx, []byte("c"), "/m", make([]byte, 32), o); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.AuditCount(ctx); err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
	rows, err := s.AuditRows(ctx)
	if err != nil || len(rows) != 3 {
		t.Fatalf("%v %v", rows, err)
	}
	for i, want := range []string{"attempt", "success", "failure"} {
		r := rows[i]
		if r.Outcome != want || r.Method != "/m" || string(r.CredentialID) != "c" || !r.At.Equal(epoch) {
			t.Fatalf("row %d = %+v, want outcome %q", i, r, want)
		}
	}
	if err := s.Audit(ctx, []byte("c"), "/m", make([]byte, 32), "done"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("an unknown outcome was recorded: %v", err)
	}
	if n, _ := s.AuditCount(ctx); n != 3 {
		t.Fatalf("a refused outcome left a row: %d", n)
	}
}

func TestListBounded(t *testing.T) {
	ctx := t.Context()
	s := open(t)
	for i := range store.MaxList + 5 {
		if _, err := s.CreateUser(ctx, fmt.Sprintf("u%04d", i), ""); err != nil {
			t.Fatal(err)
		}
	}
	us, err := s.ListUsers(ctx)
	if err != nil || len(us) != store.MaxList {
		t.Fatalf("list returned %d, want %d (%v)", len(us), store.MaxList, err)
	}
}
