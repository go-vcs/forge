// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"errors"
	"io/fs"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-vcs/forge/internal/store"
)

// wantErr fails unless err is non-nil and says want: a guard is held by the
// error it returns, not by the fact that something failed.
func wantErr(t *testing.T, name string, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: no error, want one saying %q", name, want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: error %q does not say %q", name, err, want)
	}
}

// rawExec runs SQL on a database file behind the store's back.
func rawExec(t *testing.T, path, stmts string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(stmts); err != nil {
		t.Fatalf("%s: %v", stmts, err)
	}
}

// damaged returns a store on a migrated file database after stmts ran on it.
func damaged(t *testing.T, stmts string) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "forge.db")
	s, err := store.Open(t.Context(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	rawExec(t, path, stmts)
	s, err = store.Open(t.Context(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// failOpen is a file system whose .sql files cannot be opened.
type failOpen struct{ fs.FS }

func (f failOpen) Open(name string) (fs.File, error) {
	if strings.HasSuffix(name, ".sql") {
		return nil, errors.New("unreadable migration")
	}
	return f.FS.Open(name)
}

func mig(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for n, c := range files {
		m["migrations/"+n] = &fstest.MapFile{Data: []byte(c)}
	}
	return m
}

func TestAMigrationSetThatIsNotUsableIsRefused(t *testing.T) {
	cases := []struct {
		name, want string
		fsys       fs.FS
	}{
		{"no directory", "migrations", fstest.MapFS{}},
		{"no number", "not NNNN_name.sql", mig(map[string]string{"abc_x.sql": "SELECT 1;"})},
		{"no underscore", "not NNNN_name.sql", mig(map[string]string{"7": "SELECT 1;"})},
		{"a gap", "without gaps", mig(map[string]string{"0002_a.sql": "SELECT 1;"})},
		{"unreadable file", "unreadable migration", failOpen{mig(map[string]string{"0001_a.sql": "SELECT 1;"})}},
		{"bad SQL", "migration 1", mig(map[string]string{"0001_a.sql": "NOT SQL AT ALL;"})},
		{"a migration that removes the ledger", "schema_migrations", mig(map[string]string{"0001_a.sql": "DROP TABLE schema_migrations;"})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer store.UseMigrations(c.fsys)()
			_, err := store.Open(t.Context(), ":memory:", nil)
			wantErr(t, "Open", err, c.want)
			if c.name == "bad SQL" || strings.HasPrefix(c.name, "a migration") {
				return // these reach the database: SchemaVersion does not
			}
			_, err = store.SchemaVersion()
			wantErr(t, "SchemaVersion", err, c.want)
		})
	}
}

func TestOpenRefusesAnUnknownDriver(t *testing.T) {
	defer store.UseDriver("no-such-driver")()
	_, err := store.Open(t.Context(), ":memory:", nil)
	wantErr(t, "Open", err, "unknown driver")
}

func TestMigrateReportsWhatTheLedgerGot(t *testing.T) {
	t.Run("an index takes the ledger's name", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "forge.db")
		rawExec(t, path, `CREATE TABLE t(a); CREATE INDEX schema_migrations ON t(a);`)
		_, err := store.Open(t.Context(), path, nil)
		wantErr(t, "Open", err, "already an index")
	})
	t.Run("a ledger without a version column", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "forge.db")
		rawExec(t, path, `CREATE TABLE schema_migrations(x);`)
		_, err := store.Open(t.Context(), path, nil)
		wantErr(t, "Open", err, "no such column: version")
	})
}

func TestEveryOperationReportsAClosedDatabase(t *testing.T) {
	s, err := store.Open(t.Context(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	ctx := t.Context()
	k := key(t)
	ops := map[string]func() error{
		"Version":                func() error { _, e := s.Version(ctx); return e },
		"AddCredential":          func() error { _, e := s.AddCredential(ctx, []byte{1}, k, "a", "n"); return e },
		"ActiveCredential":       func() error { _, e := s.ActiveCredential(ctx, []byte{1}); return e },
		"AdvanceCounter":         func() error { return s.AdvanceCounter(ctx, []byte{1}, 1) },
		"ListCredentials":        func() error { _, e := s.ListCredentials(ctx); return e },
		"RevokeCredential":       func() error { return s.RevokeCredential(ctx, []byte{1}) },
		"ActiveCredentialCount":  func() error { _, e := s.ActiveCredentialCount(ctx); return e },
		"CreateUser":             func() error { _, e := s.CreateUser(ctx, "alice", "Alice"); return e },
		"ListUsers":              func() error { _, e := s.ListUsers(ctx); return e },
		"DisableUser":            func() error { return s.DisableUser(ctx, "alice") },
		"BindIdentity":           func() error { _, e := s.BindIdentity(ctx, "https://i.example", "sub", "alice"); return e },
		"ListIdentities":         func() error { _, e := s.ListIdentities(ctx, ""); return e },
		"ListIdentities (login)": func() error { _, e := s.ListIdentities(ctx, "alice"); return e },
		"UnbindIdentity":         func() error { return s.UnbindIdentity(ctx, "https://i.example", "sub") },
		"Audit":                  func() error { return s.Audit(ctx, []byte{1}, "m", []byte{2}, store.OutcomeAttempt) },
		"AuditRows":              func() error { _, e := s.AuditRows(ctx); return e },
	}
	for name, op := range ops {
		wantErr(t, name, op(), "database is closed")
	}
}

func TestAddCredentialRefusesKeysThatAreNotP256Points(t *testing.T) {
	s := open(t)
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]*ecdsa.PublicKey{
		"nil":           nil,
		"another curve": &other.PublicKey,
		"off the curve": {Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)},
	} {
		if _, err := s.AddCredential(t.Context(), []byte{1}, k, "a", "n"); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("%s: got %v, want ErrInvalid", name, err)
		}
	}
	if n, _ := s.ActiveCredentialCount(t.Context()); n != 0 {
		t.Fatalf("%d credentials stored", n)
	}
}

func TestBindIdentityRefusesAnInvalidSubjectBeforeLookingForTheUser(t *testing.T) {
	s := open(t)
	if _, err := s.BindIdentity(t.Context(), "https://i.example", "", "alice"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestAStoredKeyThatIsNotAPointIsReportedNotTrusted(t *testing.T) {
	s := damaged(t, `INSERT INTO admin_credentials(credential_id, public_key, aaguid, name, created_at) VALUES (x'01', zeroblob(65), 'a', 'n', 0)`)
	_, err := s.ActiveCredential(t.Context(), []byte{1})
	wantErr(t, "ActiveCredential", err, "stored public key")
}

func TestARowThatCannotBeReadIsAnErrorNotASilentGap(t *testing.T) {
	t.Run("credentials", func(t *testing.T) {
		s := damaged(t, `DROP TABLE admin_credentials;
CREATE TABLE admin_credentials(id INTEGER PRIMARY KEY, credential_id BLOB, public_key BLOB, aaguid TEXT, name TEXT, sign_count INTEGER, created_at INTEGER, revoked_at INTEGER);
INSERT INTO admin_credentials(credential_id, public_key, aaguid, name, sign_count, created_at) VALUES (x'01', zeroblob(65), 'a', NULL, 0, 0);`)
		_, err := s.ListCredentials(t.Context())
		wantErr(t, "ListCredentials", err, "NULL")
		_, err = s.ActiveCredential(t.Context(), []byte{1})
		wantErr(t, "ActiveCredential", err, "NULL")
	})
	t.Run("users", func(t *testing.T) {
		s := damaged(t, `DROP TABLE identities; DROP TABLE users;
CREATE TABLE users(id INTEGER PRIMARY KEY, login TEXT, display_name TEXT, created_at INTEGER, disabled_at INTEGER);
INSERT INTO users(login, display_name, created_at) VALUES ('alice', NULL, 0);`)
		_, err := s.ListUsers(t.Context())
		wantErr(t, "ListUsers", err, "NULL")
	})
	t.Run("identities", func(t *testing.T) {
		s := damaged(t, `DROP TABLE identities;
CREATE TABLE identities(issuer TEXT, subject TEXT, user_id INTEGER, created_at INTEGER);
INSERT INTO users(login, display_name, created_at) VALUES ('alice', 'A', 0);
INSERT INTO identities(issuer, subject, user_id, created_at) VALUES ('https://i.example', NULL, 1, 0);`)
		_, err := s.ListIdentities(t.Context(), "")
		wantErr(t, "ListIdentities", err, "NULL")
	})
	t.Run("audit", func(t *testing.T) {
		s := damaged(t, `DROP TABLE admin_audit;
CREATE TABLE admin_audit(id INTEGER PRIMARY KEY, at INTEGER, credential_id BLOB, method TEXT, request_sha256 BLOB, outcome TEXT);
INSERT INTO admin_audit(at, method, outcome) VALUES (0, NULL, 'attempt');`)
		_, err := s.AuditRows(t.Context())
		wantErr(t, "AuditRows", err, "NULL")
	})
}

func TestBindIdentityReportsAFailedUserLookup(t *testing.T) {
	s := damaged(t, `DROP TABLE identities; DROP TABLE users;
CREATE TABLE users(id INTEGER PRIMARY KEY, login TEXT);
CREATE TABLE identities(issuer TEXT, subject TEXT, user_id INTEGER, created_at INTEGER);`)
	_, err := s.BindIdentity(t.Context(), "https://i.example", "sub", "alice")
	wantErr(t, "BindIdentity", err, "no such column")
}

func TestBindIdentityReportsAFailedInsert(t *testing.T) {
	s := damaged(t, `INSERT INTO users(login, display_name, created_at) VALUES ('alice', 'A', 0); DROP TABLE identities;`)
	_, err := s.BindIdentity(t.Context(), "https://i.example", "sub", "alice")
	wantErr(t, "BindIdentity", err, "no such table")
}
