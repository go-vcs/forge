// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package store is the forge's SQLite storage (pure Go, no cgo), with schema
// migrations.
package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-vcs/forge/internal/adminauth"
	_ "modernc.org/sqlite" // the driver
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// migrationFS and driverName are variables so that a test can make the paths
// that cannot fail with the real ones (a broken migration set, an unknown
// driver) fail.
var (
	migrationFS fs.FS = embeddedMigrations
	driverName        = "sqlite"
)

// Errors the store returns.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrInvalid  = errors.New("invalid argument")
	// ErrFutureSchema means the database was written by a newer forge.
	ErrFutureSchema = errors.New("database schema is newer than this program")
)

// Limits on stored text.
const (
	MaxNameLen        = 64
	MaxDisplayNameLen = 128
	MaxIssuerLen      = 512
	MaxSubjectLen     = 255
	MaxList           = 1000
)

// Store is the database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// SchemaVersion is the number of the newest migration this program knows.
func SchemaVersion() (int, error) {
	ms, err := migrations()
	if err != nil {
		return 0, err
	}
	return ms[len(ms)-1].version, nil
}

type migration struct {
	version int
	sql     string
}

func migrations() ([]migration, error) {
	ents, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range ents {
		name := e.Name()
		num, _, ok := strings.Cut(name, "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil {
			return nil, fmt.Errorf("store: migration file %q is not NNNN_name.sql", name)
		}
		b, err := fs.ReadFile(migrationFS, "migrations/"+name)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{v, string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("store: migrations are not numbered 1..n without gaps (found %d at position %d)", m.version, i+1)
		}
	}
	return out, nil
}

// Open opens (creating it if needed) the database at path and migrates it.
// A path of ":memory:" gives a private in-memory database.
func Open(ctx context.Context, path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	if path == ":memory:" {
		dsn = "file::memory:?_pragma=foreign_keys(1)&_txlock=immediate"
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	// One connection: serialises writers, and keeps :memory: one database.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: now}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	ms, err := migrations()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL) STRICT`); err != nil {
		return err
	}
	var have sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&have); err != nil {
		return err
	}
	if int(have.Int64) > len(ms) {
		return fmt.Errorf("%w: database at %d, program at %d", ErrFutureSchema, have.Int64, len(ms))
	}
	for _, m := range ms[have.Int64:] {
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("store: migration %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, m.version, s.now().Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Version returns the schema version of the open database.
func (s *Store) Version(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&v)
	return v, err
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func ts(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.Unix(v.Int64, 0).UTC()
}

// ---- admin credentials ----

// AdminCredential is a stored admin credential.
type AdminCredential struct {
	ID        []byte
	Name      string
	AAGUID    string
	SignCount uint32
	CreatedAt time.Time
	RevokedAt time.Time // zero while active
}

// AddCredential stores a newly enrolled credential.
func (s *Store) AddCredential(ctx context.Context, id []byte, pub *ecdsa.PublicKey, aaguid, name string) (AdminCredential, error) {
	if err := ValidName(name); err != nil {
		return AdminCredential{}, err
	}
	if pub == nil || pub.Curve != elliptic.P256() {
		return AdminCredential{}, fmt.Errorf("%w: public key", ErrInvalid)
	}
	raw, err := pub.Bytes()
	if err != nil {
		return AdminCredential{}, fmt.Errorf("%w: public key", ErrInvalid)
	}
	now := s.now().Unix()
	_, err = s.db.ExecContext(ctx, `INSERT INTO admin_credentials(credential_id, public_key, aaguid, name, created_at) VALUES (?,?,?,?,?)`,
		id, raw, aaguid, name, now)
	if isUnique(err) {
		return AdminCredential{}, ErrExists
	}
	if err != nil {
		return AdminCredential{}, err
	}
	return AdminCredential{ID: id, Name: name, AAGUID: aaguid, CreatedAt: time.Unix(now, 0).UTC()}, nil
}

// ActiveCredential implements [adminauth.Credentials].
func (s *Store) ActiveCredential(ctx context.Context, id []byte) (adminauth.Credential, error) {
	var raw []byte
	c := adminauth.Credential{ID: id}
	var sc int64
	err := s.db.QueryRowContext(ctx, `SELECT public_key, sign_count, aaguid, name FROM admin_credentials WHERE credential_id = ? AND revoked_at IS NULL`, id).
		Scan(&raw, &sc, &c.AAGUID, &c.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return adminauth.Credential{}, adminauth.ErrUnknownCredential
	}
	if err != nil {
		return adminauth.Credential{}, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return adminauth.Credential{}, fmt.Errorf("store: stored public key: %w", err)
	}
	c.PublicKey, c.SignCount = pub, uint32(sc)
	return c, nil
}

// AdvanceCounter implements [adminauth.Credentials].
func (s *Store) AdvanceCounter(ctx context.Context, id []byte, count uint32) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admin_credentials SET sign_count = ? WHERE credential_id = ? AND revoked_at IS NULL AND ((sign_count = 0 AND ? = 0) OR sign_count < ?)`,
		int64(count), id, int64(count), int64(count))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return adminauth.ErrCounterRegression
	}
	return nil
}

// ListCredentials lists every admin credential, revoked ones included.
func (s *Store) ListCredentials(ctx context.Context) ([]AdminCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT credential_id, name, aaguid, sign_count, created_at, revoked_at FROM admin_credentials ORDER BY id LIMIT ?`, MaxList)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminCredential
	for rows.Next() {
		var c AdminCredential
		var sc, created int64
		var rev sql.NullInt64
		if err := rows.Scan(&c.ID, &c.Name, &c.AAGUID, &sc, &created, &rev); err != nil {
			return nil, err
		}
		c.SignCount, c.CreatedAt, c.RevokedAt = uint32(sc), time.Unix(created, 0).UTC(), ts(rev)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ErrLastCredential is returned when a revocation would leave no active admin
// credential, which would lock every administrator out.
var ErrLastCredential = errors.New("store: refusing to revoke the last active admin credential")

// RevokeCredential revokes an active credential, unless it is the last one. The
// count and the update are one statement, so two concurrent revocations of the
// last two credentials cannot both succeed.
func (s *Store) RevokeCredential(ctx context.Context, id []byte) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admin_credentials SET revoked_at = ? WHERE credential_id = ? AND revoked_at IS NULL
		AND (SELECT count(*) FROM admin_credentials WHERE revoked_at IS NULL) > 1`, s.now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	var active int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM admin_credentials WHERE credential_id = ? AND revoked_at IS NULL`, id).Scan(&active); err != nil {
		return err
	}
	if active == 1 {
		return ErrLastCredential
	}
	return ErrNotFound
}

// ActiveCredentialCount is how many credentials can still authenticate.
func (s *Store) ActiveCredentialCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM admin_credentials WHERE revoked_at IS NULL`).Scan(&n)
	return n, err
}

// ---- users ----

// User is an account.
type User struct {
	Login       string
	DisplayName string
	CreatedAt   time.Time
	DisabledAt  time.Time // zero while enabled
}

var loginRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}$`)

// ValidLogin reports whether s is an acceptable login: 1 to 39 characters of
// [a-z0-9-], starting with a letter or digit. (An e-mail address is not.)
func ValidLogin(s string) error {
	if !loginRE.MatchString(s) {
		return fmt.Errorf("%w: login must match %s", ErrInvalid, loginRE)
	}
	return nil
}

func validText(what, s string, max int, empty bool) error {
	if (!empty && s == "") || len(s) > max || !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s", ErrInvalid, what)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s has a control character", ErrInvalid, what)
		}
	}
	return nil
}

// ValidName checks a credential name.
func ValidName(s string) error { return validText("name", s, MaxNameLen, false) }

// CreateUser creates an enabled user.
func (s *Store) CreateUser(ctx context.Context, login, display string) (User, error) {
	if err := ValidLogin(login); err != nil {
		return User{}, err
	}
	if err := validText("display name", display, MaxDisplayNameLen, true); err != nil {
		return User{}, err
	}
	now := s.now().Unix()
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(login, display_name, created_at) VALUES (?,?,?)`, login, display, now)
	if isUnique(err) {
		return User{}, ErrExists
	}
	if err != nil {
		return User{}, err
	}
	return User{Login: login, DisplayName: display, CreatedAt: time.Unix(now, 0).UTC()}, nil
}

// ListUsers lists users by creation.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT login, display_name, created_at, disabled_at FROM users ORDER BY id LIMIT ?`, MaxList)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var created int64
		var dis sql.NullInt64
		if err := rows.Scan(&u.Login, &u.DisplayName, &created, &dis); err != nil {
			return nil, err
		}
		u.CreatedAt, u.DisabledAt = time.Unix(created, 0).UTC(), ts(dis)
		out = append(out, u)
	}
	return out, rows.Err()
}

// DisableUser disables an enabled user.
func (s *Store) DisableUser(ctx context.Context, login string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET disabled_at = ? WHERE login = ? AND disabled_at IS NULL`, s.now().Unix(), login)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// ---- identities ----

// Identity is an external identity bound to a user.
type Identity struct {
	Issuer, Subject, Login string
	CreatedAt              time.Time
}

// ValidIssuer accepts an https URL without query, fragment or credentials.
func ValidIssuer(s string) error {
	if err := validText("issuer", s, MaxIssuerLen, false); err != nil {
		return err
	}
	if !strings.HasPrefix(s, "https://") || len(s) == len("https://") ||
		strings.ContainsAny(s, "?#@ ") {
		return fmt.Errorf("%w: issuer must be an https URL without query, fragment or userinfo", ErrInvalid)
	}
	return nil
}

// ValidSubject checks an OIDC subject (opaque, bounded).
func ValidSubject(s string) error { return validText("subject", s, MaxSubjectLen, false) }

// BindIdentity binds (issuer, subject) to an enabled user. An identity that is
// already bound, to anyone, is refused: a rebinding is an unbind then a bind.
func (s *Store) BindIdentity(ctx context.Context, issuer, subject, login string) (Identity, error) {
	if err := ValidIssuer(issuer); err != nil {
		return Identity{}, err
	}
	if err := ValidSubject(subject); err != nil {
		return Identity{}, err
	}
	if err := ValidLogin(login); err != nil {
		return Identity{}, err
	}
	var uid int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE login = ? AND disabled_at IS NULL`, login).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, ErrNotFound
	}
	if err != nil {
		return Identity{}, err
	}
	now := s.now().Unix()
	_, err = s.db.ExecContext(ctx, `INSERT INTO identities(issuer, subject, user_id, created_at) VALUES (?,?,?,?)`, issuer, subject, uid, now)
	if isUnique(err) {
		return Identity{}, ErrExists
	}
	if err != nil {
		return Identity{}, err
	}
	return Identity{issuer, subject, login, time.Unix(now, 0).UTC()}, nil
}

// ListIdentities lists bindings, of one user when login is not empty.
func (s *Store) ListIdentities(ctx context.Context, login string) ([]Identity, error) {
	q := `SELECT i.issuer, i.subject, u.login, i.created_at FROM identities i JOIN users u ON u.id = i.user_id`
	var args []any
	if login != "" {
		q += ` WHERE u.login = ?`
		args = append(args, login)
	}
	q += ` ORDER BY i.created_at, i.issuer, i.subject LIMIT ?`
	args = append(args, MaxList)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		var i Identity
		var created int64
		if err := rows.Scan(&i.Issuer, &i.Subject, &i.Login, &created); err != nil {
			return nil, err
		}
		i.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, i)
	}
	return out, rows.Err()
}

// UnbindIdentity removes a binding.
func (s *Store) UnbindIdentity(ctx context.Context, issuer, subject string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM identities WHERE issuer = ? AND subject = ?`, issuer, subject)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// ---- audit ----

// Audit outcomes. An act leaves an attempt row when it is authorized and a
// success or failure row once it has run.
const (
	OutcomeAttempt = "attempt"
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// Audit records a step of an administrative act.
func (s *Store) Audit(ctx context.Context, credentialID []byte, method string, requestSHA256 []byte, outcome string) error {
	switch outcome {
	case OutcomeAttempt, OutcomeSuccess, OutcomeFailure:
	default:
		return fmt.Errorf("%w: audit outcome %q", ErrInvalid, outcome)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_audit(at, credential_id, method, request_sha256, outcome) VALUES (?,?,?,?,?)`,
		s.now().Unix(), credentialID, method, requestSHA256, outcome)
	return err
}

// AuditRow is one row of the audit trail.
type AuditRow struct {
	At           time.Time
	CredentialID []byte
	Method       string
	Outcome      string
}

// AuditRows returns the audit trail, oldest first.
func (s *Store) AuditRows(ctx context.Context) ([]AuditRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at, credential_id, method, outcome FROM admin_audit ORDER BY id LIMIT ?`, MaxList)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		var at int64
		if err := rows.Scan(&at, &r.CredentialID, &r.Method, &r.Outcome); err != nil {
			return nil, err
		}
		r.At = time.Unix(at, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AuditCount is the number of audit rows (for tests and status).
func (s *Store) AuditCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM admin_audit`).Scan(&n)
	return n, err
}
