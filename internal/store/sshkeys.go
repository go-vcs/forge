// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-vcs/forge/internal/sshkeys"
)

// ---- policy ----

// Policy is the set of forge-wide settings.
type Policy struct {
	// RequireSKKeys refuses to store, and to authenticate with, any SSH key
	// that is not FIDO-backed.
	RequireSKKeys bool
}

const settingRequireSK = "require_sk_ssh_keys"

// GetPolicy reads the settings. A setting never written is false.
func (s *Store) GetPolicy(ctx context.Context) (Policy, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE name = ?`, settingRequireSK).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, nil
	}
	if err != nil {
		return Policy{}, err
	}
	return Policy{RequireSKKeys: v == "true"}, nil
}

// SetPolicy stores the settings.
func (s *Store) SetPolicy(ctx context.Context, p Policy) error {
	v := "false"
	if p.RequireSKKeys {
		v = "true"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(name, value) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET value = excluded.value`, settingRequireSK, v)
	return err
}

// ---- ssh keys ----

// SSHKey is a stored public key.
type SSHKey struct {
	Login     string
	Key       sshkeys.Key
	CreatedAt time.Time
}

// AddSSHKey stores a public key for an enabled user. When the policy requires
// security keys, any other type is refused. A key already registered, to anyone,
// is refused with ErrExists.
func (s *Store) AddSSHKey(ctx context.Context, login, line string) (SSHKey, error) {
	if err := ValidLogin(login); err != nil {
		return SSHKey{}, err
	}
	k, err := sshkeys.Parse(line)
	if err != nil {
		return SSHKey{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	pol, err := s.GetPolicy(ctx)
	if err != nil {
		return SSHKey{}, err
	}
	if pol.RequireSKKeys && !k.SecurityKey {
		return SSHKey{}, fmt.Errorf("%w: policy requires a FIDO-backed (sk-) key, not %s", ErrInvalid, k.Type)
	}
	var uid int64
	err = s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE login = ? AND disabled_at IS NULL`, login).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return SSHKey{}, ErrNotFound
	}
	if err != nil {
		return SSHKey{}, err
	}
	now := s.now().Unix()
	_, err = s.db.ExecContext(ctx, `INSERT INTO ssh_keys(user_id, fingerprint, key_type, blob, comment, created_at) VALUES (?,?,?,?,?,?)`,
		uid, k.Fingerprint, k.Type, k.Blob, k.Comment, now)
	if isUnique(err) {
		return SSHKey{}, ErrExists
	}
	if err != nil {
		return SSHKey{}, err
	}
	return SSHKey{Login: login, Key: k, CreatedAt: time.Unix(now, 0).UTC()}, nil
}

// ListSSHKeys lists keys by creation, of one user when login is not empty.
func (s *Store) ListSSHKeys(ctx context.Context, login string) ([]SSHKey, error) {
	q := `SELECT u.login, k.blob, k.comment, k.created_at FROM ssh_keys k JOIN users u ON u.id = k.user_id`
	var args []any
	if login != "" {
		q += ` WHERE u.login = ?`
		args = append(args, login)
	}
	q += ` ORDER BY k.id LIMIT ?`
	args = append(args, MaxList)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSHKey
	for rows.Next() {
		var (
			k       SSHKey
			blob    []byte
			comment string
			created int64
		)
		if err := rows.Scan(&k.Login, &blob, &comment, &created); err != nil {
			return nil, err
		}
		if k.Key, err = sshkeys.ParseBlob(blob, comment); err != nil {
			return nil, err
		}
		k.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, k)
	}
	return out, rows.Err()
}

// RemoveSSHKey deletes the key with this fingerprint.
func (s *Store) RemoveSSHKey(ctx context.Context, fingerprint string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ssh_keys WHERE fingerprint = ?`, fingerprint)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// ErrNotAuthorized is returned by AuthenticateSSHKey for every reason a key
// does not log in: unknown key, disabled account, or a policy refusal. The
// reason is not distinguished, so a probe learns nothing.
var ErrNotAuthorized = errors.New("not authorized")

// AuthenticateSSHKey returns the login an offered key authenticates as. The
// account must be enabled, and when the policy requires security keys the key
// must be one.
func (s *Store) AuthenticateSSHKey(ctx context.Context, fingerprint string) (login string, err error) {
	var keyType string
	err = s.db.QueryRowContext(ctx, `SELECT u.login, k.key_type FROM ssh_keys k JOIN users u ON u.id = k.user_id
		WHERE k.fingerprint = ? AND u.disabled_at IS NULL`, fingerprint).Scan(&login, &keyType)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotAuthorized
	}
	if err != nil {
		return "", err
	}
	pol, err := s.GetPolicy(ctx)
	if err != nil {
		return "", err
	}
	if pol.RequireSKKeys && !sshkeys.IsSecurityKeyType(keyType) {
		return "", ErrNotAuthorized
	}
	return login, nil
}
