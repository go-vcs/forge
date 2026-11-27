// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// MaxSessionsPerUser bounds the live web sessions of one account: a new
// sign-in beyond it ends the oldest.
const MaxSessionsPerUser = 16

// Session is a live web session.
type Session struct {
	Login string
	// CSRF is the token a state-changing form must carry.
	CSRF                string
	CreatedAt, LastSeen time.Time
}

// CreateSession stores a session for the account (issuer, subject) is bound to.
// idHash is the SHA-256 of the cookie value; the cookie value itself is never
// stored. An identity that is unbound, or whose account is disabled, gets
// ErrNotAuthorized and no row, whatever was checked before.
func (s *Store) CreateSession(ctx context.Context, idHash []byte, csrf, issuer, subject string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		now := s.now().Unix()
		res, err := tx.ExecContext(ctx, `INSERT INTO web_sessions (id_hash, user_id, issuer, subject, csrf, created_at, last_seen)
			SELECT ?, u.id, i.issuer, i.subject, ?, ?, ? FROM identities i JOIN users u ON u.id = i.user_id
			WHERE i.issuer = ? AND i.subject = ? AND u.disabled_at IS NULL`,
			idHash, csrf, now, now, issuer, subject)
		if err == nil {
			if n, _ := res.RowsAffected(); n != 1 {
				err = ErrNotAuthorized
			}
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE user_id = (SELECT user_id FROM web_sessions WHERE id_hash = ?)
				AND id_hash NOT IN (SELECT id_hash FROM web_sessions WHERE user_id = (SELECT user_id FROM web_sessions WHERE id_hash = ?)
				ORDER BY created_at DESC, rowid DESC LIMIT ?)`, idHash, idHash, MaxSessionsPerUser)
		}
		return err
	})
}

// inTx runs fn in a transaction: committed when fn succeeds, rolled back
// otherwise. It has no early return, so no refusal of it can be removed
// without the compiler or a test noticing.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err == nil {
		defer tx.Rollback()
		if err = fn(tx); err == nil {
			err = tx.Commit()
		}
	}
	return err
}

// LookupSession returns the session idHash names, and refreshes its idle
// clock. A session is gone, ErrNotFound, when it is idle for idle or older than
// abs, when its account is disabled, or when the identity it was created from
// is no longer bound.
func (s *Store) LookupSession(ctx context.Context, idHash []byte, idle, abs time.Duration) (Session, error) {
	var (
		out           Session
		created, seen int64
	)
	err := s.db.QueryRowContext(ctx, `SELECT u.login, w.csrf, w.created_at, w.last_seen FROM web_sessions w
		JOIN users u ON u.id = w.user_id AND u.disabled_at IS NULL
		JOIN identities i ON i.issuer = w.issuer AND i.subject = w.subject AND i.user_id = w.user_id
		WHERE w.id_hash = ?`, idHash).Scan(&out.Login, &out.CSRF, &created, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	out.CreatedAt, out.LastSeen = time.Unix(created, 0).UTC(), time.Unix(seen, 0).UTC()
	if !now.Before(out.LastSeen.Add(idle)) || !now.Before(out.CreatedAt.Add(abs)) {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE id_hash = ?`, idHash); err != nil {
			return Session{}, err
		}
		return Session{}, ErrNotFound
	}
	// One statement, so no transaction: a session removed in between is a
	// touch that changes no row, which is the right outcome.
	if _, err := s.db.ExecContext(ctx, `UPDATE web_sessions SET last_seen = ? WHERE id_hash = ?`, now.Unix(), idHash); err != nil {
		return Session{}, err
	}
	out.LastSeen = time.Unix(now.Unix(), 0).UTC()
	return out, nil
}

// DeleteSession ends one session. A session that is already gone is not an
// error: a logout is idempotent.
func (s *Store) DeleteSession(ctx context.Context, idHash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE id_hash = ?`, idHash)
	return err
}

// PurgeSessions deletes every session that is idle for idle or older than abs.
func (s *Store) PurgeSessions(ctx context.Context, idle, abs time.Duration) error {
	now := s.now()
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE last_seen <= ? OR created_at <= ?`,
		now.Add(-idle).Unix(), now.Add(-abs).Unix())
	return err
}

// SessionCount is the number of stored sessions (for tests and metrics).
func (s *Store) SessionCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM web_sessions`).Scan(&n)
	return n, err
}
