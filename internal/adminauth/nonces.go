// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminauth

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"sync"
	"time"
)

// Errors a nonce or session check returns.
var (
	ErrNonceUnknown         = errors.New("nonce unknown, already used or malformed")
	ErrNonceExpired         = errors.New("nonce expired")
	ErrNonceOtherConnection = errors.New("nonce was issued to another connection")
	ErrTooManyNonces        = errors.New("too many outstanding nonces")
	ErrSessionInvalid       = errors.New("session unknown, expired or malformed")
	ErrSessionOtherConn     = errors.New("session belongs to another connection")
	ErrTooManySessions      = errors.New("too many open sessions")
)

type record struct {
	exporter []byte
	expires  time.Time
}

// table is a bounded set of random 32-byte tokens, each bound to a connection.
type table struct {
	mu      sync.Mutex
	now     func() time.Time
	ttl     time.Duration
	perConn int
	total   int
	m       map[[NonceLen]byte]record
}

func newTable(now func() time.Time, ttl time.Duration, perConn, total int) *table {
	if now == nil {
		now = time.Now
	}
	return &table{now: now, ttl: ttl, perConn: perConn, total: total, m: map[[NonceLen]byte]record{}}
}

func (t *table) issue(exporter []byte, errTooMany error) ([]byte, time.Time, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	n := 0
	for k, r := range t.m {
		if !now.Before(r.expires) {
			delete(t.m, k)
			continue
		}
		if bytes.Equal(r.exporter, exporter) {
			n++
		}
	}
	if n >= t.perConn || len(t.m) >= t.total {
		return nil, time.Time{}, errTooMany
	}
	var k [NonceLen]byte
	rand.Read(k[:]) // never fails: crypto/rand.Read aborts the program instead
	exp := now.Add(t.ttl)
	t.m[k] = record{exporter: append([]byte(nil), exporter...), expires: exp}
	return k[:], exp, nil
}

// take removes the token (whatever the outcome of the other checks, so a failed
// attempt burns it) and reports why it is not acceptable, if it is not.
func (t *table) take(tok, exporter []byte, burn bool, unknown, expired, other error) error {
	if len(tok) != NonceLen {
		return unknown
	}
	var k [NonceLen]byte
	copy(k[:], tok)
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.m[k]
	if !ok {
		return unknown
	}
	if burn {
		delete(t.m, k)
	}
	if !t.now().Before(r.expires) {
		delete(t.m, k)
		return expired
	}
	if subtle.ConstantTimeCompare(r.exporter, exporter) != 1 {
		return other
	}
	return nil
}

// Nonces issues and consumes the single-use nonces of signed calls.
type Nonces struct{ t *table }

// NewNonces returns a nonce store. A nonce lives ttl, a connection may hold
// perConn outstanding nonces and the store total.
func NewNonces(now func() time.Time, ttl time.Duration, perConn, total int) *Nonces {
	return &Nonces{newTable(now, ttl, perConn, total)}
}

// Issue returns a fresh nonce bound to the connection whose exporter value is
// given.
func (n *Nonces) Issue(exporter []byte) ([]byte, time.Time, error) {
	return n.t.issue(exporter, ErrTooManyNonces)
}

// Consume spends a nonce. It is gone afterwards even when it is refused, so a
// replay, a wrong-connection use and an expiry each cost the caller the nonce.
func (n *Nonces) Consume(nonce, exporter []byte) error {
	return n.t.take(nonce, exporter, true, ErrNonceUnknown, ErrNonceExpired, ErrNonceOtherConnection)
}

// Sessions holds the short read-only sessions opened by one assertion.
type Sessions struct{ t *table }

// NewSessions returns a session store.
func NewSessions(now func() time.Time, ttl time.Duration, perConn, total int) *Sessions {
	return &Sessions{newTable(now, ttl, perConn, total)}
}

// Open returns a session token bound to the connection.
func (s *Sessions) Open(exporter []byte) ([]byte, time.Time, error) {
	return s.t.issue(exporter, ErrTooManySessions)
}

// Check accepts a token only on the connection it was opened on.
func (s *Sessions) Check(token, exporter []byte) error {
	return s.t.take(token, exporter, false, ErrSessionInvalid, ErrSessionInvalid, ErrSessionOtherConn)
}
