// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// Errors a nonce or session check returns.
var (
	ErrNonceUnknown     = errors.New("nonce unknown, forged, already used, malformed or issued to another connection")
	ErrNonceExpired     = errors.New("nonce expired")
	ErrNonceStoreFull   = errors.New("too many accepted calls in one nonce lifetime")
	ErrSessionInvalid   = errors.New("session unknown, expired or malformed")
	ErrSessionOtherConn = errors.New("session belongs to another connection")
	ErrTooManySessions  = errors.New("too many open sessions")
)

type record struct {
	exporter []byte
	owner    []byte // the credential that opened a session
	expires  time.Time
}

// table is a bounded set of random 32-byte tokens, each bound to a connection.
// It holds sessions: opening one needs a signed call, so a peer that has proved
// nothing cannot fill it.
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

func (t *table) issue(exporter, owner []byte, errTooMany error) ([]byte, time.Time, error) {
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
	t.m[k] = record{exporter: append([]byte(nil), exporter...), owner: append([]byte(nil), owner...), expires: exp}
	return k[:], exp, nil
}

func (t *table) take(tok, exporter []byte, unknown, expired, other error) ([]byte, error) {
	if len(tok) != NonceLen {
		return nil, unknown
	}
	var k [NonceLen]byte
	copy(k[:], tok)
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.m[k]
	if !ok {
		return nil, unknown
	}
	if !t.now().Before(r.expires) {
		delete(t.m, k)
		return nil, expired
	}
	if subtle.ConstantTimeCompare(r.exporter, exporter) != 1 {
		return nil, other
	}
	return r.owner, nil
}

// Layout of a stateless nonce: issue time (Unix seconds, big endian), 16 random
// bytes, then HMAC-SHA-256 over a label, the first two fields and the TLS
// exporter value of the connection it was issued on.
const (
	nonceRandLen = 16
	nonceMACLen  = sha256.Size
	// TokenLen is the length of a nonce.
	TokenLen = 8 + nonceRandLen + nonceMACLen
)

// Nonces issues and consumes the single-use nonces of signed calls. It stores
// nothing at issue time, so a peer that has proved nothing, however many
// connections and nonces it asks for, uses no memory and takes no room from
// anyone. The only state is the set of nonces of ACCEPTED assertions, kept until
// they would have expired anyway: it cannot hold more than the number of
// accepted (physically authorised) calls in one lifetime, and is capped.
//
// The MAC key is random and made when the process starts: nonces do not survive
// a restart (at most one lifetime of an in-flight call is lost), and no key
// file exists to protect.
type Nonces struct {
	now     func() time.Time
	ttl     time.Duration
	key     [32]byte
	maxUsed int

	mu   sync.Mutex
	used map[[nonceRandLen]byte]time.Time // random part -> expiry
}

// NewNonces returns a nonce store. A nonce lives ttl; at most maxUsed accepted
// nonces are remembered at once.
func NewNonces(now func() time.Time, ttl time.Duration, maxUsed int) *Nonces {
	if now == nil {
		now = time.Now
	}
	n := &Nonces{now: now, ttl: ttl, maxUsed: maxUsed, used: map[[nonceRandLen]byte]time.Time{}}
	rand.Read(n.key[:])
	return n
}

func (n *Nonces) mac(head, exporter []byte) []byte {
	h := hmac.New(sha256.New, n.key[:])
	h.Write([]byte("go-vcs admin nonce v1"))
	h.Write(head)
	h.Write(exporter)
	return h.Sum(nil)
}

// Issue returns a fresh nonce bound to the connection whose exporter value is
// given. It never fails and stores nothing.
func (n *Nonces) Issue(exporter []byte) ([]byte, time.Time) {
	t := n.now()
	b := make([]byte, 8+nonceRandLen, TokenLen)
	binary.BigEndian.PutUint64(b, uint64(t.Unix()))
	rand.Read(b[8:])
	return append(b, n.mac(b, exporter)...), time.Unix(t.Unix(), 0).Add(n.ttl)
}

// check validates the MAC, the lifetime, the connection and the used-set, and
// returns the random part and the expiry.
func (n *Nonces) check(nonce, exporter []byte) ([nonceRandLen]byte, time.Time, error) {
	var r [nonceRandLen]byte
	if len(nonce) != TokenLen {
		return r, time.Time{}, ErrNonceUnknown
	}
	// The MAC covers the exporter, so a nonce replayed on another connection
	// fails here like a forgery: a peer learns nothing from telling them apart.
	if !hmac.Equal(nonce[8+nonceRandLen:], n.mac(nonce[:8+nonceRandLen], exporter)) {
		return r, time.Time{}, ErrNonceUnknown
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(nonce)), 0).Add(n.ttl)
	now := n.now()
	if !now.Before(exp) {
		return r, time.Time{}, ErrNonceExpired
	}
	copy(r[:], nonce[8:])
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, spent := n.used[r]; spent {
		return r, time.Time{}, ErrNonceUnknown
	}
	return r, exp, nil
}

// Check reports whether nonce is acceptable on this connection, without
// spending it.
func (n *Nonces) Check(nonce, exporter []byte) error {
	_, _, err := n.check(nonce, exporter)
	return err
}

// Spend marks the nonce of an accepted assertion as used. It is atomic: of two
// calls carrying the same nonce, one gets ErrNonceUnknown. Nothing else ever
// enters the used-set.
func (n *Nonces) Spend(nonce, exporter []byte) error {
	r, exp, err := n.check(nonce, exporter)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, spent := n.used[r]; spent {
		return ErrNonceUnknown
	}
	now := n.now()
	if len(n.used) >= n.maxUsed {
		for k, e := range n.used {
			if !now.Before(e) {
				delete(n.used, k)
			}
		}
		if len(n.used) >= n.maxUsed {
			return ErrNonceStoreFull
		}
	}
	n.used[r] = exp
	return nil
}

// Sessions holds the short read-only sessions opened by one assertion.
type Sessions struct{ t *table }

// NewSessions returns a session store.
func NewSessions(now func() time.Time, ttl time.Duration, perConn, total int) *Sessions {
	return &Sessions{newTable(now, ttl, perConn, total)}
}

// Open returns a session token bound to the connection and to the credential
// that opened it.
func (s *Sessions) Open(exporter, credentialID []byte) ([]byte, time.Time, error) {
	return s.t.issue(exporter, credentialID, ErrTooManySessions)
}

// Check accepts a token only on the connection it was opened on, and returns
// the id of the credential that opened it, which the caller must still find
// active.
func (s *Sessions) Check(token, exporter []byte) ([]byte, error) {
	return s.t.take(token, exporter, ErrSessionInvalid, ErrSessionInvalid, ErrSessionOtherConn)
}
