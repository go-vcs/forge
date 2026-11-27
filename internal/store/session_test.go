// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/store"
)

const (
	sessIss  = "https://i.example"
	sessIdle = 30 * time.Minute
	sessAbs  = 12 * time.Hour
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func openClock(t *testing.T) (*store.Store, *clock) {
	t.Helper()
	c := &clock{epoch}
	s, err := store.Open(t.Context(), ":memory:", c.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, c
}

func idh(n string) []byte { h := sha256.Sum256([]byte(n)); return h[:] }

func bound(t *testing.T, s *store.Store, login, sub string) {
	t.Helper()
	if _, err := s.CreateUser(t.Context(), login, login); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindIdentity(t.Context(), sessIss, sub, login); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, s *store.Store) int {
	t.Helper()
	n, err := s.SessionCount(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSessionRoundTrip(t *testing.T) {
	ctx := t.Context()
	s, c := openClock(t)
	bound(t, s, "alice", "a")
	if err := s.CreateSession(ctx, idh("1"), "csrf-token-0123456789", sessIss, "a"); err != nil {
		t.Fatal(err)
	}
	c.t = epoch.Add(time.Minute)
	got, err := s.LookupSession(ctx, idh("1"), sessIdle, sessAbs)
	if err != nil || got.Login != "alice" || got.CSRF != "csrf-token-0123456789" ||
		!got.CreatedAt.Equal(epoch) || !got.LastSeen.Equal(epoch.Add(time.Minute)) {
		t.Fatalf("got %+v %v", got, err)
	}
	if _, err := s.LookupSession(ctx, idh("other"), sessIdle, sessAbs); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown id = %v", err)
	}
	if err := s.DeleteSession(ctx, idh("1")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, idh("1")); err != nil {
		t.Fatalf("a second delete = %v", err)
	}
	if _, err := s.LookupSession(ctx, idh("1"), sessIdle, sessAbs); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted = %v", err)
	}
}

// A session is created only for a bound identity of an enabled account.
func TestCreateSessionRefusesWhatIsNotBound(t *testing.T) {
	ctx := t.Context()
	s, _ := openClock(t)
	bound(t, s, "alice", "a")
	for name, id := range map[string][2]string{
		"unbound subject": {sessIss, "zzz"},
		"other issuer":    {"https://j.example", "a"},
	} {
		if err := s.CreateSession(ctx, idh(name), "csrf-token-0123456789", id[0], id[1]); !errors.Is(err, store.ErrNotAuthorized) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := s.DisableUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, idh("d"), "csrf-token-0123456789", sessIss, "a"); !errors.Is(err, store.ErrNotAuthorized) {
		t.Errorf("disabled: %v", err)
	}
	if n := count(t, s); n != 0 {
		t.Fatalf("%d sessions stored", n)
	}
}

func TestSessionExpiry(t *testing.T) {
	ctx := t.Context()
	for _, tc := range []struct {
		name  string
		steps []time.Duration // lookups at these offsets from creation
		alive []bool
	}{
		{"idle, one second before", []time.Duration{sessIdle - time.Second}, []bool{true}},
		{"idle, at the limit", []time.Duration{sessIdle}, []bool{false}},
		{"activity keeps it alive", []time.Duration{20 * time.Minute, 40 * time.Minute, 60 * time.Minute}, []bool{true, true, true}},
		{"absolute: alive one second before the limit, gone at it, despite activity", activeUntil(sessAbs), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, c := openClock(t)
			bound(t, s, "alice", "a")
			if err := s.CreateSession(ctx, idh("1"), "csrf-token-0123456789", sessIss, "a"); err != nil {
				t.Fatal(err)
			}
			for i, d := range tc.steps {
				c.t = epoch.Add(d)
				_, err := s.LookupSession(ctx, idh("1"), sessIdle, sessAbs)
				want := true
				if tc.alive != nil {
					want = tc.alive[i]
				} else {
					want = d < sessAbs
				}
				if (err == nil) != want {
					t.Fatalf("at +%v: err = %v, alive want %v", d, err, want)
				}
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					t.Fatal(err)
				}
			}
			// an expired session is deleted, not only hidden
			if tc.name == "idle, at the limit" {
				if n := count(t, s); n != 0 {
					t.Fatalf("expired session still stored: %d", n)
				}
			}
		})
	}
}

// activeUntil is a lookup every 10 minutes, up to and including limit.
func activeUntil(limit time.Duration) []time.Duration {
	var out []time.Duration
	for d := 10 * time.Minute; d < limit; d += 10 * time.Minute {
		out = append(out, d)
	}
	return append(out, limit-time.Second, limit)
}

func TestPurgeSessions(t *testing.T) {
	ctx := t.Context()
	s, c := openClock(t)
	bound(t, s, "alice", "a")
	mk := func(n string) {
		if err := s.CreateSession(ctx, idh(n), "csrf-token-0123456789", sessIss, "a"); err != nil {
			t.Fatal(err)
		}
	}
	mk("old")
	c.t = epoch.Add(sessIdle - time.Second)
	mk("fresh")
	c.t = epoch.Add(sessIdle) // old: idle exactly sessIdle; fresh: one second
	if err := s.PurgeSessions(ctx, sessIdle, sessAbs); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s); n != 1 {
		t.Fatalf("after idle purge: %d sessions, want 1", n)
	}
	if _, err := s.LookupSession(ctx, idh("fresh"), sessIdle, sessAbs); err != nil {
		t.Fatalf("the fresh one was purged: %v", err)
	}
	// absolute: keep it active, then purge by age
	c.t = epoch.Add(sessAbs - time.Second)
	if _, err := s.LookupSession(ctx, idh("fresh"), sessIdle, sessAbs); err == nil {
		t.Fatal("idle for hours yet alive") // the idle limit applies first
	}
	mk("again")
	c.t = c.t.Add(sessAbs) // created sessAbs ago
	if err := s.PurgeSessions(ctx, 100*time.Hour, sessAbs); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s); n != 0 {
		t.Fatalf("after absolute purge: %d", n)
	}
	// and one second younger than the limit survives
	mk("young")
	c.t = c.t.Add(sessAbs - time.Second)
	if err := s.PurgeSessions(ctx, 100*time.Hour, sessAbs); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s); n != 1 {
		t.Fatalf("a session younger than the limit was purged: %d", n)
	}
}

func TestSessionsDieWithTheAccountAndTheBinding(t *testing.T) {
	ctx := t.Context()
	s, _ := openClock(t)
	bound(t, s, "alice", "a")
	bound(t, s, "bob", "b")
	for n, sub := range map[string]string{"a1": "a", "a2": "a", "b1": "b"} {
		if err := s.CreateSession(ctx, idh(n), "csrf-token-0123456789", sessIss, sub); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DisableUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s); n != 1 {
		t.Fatalf("disable left %d sessions, want bob's one", n)
	}
	for _, id := range []string{"a1", "a2"} {
		if _, err := s.LookupSession(ctx, idh(id), sessIdle, sessAbs); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if err := s.UnbindIdentity(ctx, sessIss, "b"); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s); n != 0 {
		t.Fatalf("unbind left %d sessions", n)
	}
	// a failed disable or unbind removes nothing
	bound(t, s, "carol", "c")
	if err := s.CreateSession(ctx, idh("c1"), "csrf-token-0123456789", sessIss, "c"); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableUser(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.UnbindIdentity(ctx, sessIss, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if n := count(t, s); n != 1 {
		t.Fatalf("a refused disable/unbind removed sessions: %d", n)
	}
}

// Rows the join would hide are not served: a disabled account's session that a
// bug left behind, and a session whose binding went away.
func TestLookupRechecksAccountAndBinding(t *testing.T) {
	ctx := t.Context()
	s := damaged(t, `INSERT INTO users(id, login, display_name, created_at, disabled_at) VALUES (1,'alice','a',0,5);
		INSERT INTO identities(issuer, subject, user_id, created_at) VALUES ('https://i.example','a',1,0);
		INSERT INTO web_sessions(id_hash, user_id, issuer, subject, csrf, created_at, last_seen)
		  VALUES (zeroblob(32), 1, 'https://i.example', 'a', 'csrf-token-0123456789', 1800000000, 1800000000);
		INSERT INTO users(id, login, display_name, created_at) VALUES (2,'bob','b',0);
		INSERT INTO web_sessions(id_hash, user_id, issuer, subject, csrf, created_at, last_seen)
		  VALUES (x'0000000000000000000000000000000000000000000000000000000000000001', 2, 'https://i.example', 'unbound', 'csrf-token-0123456789', 1800000000, 1800000000);`)
	if _, err := s.LookupSession(ctx, make([]byte, 32), sessIdle, sessAbs); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("disabled account: %v", err)
	}
	id := make([]byte, 32)
	id[31] = 1
	if _, err := s.LookupSession(ctx, id, sessIdle, sessAbs); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unbound identity: %v", err)
	}
}

func TestSessionsPerUserAreBounded(t *testing.T) {
	ctx := t.Context()
	s, c := openClock(t)
	bound(t, s, "alice", "a")
	bound(t, s, "bob", "b")
	if err := s.CreateSession(ctx, idh("bob"), "csrf-token-0123456789", sessIss, "b"); err != nil {
		t.Fatal(err)
	}
	for i := range store.MaxSessionsPerUser + 4 {
		c.t = epoch.Add(time.Duration(i) * time.Second)
		if err := s.CreateSession(ctx, idh(fmt.Sprint("a", i)), "csrf-token-0123456789", sessIss, "a"); err != nil {
			t.Fatal(err)
		}
	}
	c.t = epoch.Add(time.Minute)
	if n := count(t, s); n != store.MaxSessionsPerUser+1 {
		t.Fatalf("%d sessions, want %d (alice's cap plus bob's)", n, store.MaxSessionsPerUser+1)
	}
	for i := range store.MaxSessionsPerUser + 4 {
		_, err := s.LookupSession(ctx, idh(fmt.Sprint("a", i)), sessIdle, sessAbs)
		if kept := i >= 4; kept != (err == nil) {
			t.Errorf("session %d: err %v, kept want %v (the oldest go first)", i, err, kept)
		}
	}
	if _, err := s.LookupSession(ctx, idh("bob"), sessIdle, sessAbs); err != nil {
		t.Errorf("bob's session was evicted by alice's: %v", err)
	}
}

// A statement that fails in the middle of an operation is reported, and
// nothing half-done is kept.
func TestSessionStatementFailuresAreReported(t *testing.T) {
	ctx := t.Context()
	const account = `INSERT INTO users(id, login, display_name, created_at) VALUES (1,'alice','a',0);
		INSERT INTO identities(issuer, subject, user_id, created_at) VALUES ('https://i.example','a',1,0);`
	const row = `INSERT INTO web_sessions(id_hash, user_id, issuer, subject, csrf, created_at, last_seen)
		VALUES (zeroblob(32), 1, 'https://i.example', 'a', 'csrf-token-0123456789', %s, %s);`
	const sixteen = `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 16)
		INSERT INTO web_sessions SELECT randomblob(32), 1, 'https://i.example', 'a', 'csrf-token-0123456789', 1, 1 FROM n;`
	deny := func(event string) string {
		return `CREATE TRIGGER deny BEFORE ` + event + ` ON web_sessions BEGIN SELECT RAISE(ABORT, 'denied'); END;`
	}
	now := "CAST(strftime('%s','now') AS INTEGER)"

	t.Run("insert", func(t *testing.T) {
		s := damaged(t, account+`DROP TABLE web_sessions;`)
		wantErr(t, "CreateSession", s.CreateSession(ctx, idh("n"), "csrf-token-0123456789", sessIss, "a"), "no such table")
	})
	t.Run("eviction", func(t *testing.T) {
		s := damaged(t, account+sixteen+deny("DELETE"))
		wantErr(t, "CreateSession", s.CreateSession(ctx, idh("n"), "csrf-token-0123456789", sessIss, "a"), "denied")
		if n := count(t, s); n != 16 {
			t.Errorf("%d sessions after a failed create, want the 16 there were (rolled back)", n)
		}
	})
	t.Run("lookup select", func(t *testing.T) {
		s := damaged(t, `DROP TABLE identities;`)
		_, err := s.LookupSession(ctx, idh("n"), sessIdle, sessAbs)
		wantErr(t, "LookupSession", err, "no such table")
		if errors.Is(err, store.ErrNotFound) {
			t.Error("a broken database reads as a missing session")
		}
	})
	t.Run("lookup delete expired", func(t *testing.T) {
		s := damaged(t, account+fmt.Sprintf(row, "1", "1")+deny("DELETE"))
		_, err := s.LookupSession(ctx, make([]byte, 32), sessIdle, sessAbs)
		wantErr(t, "LookupSession", err, "denied")
	})
	t.Run("lookup touch", func(t *testing.T) {
		s := damaged(t, account+fmt.Sprintf(row, now, now)+deny("UPDATE"))
		_, err := s.LookupSession(ctx, make([]byte, 32), sessIdle, sessAbs)
		wantErr(t, "LookupSession", err, "denied")
	})
}

func TestSessionOperationsReportAClosedDatabase(t *testing.T) {
	s, err := store.Open(t.Context(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	ctx := t.Context()
	for name, op := range map[string]func() error{
		"CreateSession": func() error { return s.CreateSession(ctx, idh("1"), "csrf-token-0123456789", sessIss, "a") },
		"LookupSession": func() error { _, e := s.LookupSession(ctx, idh("1"), sessIdle, sessAbs); return e },
		"DeleteSession": func() error { return s.DeleteSession(ctx, idh("1")) },
		"PurgeSessions": func() error { return s.PurgeSessions(ctx, sessIdle, sessAbs) },
		"SessionCount":  func() error { _, e := s.SessionCount(ctx); return e },
	} {
		wantErr(t, name, op(), "database is closed")
	}
}
