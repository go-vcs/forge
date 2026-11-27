// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package web_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	denyInsert = `CREATE TRIGGER deny BEFORE INSERT ON web_sessions BEGIN SELECT RAISE(ABORT, 'denied'); END;`
	denyDelete = `CREATE TRIGGER deny BEFORE DELETE ON web_sessions BEGIN SELECT RAISE(ABORT, 'denied'); END;`
)

// A failing database is a refusal, never a session, and the log says which step
// failed (the page does not).
func TestSignInStepsThatFailAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signed bool   // a session cookie is held when the sign-in starts
		fault  string // SQL run once the browser is at the bridge
		reason string
	}{
		{"the registration vanished", false, `DROP TABLE oidc_client`, `reason="no client"`},
		{"the old session cannot be ended", true, denyDelete, `reason="ending the previous session"`},
		{"expired sessions cannot be purged", false, `DROP TABLE web_sessions`, `reason=purge`},
		{"the session cannot be stored", false, denyInsert, `reason=session`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.signed {
				e.signedIn()
			}
			a, _ := e.startLogin("")
			cb := e.authorize(a)
			e.raw(tc.fault)
			r := get(t, e.b, cb)
			b := body(t, r)
			if r.StatusCode != http.StatusForbidden || !strings.Contains(b, "Sign-in refused") {
				t.Fatalf("callback = %d\n%s", r.StatusCode, b)
			}
			if !strings.Contains(e.logs.String(), tc.reason) {
				t.Errorf("log does not say %s:\n%s", tc.reason, e.logs)
			}
		})
	}
}

// A database that cannot be read is not a missing session: the user is signed
// out and the operator is told.
func TestSessionLookupFailureSignsOut(t *testing.T) {
	e := newEnv(t)
	e.signedIn()
	e.raw(`DROP TABLE web_sessions`)
	if e.isSignedIn() {
		t.Fatal("signed in with no session table")
	}
	if !strings.Contains(e.logs.String(), "session lookup") {
		t.Errorf("the failure was not logged:\n%s", e.logs)
	}
}

func TestLogoutThatCannotDeleteIsAnError(t *testing.T) {
	e := newEnv(t)
	e.signedIn()
	csrf := csrfOf(t, e.home())
	e.raw(denyDelete)
	r := e.post("/logout", url.Values{"csrf": {csrf}})
	body(t, r)
	if r.StatusCode != http.StatusInternalServerError {
		t.Fatalf("logout = %d, want 500: a session that is still there must not look ended", r.StatusCode)
	}
	if findCookie(r, "__Host-forge_session") != nil {
		t.Error("the cookie was cleared although the session was not deleted")
	}
}

func TestTemplateFailureIsAnErrorPage(t *testing.T) {
	e := newEnv(t)
	w := httptest.NewRecorder()
	e.srv.Page(w, "no-such-template.html")
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "internal error") {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	if !strings.Contains(e.logs.String(), "no-such-template.html") {
		t.Errorf("not logged:\n%s", e.logs)
	}
}

func TestDiscoveryIsCached(t *testing.T) {
	e := newEnv(t)
	if _, r := e.startLogin(""); r.StatusCode != http.StatusFound {
		t.Fatalf("login = %d", r.StatusCode)
	}
	first := e.idp.Discoveries // however many requests one discovery takes
	for range 3 {
		if _, r := e.startLogin(""); r.StatusCode != http.StatusFound {
			t.Fatalf("login = %d", r.StatusCode)
		}
	}
	if first == 0 || e.idp.Discoveries != first {
		t.Fatalf("%d discovery requests after the first login, %d after four", first, e.idp.Discoveries)
	}
}
