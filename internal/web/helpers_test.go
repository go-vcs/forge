// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package web_test

import (
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/idptest"
	"github.com/go-vcs/forge/internal/secretbox"
	"github.com/go-vcs/forge/internal/store"
	"github.com/go-vcs/forge/internal/web"
)

var epoch = time.Unix(1_800_000_000, 0).UTC()

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	t    *testing.T
	st   *store.Store
	idp  *idptest.IdP
	srv  *web.Server
	ts   *httptest.Server
	clk  *clock
	jar  *cookiejar.Jar
	b    *http.Client // the browser: cookies, no redirects followed
	box  *secretbox.Box
	path string // the database file, for faults injected behind the store's back
	logs *logBuf
}

// logBuf collects the server's log, which says WHY a refusal happened: the
// pages of every refusal are identical on purpose.
type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// raw runs SQL on the database file behind the store's back.
func (e *env) raw(stmts string) {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+e.path)
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(stmts); err != nil {
		e.t.Fatalf("%s: %v", stmts, err)
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, clk: &clock{t: epoch}, logs: &logBuf{}, path: filepath.Join(t.TempDir(), "forge.db")}
	var err error
	e.st, err = store.Open(t.Context(), e.path, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.st.Close() })
	e.box, err = secretbox.New(make([]byte, secretbox.KeyLen))
	if err != nil {
		t.Fatal(err)
	}
	e.idp = idptest.New(t)
	e.srv = &web.Server{Store: e.st, Seal: e.box, HTTP: e.idp.Client(), Now: e.clk.Now,
		Log: slog.New(slog.NewTextHandler(e.logs, nil))}
	var h http.Handler
	e.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(e.ts.Close)
	h = e.srv.Handler()
	e.idp.Redirect = e.ts.URL + "/callback"
	e.register(e.idp.Issuer, e.idp.ClientID, e.idp.Secret)
	e.bind("alice", "alice-sub")
	e.jar, _ = cookiejar.New(nil)
	e.b = e.newBrowser()
	return e
}

func (e *env) newBrowser() *http.Client {
	jar, _ := cookiejar.New(nil)
	e.jar = jar
	return &http.Client{Transport: e.ts.Client().Transport, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (e *env) register(issuer, clientID, secret string) {
	e.t.Helper()
	c := store.OIDCClient{Issuer: issuer, ClientID: clientID, RedirectURI: e.ts.URL + "/callback"}
	if secret != "" {
		var err error
		if c.SecretSealed, err = e.box.Seal([]byte(secret), adminsrv.OIDCSecretPurpose); err != nil {
			e.t.Fatal(err)
		}
	}
	if err := e.st.SetOIDCClient(e.t.Context(), c); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) bind(login, sub string) {
	e.t.Helper()
	if _, err := e.st.CreateUser(e.t.Context(), login, login); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.st.BindIdentity(e.t.Context(), e.idp.Issuer, sub, login); err != nil {
		e.t.Fatal(err)
	}
}

func get(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	r, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (e *env) post(path string, form url.Values) *http.Response {
	e.t.Helper()
	r, err := e.b.PostForm(e.ts.URL+path, form)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// startLogin is GET /login: the authorization URL the browser is sent to.
func (e *env) startLogin(next string) (authURL string, r *http.Response) {
	e.t.Helper()
	u := e.ts.URL + "/login"
	if next != "" {
		u += "?next=" + url.QueryEscape(next)
	}
	r = get(e.t, e.b, u)
	body(e.t, r)
	if r.StatusCode != http.StatusFound {
		return "", r
	}
	return r.Header.Get("Location"), r
}

// authorize is the browser at the bridge: it comes back with the callback URL.
func (e *env) authorize(authURL string) string {
	e.t.Helper()
	c := &http.Client{Transport: e.idp.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r := get(e.t, c, authURL)
	body(e.t, r)
	if r.StatusCode != http.StatusFound {
		e.t.Fatalf("authorize: %d", r.StatusCode)
	}
	return r.Header.Get("Location")
}

// signIn runs the whole flow and returns the callback's response and body.
func (e *env) signIn() (*http.Response, string) {
	e.t.Helper()
	a, _ := e.startLogin("")
	if a == "" {
		e.t.Fatal("login did not redirect")
	}
	r := get(e.t, e.b, e.authorize(a))
	return r, body(e.t, r)
}

func (e *env) signedIn() *http.Response {
	e.t.Helper()
	r, _ := e.signIn()
	if r.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("sign-in: %d", r.StatusCode)
	}
	return r
}

func (e *env) cookieValue(name string) string {
	u, _ := url.Parse(e.ts.URL)
	for _, c := range e.jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func (e *env) home() string {
	e.t.Helper()
	r := get(e.t, e.b, e.ts.URL+"/")
	return body(e.t, r)
}

func (e *env) isSignedIn() bool { return strings.Contains(e.home(), `action="/logout"`) }

func (e *env) sessions() int {
	e.t.Helper()
	n, err := e.st.SessionCount(e.t.Context())
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}
