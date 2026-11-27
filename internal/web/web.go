// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package web is the forge's web listener: OIDC sign-in through the identity
// bridge, server-side sessions, and the read-only repository pages.
//
// Rules it keeps, each with a test:
//
//   - a sign-in never creates an account, never links an identity to a session
//     that already exists, and never looks at an e-mail address: the only key is
//     (issuer, subject), read through store.LoginForIdentity;
//   - every refusal of a sign-in is the same page, so the reason is no oracle;
//   - the session cookie is __Host-, Secure, HttpOnly and SameSite=Lax, its value
//     is random and only its SHA-256 is stored, it is replaced at every sign-in,
//     and it dies by idle time, by age, and with the account or the binding;
//   - a state-changing request (logout) is a POST carrying the session's token;
//   - every response carries a CSP with no inline script and no inline style.
package web

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-authn/harden/redirect"
	"github.com/go-authn/rp"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/secretbox"
	"github.com/go-vcs/forge/internal/store"
)

// Cookie names. The __Host- prefix makes a browser accept the cookie only with
// Secure, Path=/ and no Domain (RFC 6265bis §4.1.3.2), so a sibling host cannot
// plant one.
const (
	SessionCookie = "__Host-forge_session"
	FlowCookie    = "__Host-forge_flow"
)

// Defaults.
const (
	DefaultIdle    = 30 * time.Minute
	DefaultAbs     = 12 * time.Hour
	DefaultFlowTTL = 10 * time.Minute
	// MaxFlows bounds the sign-ins in progress. A flood evicts the oldest.
	MaxFlows = 1024
	// MaxCode and MaxNext bound what the callback and /login accept.
	MaxCode = 2048
	MaxNext = 512
	// MaxForm bounds a POST body.
	MaxForm = 4 << 10
	// discoveryRetry is how long a failed discovery is not retried: a stream of
	// /login requests must not become a stream of requests to the bridge.
	discoveryRetry = 10 * time.Second
	discoveryLimit = 10 * time.Second
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server is the web listener's handler.
type Server struct {
	Store *store.Store
	// Seal opens the stored client secret; nil serves public clients only.
	Seal *secretbox.Box
	// HTTP reaches the bridge (nil: a client that refuses redirects to cleartext
	// and times out).
	HTTP *http.Client
	Log  *slog.Logger
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// Zero fields mean the defaults.
	Idle, Abs, FlowTTL time.Duration
	// Repos serves the repository pages (nil: there are none).
	Repos *gitrepo.Service
	// Limiter caps the repository pages at once, in total and per reader
	// (nil: no cap).
	Limiter *gitrepo.Limiter

	mu     sync.Mutex
	client cachedClient
	flows  map[string]flowEntry
}

type cachedClient struct {
	cfg    store.OIDCClient
	c      *rp.Client
	err    error
	failed time.Time
}

// The templates and the stylesheet are part of the binary: a parse error is a
// build defect that the first test run shows, not a runtime condition.
var (
	tmpl = template.Must(template.ParseFS(assets, "templates/*.html"))
	css  = mustRead("static/style.css")
)

func mustRead(name string) []byte {
	b, err := assets.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

// Handler returns the listener's handler.
func (s *Server) Handler() http.Handler {
	if s.Log == nil {
		s.Log = slog.New(slog.DiscardHandler)
	}
	if s.HTTP == nil {
		s.HTTP = &http.Client{Timeout: discoveryLimit, CheckRedirect: redirect.CheckRedirect}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /callback", s.callback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /static/style.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(css)
	})
	s.routes(mux)
	return secure(mux)
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) idle() time.Duration { return orDefault(s.Idle, DefaultIdle) }
func (s *Server) abs() time.Duration  { return orDefault(s.Abs, DefaultAbs) }
func (s *Server) flowTTL() time.Duration {
	return orDefault(s.FlowTTL, DefaultFlowTTL)
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// CSP is the policy of every response: nothing but our own stylesheet, no
// script at all (inline or not), no framing, no base tag, forms only to us.
const CSP = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// secure adds the security headers to every response, including errors and
// the ones a handler writes before its first byte.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", CSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Strict-Transport-Security", "max-age=63072000")
		next.ServeHTTP(w, r)
	})
}

// token returns n random bytes, base64url without padding.
func token(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand does not fail (Go 1.24+: it crashes the program instead)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashID(v string) []byte {
	h := sha256.Sum256([]byte(v))
	return h[:]
}

// validToken reports whether v looks like what token(32) makes: the cookie
// value is checked for shape before it reaches a hash or the database.
func validToken(v string) bool {
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == 32
}

func eq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// cookie builds a __Host- cookie.
func cookie(name, value string, maxAge time.Duration) *http.Cookie {
	c := &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if maxAge < 0 {
		c.MaxAge = -1
	} else {
		c.MaxAge = int(maxAge / time.Second)
	}
	return c
}

// sessionFor reads the request's session. The second result is the stored id
// (hash), for logout and for ending the session a sign-in replaces.
func (s *Server) sessionFor(r *http.Request) (store.Session, []byte, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || !validToken(c.Value) {
		return store.Session{}, nil, false
	}
	id := hashID(c.Value)
	sess, err := s.Store.LookupSession(r.Context(), id, s.idle(), s.abs())
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.Log.Error("session lookup", "err", err)
		}
		return store.Session{}, id, false
	}
	return sess, id, true
}

// page renders a template. The body is buffered so a template error is a clean
// 500, never a half page.
func (s *Server) page(w http.ResponseWriter, code int, name string, data any) {
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, name, data); err != nil {
		s.Log.Error("template", "name", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(b.Bytes())
}

type homeData struct {
	Login string
	CSRF  string
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.sessionFor(r)
	d := homeData{}
	if ok {
		d.Login, d.CSRF = sess.Login, sess.CSRF
	}
	s.page(w, http.StatusOK, "home.html", d)
}
