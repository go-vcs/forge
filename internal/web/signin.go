// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-authn/rp"

	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/secretbox"
	"github.com/go-vcs/forge/internal/store"
)

type flowEntry struct {
	flow    rp.Flow
	next    string
	expires time.Time
}

// oidcClient returns the rp client for the stored registration, discovering the
// bridge when the registration changed. A failed discovery is remembered for a
// few seconds.
func (s *Server) oidcClient(ctx context.Context) (*rp.Client, error) {
	cfg, err := s.Store.GetOIDCClient(ctx)
	if err != nil { // store.ErrNotFound when nothing is registered
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := &s.client
	if sameClient(cur.cfg, cfg) {
		if cur.c != nil {
			return cur.c, nil
		}
		if s.now().Sub(cur.failed) < discoveryRetry {
			return nil, cur.err
		}
	}
	*cur = cachedClient{cfg: cfg}
	cur.c, cur.err = s.discover(ctx, cfg)
	if cur.err != nil {
		cur.failed = s.now()
	}
	return cur.c, cur.err
}

func sameClient(a, b store.OIDCClient) bool {
	return a.Issuer == b.Issuer && a.ClientID == b.ClientID && a.RedirectURI == b.RedirectURI &&
		a.UpdatedAt.Equal(b.UpdatedAt) && bytes.Equal(a.SecretSealed, b.SecretSealed)
}

func (s *Server) discover(ctx context.Context, cfg store.OIDCClient) (*rp.Client, error) {
	var secret string
	if len(cfg.SecretSealed) > 0 {
		if s.Seal == nil {
			return nil, secretbox.ErrNoKey
		}
		b, err := s.Seal.Open(cfg.SecretSealed, adminsrv.OIDCSecretPurpose)
		if err != nil {
			return nil, err
		}
		secret = string(b)
	}
	p, err := rp.Discover(ctx, s.HTTP, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	return rp.NewClient(ctx, p, rp.Config{ClientID: cfg.ClientID, Secret: secret, RedirectURI: cfg.RedirectURI})
}

// safeNext accepts only a path on this server: it starts with one "/", has no
// second "/" or "\" after it (a scheme-relative URL), no control character, and
// is not one of the sign-in endpoints.
func safeNext(n string) string {
	if n == "" || len(n) > MaxNext || !utf8.ValidString(n) || n[0] != '/' {
		return ""
	}
	if len(n) > 1 && (n[1] == '/' || n[1] == '\\') {
		return ""
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return ""
		}
	}
	// What is left starts with one "/" and a character that is not "/" or "\":
	// it has no scheme and no host, so only a malformed escape can still fail.
	if _, err := url.Parse(n); err != nil {
		return ""
	}
	if n == "/login" || n == "/callback" || strings.HasPrefix(n, "/login?") || strings.HasPrefix(n, "/callback?") {
		return ""
	}
	return n
}

// addFlow stores a sign-in in progress and returns the cookie value that finds
// it again. Expired flows go first; past MaxFlows the oldest goes.
func (s *Server) addFlow(f rp.Flow, next string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.flows == nil {
		s.flows = map[string]flowEntry{}
	}
	for k, e := range s.flows {
		if !now.Before(e.expires) {
			delete(s.flows, k)
		}
	}
	for len(s.flows) >= MaxFlows {
		var oldest string
		for k, e := range s.flows {
			if oldest == "" || e.expires.Before(s.flows[oldest].expires) {
				oldest = k
			}
		}
		delete(s.flows, oldest)
	}
	id := token(32)
	s.flows[id] = flowEntry{flow: f, next: next, expires: now.Add(s.flowTTL())}
	return id
}

// takeFlow removes and returns the flow: a flow is single-use, whatever the
// callback then decides.
func (s *Server) takeFlow(id string) (flowEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.flows[id]
	delete(s.flows, id)
	return e, ok && s.now().Before(e.expires)
}

type errorData struct{ Title, Message string }

// refuse is the one page of every failed sign-in, whatever the reason.
func (s *Server) refuse(w http.ResponseWriter, reason string, err error) {
	s.Log.Warn("sign-in refused", "reason", reason, "err", err)
	http.SetCookie(w, cookie(FlowCookie, "", -1))
	s.page(w, http.StatusForbidden, "error.html", errorData{"Sign-in refused", "This sign-in was refused."})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	c, err := s.oidcClient(r.Context())
	if err != nil {
		s.Log.Error("oidc client", "err", err)
		s.page(w, http.StatusServiceUnavailable, "error.html", errorData{"Sign-in unavailable", "Sign-in is not available now."})
		return
	}
	flow := rp.NewFlow()
	id := s.addFlow(flow, safeNext(r.URL.Query().Get("next")))
	http.SetCookie(w, cookie(FlowCookie, id, s.flowTTL()))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, c.AuthCodeURL(flow, nil), http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	// The flow is consumed first: a callback that fails cannot be retried.
	var (
		e  flowEntry
		ok bool
	)
	if fc, err := r.Cookie(FlowCookie); err == nil && validToken(fc.Value) {
		e, ok = s.takeFlow(fc.Value)
	}
	if !ok {
		s.refuse(w, "no flow for this browser", nil)
		return
	}
	q := r.URL.Query()
	if q.Has("error") {
		s.refuse(w, "the bridge refused", nil)
		return
	}
	c, err := s.oidcClient(r.Context())
	if err != nil {
		s.refuse(w, "no client", err)
		return
	}
	if err := c.CheckIssuer(q); err != nil { // RFC 9207
		s.refuse(w, "issuer mix-up", err)
		return
	}
	code := q.Get("code")
	if len(q["state"]) != 1 || !eq(q.Get("state"), e.flow.State) || len(q["code"]) != 1 || code == "" || len(code) > MaxCode {
		s.refuse(w, "state or code", nil)
		return
	}
	_, id, err := c.Exchange(r.Context(), code, e.flow)
	if err != nil {
		s.refuse(w, "exchange", err)
		return
	}
	// Only (issuer, subject) is read: no e-mail, no preferred_username. The
	// issuer is the registered one by construction: the client discovered the
	// registered issuer and Exchange verified the token against that document.
	if _, err := s.Store.LoginForIdentity(r.Context(), id.Issuer(), id.Subject()); err != nil {
		s.refuse(w, "unbound or disabled identity", err)
		return
	}
	// Rotation: a new id at every sign-in, and the one the browser held, if any,
	// ends. The old session is never read as a source of identity.
	if old, err := r.Cookie(SessionCookie); err == nil && validToken(old.Value) {
		if err := s.Store.DeleteSession(r.Context(), hashID(old.Value)); err != nil {
			s.refuse(w, "ending the previous session", err)
			return
		}
	}
	if err := s.Store.PurgeSessions(r.Context(), s.idle(), s.abs()); err != nil {
		s.refuse(w, "purge", err)
		return
	}
	sid := token(32)
	if err := s.Store.CreateSession(r.Context(), hashID(sid), token(32), id.Issuer(), id.Subject()); err != nil {
		s.refuse(w, "session", err)
		return
	}
	http.SetCookie(w, cookie(FlowCookie, "", -1))
	http.SetCookie(w, cookie(SessionCookie, sid, s.abs()))
	w.Header().Set("Cache-Control", "no-store")
	next := e.next
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxForm)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sess, id, ok := s.sessionFor(r)
	if ok {
		if !eq(r.PostForm.Get("csrf"), sess.CSRF) {
			s.page(w, http.StatusForbidden, "error.html", errorData{"Refused", "The request carried no valid token."})
			return
		}
		if err := s.Store.DeleteSession(r.Context(), id); err != nil {
			s.Log.Error("logout", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	http.SetCookie(w, cookie(SessionCookie, "", -1))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
