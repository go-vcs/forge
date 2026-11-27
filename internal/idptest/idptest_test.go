// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package idptest_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-vcs/forge/internal/idptest"
)

const verifier = "a-code-verifier-of-sufficient-length-0123456789"

func challenge(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func newIdP(t *testing.T) (*idptest.IdP, *http.Client) {
	p := idptest.New(t)
	p.Redirect = "https://forge.example/callback"
	c := &http.Client{Transport: p.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return p, c
}

func authQuery(p *idptest.IdP) url.Values {
	return url.Values{"client_id": {p.ClientID}, "redirect_uri": {p.Redirect}, "response_type": {"code"},
		"code_challenge_method": {"S256"}, "code_challenge": {challenge(verifier)}, "state": {"st"}, "nonce": {"n"}}
}

// code runs a good authorization request and returns the code it issued.
func code(t *testing.T, p *idptest.IdP, c *http.Client) string {
	t.Helper()
	r, err := c.Get(p.Issuer + "/authorize?" + authQuery(p).Encode())
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	u, err := url.Parse(r.Header.Get("Location"))
	if r.StatusCode != http.StatusFound || err != nil || u.Query().Get("code") == "" {
		t.Fatalf("authorize = %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	return u.Query().Get("code")
}

func exchange(t *testing.T, p *idptest.IdP, c *http.Client, form url.Values) int {
	t.Helper()
	req, _ := http.NewRequest("POST", p.Issuer+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.Secret))
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	return r.StatusCode
}

func TestAuthorizeRefusesABadRequest(t *testing.T) {
	for name, mut := range map[string]func(url.Values){
		"client":    func(q url.Values) { q.Set("client_id", "other") },
		"redirect":  func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		"response":  func(q url.Values) { q.Set("response_type", "token") },
		"method":    func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"challenge": func(q url.Values) { q.Del("code_challenge") },
	} {
		t.Run(name, func(t *testing.T) {
			p, c := newIdP(t)
			q := authQuery(p)
			mut(q)
			r, err := c.Get(p.Issuer + "/authorize?" + q.Encode())
			if err != nil {
				t.Fatal(err)
			}
			r.Body.Close()
			if r.StatusCode != http.StatusBadRequest {
				t.Fatalf("authorize = %d, want 400", r.StatusCode)
			}
		})
	}
}

func TestTokenEndpointEnforcesTheGrant(t *testing.T) {
	good := func(c string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {c}, "redirect_uri": {"https://forge.example/callback"},
			"code_verifier": {verifier}}
	}
	for name, mut := range map[string]func(url.Values){
		"grant type":   func(f url.Values) { f.Set("grant_type", "password") },
		"unknown code": func(f url.Values) { f.Set("code", "nope") },
		"redirect":     func(f url.Values) { f.Set("redirect_uri", "https://evil.example/cb") },
		"verifier":     func(f url.Values) { f.Set("code_verifier", verifier+"x") },
		"no verifier":  func(f url.Values) { f.Del("code_verifier") },
	} {
		t.Run(name, func(t *testing.T) {
			p, c := newIdP(t)
			f := good(code(t, p, c))
			mut(f)
			if got := exchange(t, p, c, f); got != http.StatusBadRequest {
				t.Fatalf("token = %d, want 400", got)
			}
		})
	}
	t.Run("a code is single-use", func(t *testing.T) {
		p, c := newIdP(t)
		f := good(code(t, p, c))
		if got := exchange(t, p, c, f); got != http.StatusOK {
			t.Fatalf("first exchange = %d", got)
		}
		if got := exchange(t, p, c, f); got != http.StatusBadRequest {
			t.Fatalf("replayed exchange = %d, want 400", got)
		}
	})
}
