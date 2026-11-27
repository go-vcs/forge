// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package web_test

import (
	"crypto/sha256"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-vcs/forge/internal/store"
	"github.com/go-vcs/forge/internal/web"
)

func findCookie(r *http.Response, name string) *http.Cookie {
	for _, c := range r.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestSignInHappyPath(t *testing.T) {
	e := newEnv(t)
	a, r := e.startLogin("")
	if r.StatusCode != http.StatusFound {
		t.Fatalf("login = %d", r.StatusCode)
	}
	fc := findCookie(r, web.FlowCookie)
	if fc == nil || !fc.Secure || !fc.HttpOnly || fc.SameSite != http.SameSiteLaxMode || fc.Path != "/" || fc.Domain != "" ||
		fc.MaxAge != int(web.DefaultFlowTTL/time.Second) {
		t.Fatalf("flow cookie %+v", fc)
	}
	// the authorization request: code + PKCE S256, state, nonce, our client and redirect
	u, _ := url.Parse(a)
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 ||
		len(q.Get("state")) < 43 || len(q.Get("nonce")) < 43 || q.Get("client_id") != "forge" ||
		q.Get("redirect_uri") != e.ts.URL+"/callback" || q.Get("scope") != "openid" {
		t.Fatalf("authorization request %v", q)
	}
	if strings.Contains(a, "s3cret") || q.Get("code_verifier") != "" {
		t.Fatal("a secret is in the authorization URL")
	}
	cb := e.authorize(a)
	r = get(t, e.b, cb)
	body(t, r)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/" {
		t.Fatalf("callback = %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	sc := findCookie(r, web.SessionCookie)
	if sc == nil || !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.Domain != "" ||
		sc.MaxAge != int(web.DefaultAbs/time.Second) || len(sc.Value) != 43 {
		t.Fatalf("session cookie %+v", sc)
	}
	if !strings.HasPrefix(sc.Name, "__Host-") {
		t.Fatal("cookie is not __Host-")
	}
	if fc := findCookie(r, web.FlowCookie); fc == nil || fc.MaxAge != -1 {
		t.Fatalf("flow cookie not cleared: %+v", fc)
	}
	// only the hash is stored
	h := sha256.Sum256([]byte(sc.Value))
	if _, err := e.st.LookupSession(t.Context(), h[:], time.Hour, time.Hour); err != nil {
		t.Fatalf("session not stored under the hash: %v", err)
	}
	if _, err := e.st.LookupSession(t.Context(), []byte(sc.Value), time.Hour, time.Hour); err == nil {
		t.Fatal("session stored under the cookie value itself")
	}
	if h := e.home(); !strings.Contains(h, "alice") || !strings.Contains(h, `action="/logout"`) {
		t.Fatalf("home after sign-in:\n%s", h)
	}
	// the bridge saw a confidential client: secret by Basic (enforced by the fake), verifier sent
	tr := e.idp.TokenReq
	if len(tr) != 1 || tr[0].Get("code_verifier") == "" || tr[0].Get("client_secret") != "" {
		t.Fatalf("token request %v", tr)
	}
}

func TestSignInRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		prep func(e *env)
	}{
		{"nonce of another login", func(e *env) { e.idp.BadNonce = true }},
		{"ID token for another issuer", func(e *env) { e.idp.WrongIssuer = true }},
		{"ID token for another audience", func(e *env) { e.idp.WrongAudience = true }},
		{"expired ID token", func(e *env) { e.idp.Expired = true }},
		{"alg none", func(e *env) { e.idp.Alg = "none" }},
		{"alg HS256 keyed with the public key", func(e *env) { e.idp.Alg = "HS256" }},
		{"no ID token", func(e *env) { e.idp.NoIDToken = true }},
		{"authorization response from another issuer (RFC 9207)", func(e *env) { e.idp.IssParam = "https://evil.example" }},
		{"unbound subject", func(e *env) { e.idp.Sub = "mallory-sub" }},
		{"unbound subject whose e-mail and username are alice's", func(e *env) {
			e.idp.Sub, e.idp.Email, e.idp.Username = "mallory-sub", "alice@example.org", "alice"
		}},
		{"a client secret the bridge does not know", func(e *env) { e.idp.Secret = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.prep(e)
			r, b := e.signIn()
			if r.StatusCode != http.StatusForbidden || !strings.Contains(b, "Sign-in refused") {
				t.Fatalf("callback = %d\n%s", r.StatusCode, b)
			}
			// the page is the same, the log is not: it names the step that refused
			reason := "exchange"
			switch {
			case strings.HasPrefix(tc.name, "authorization response"):
				reason = "issuer mix-up"
			case strings.HasPrefix(tc.name, "unbound"):
				reason = "unbound or disabled identity"
			}
			if !strings.Contains(e.logs.String(), `reason="`+reason+`"`) && !strings.Contains(e.logs.String(), "reason="+reason) {
				t.Errorf("log does not say %q:\n%s", reason, e.logs)
			}
			if findCookie(r, web.SessionCookie) != nil || e.isSignedIn() || e.sessions() != 0 {
				t.Fatal("a session exists after a refused sign-in")
			}
			if us, _ := e.st.ListUsers(t.Context()); len(us) != 1 {
				t.Fatalf("%d accounts: a sign-in created one", len(us))
			}
		})
	}
}

// Every refusal is the same page: the reason is not an oracle.
func TestEveryRefusalLooksTheSame(t *testing.T) {
	var pages []string
	for _, prep := range []func(*env){
		func(e *env) { e.idp.Sub = "mallory-sub" },
		func(e *env) { e.idp.BadNonce = true },
		func(e *env) { e.idp.Alg = "none" },
	} {
		e := newEnv(t)
		prep(e)
		_, b := e.signIn()
		pages = append(pages, b)
	}
	for _, p := range pages[1:] {
		if p != pages[0] {
			t.Fatalf("refusals differ:\n%s\n----\n%s", pages[0], p)
		}
	}
}

func TestDisabledAccountCannotSignIn(t *testing.T) {
	e := newEnv(t)
	if err := e.st.DisableUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	r, _ := e.signIn()
	if r.StatusCode != http.StatusForbidden || e.sessions() != 0 {
		t.Fatalf("disabled account: %d, %d sessions", r.StatusCode, e.sessions())
	}
}

func TestCallbackStateAndCodeChecks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mangle func(q url.Values)
	}{
		{"state of another login", func(q url.Values) { q.Set("state", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") }},
		{"no state", func(q url.Values) { q.Del("state") }},
		{"two states", func(q url.Values) { q.Add("state", q.Get("state")) }},
		{"no code", func(q url.Values) { q.Del("code") }},
		{"two codes", func(q url.Values) { q.Add("code", q.Get("code")) }},
		{"huge code", func(q url.Values) { q.Set("code", strings.Repeat("a", web.MaxCode+1)) }},
		{"an error from the bridge", func(q url.Values) { q.Set("error", "access_denied") }},
		{"two iss", func(q url.Values) { q.Add("iss", q.Get("iss")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			a, _ := e.startLogin("")
			cb, _ := url.Parse(e.authorize(a))
			q := cb.Query()
			tc.mangle(q)
			cb.RawQuery = q.Encode()
			r := get(t, e.b, cb.String())
			body(t, r)
			if r.StatusCode != http.StatusForbidden || e.sessions() != 0 {
				t.Fatalf("got %d, %d sessions", r.StatusCode, e.sessions())
			}
		})
	}
}

// A callback needs the browser that started the login (login CSRF), and a
// flow is used once.
func TestFlowIsBoundToTheBrowserAndSingleUse(t *testing.T) {
	e := newEnv(t)
	a, _ := e.startLogin("")
	cb := e.authorize(a)
	other := e.newBrowser() // the attacker's code delivered to the victim, or the reverse
	r := get(t, other, cb)
	body(t, r)
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("callback from another browser = %d", r.StatusCode)
	}
	// the victim's flow was not consumed by the attacker's request
	r = get(t, e.b, cb)
	body(t, r)
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("the real browser's callback = %d", r.StatusCode)
	}
	// replay
	r = get(t, e.b, cb)
	body(t, r)
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("a replayed callback = %d", r.StatusCode)
	}
	// a cookie of the wrong shape, and one that is unknown
	for _, v := range []string{"x", strings.Repeat("A", 43)} {
		req, _ := http.NewRequest("GET", cb, nil)
		req.AddCookie(&http.Cookie{Name: web.FlowCookie, Value: v})
		resp, err := e.ts.Client().Transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("flow cookie %q = %d", v, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestFlowExpires(t *testing.T) {
	e := newEnv(t)
	a, _ := e.startLogin("")
	cb := e.authorize(a)
	e.clk.Add(web.DefaultFlowTTL)
	r := get(t, e.b, cb)
	body(t, r)
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("a flow at its TTL = %d", r.StatusCode)
	}
	a, _ = e.startLogin("")
	cb = e.authorize(a)
	e.clk.Add(web.DefaultFlowTTL - time.Second)
	r = get(t, e.b, cb)
	body(t, r)
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("a flow one second before its TTL = %d", r.StatusCode)
	}
}

func TestFlowsAreBounded(t *testing.T) {
	e := newEnv(t)
	first, _ := e.startLogin("")
	firstCB := e.authorize(first)
	for range web.MaxFlows + 20 {
		e.clk.Add(time.Millisecond) // later flows expire later: the first is the oldest
		e.startLogin("")
	}
	if n := e.srv.FlowCount(); n > web.MaxFlows {
		t.Fatalf("%d flows held, bound is %d", n, web.MaxFlows)
	}
	// an attacker's flood evicted the oldest: the first browser's login now fails
	r := get(t, e.b, firstCB)
	body(t, r)
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("an evicted flow = %d", r.StatusCode)
	}
}

func TestExpiredFlowsAreSweptBeforeLiveOnesAreEvicted(t *testing.T) {
	e := newEnv(t)
	for range 10 {
		e.startLogin("")
	}
	e.clk.Add(web.DefaultFlowTTL)
	e.startLogin("")
	if n := e.srv.FlowCount(); n != 1 {
		t.Fatalf("%d flows held after the others expired, want 1", n)
	}
}

// Signing in while signed in neither links the new identity to the session nor
// uses it, and a refused sign-in leaves the session alone.
func TestSignInNeverLinksToASignedInSession(t *testing.T) {
	e := newEnv(t)
	e.signedIn()
	before, _ := e.st.ListIdentities(t.Context(), "")
	e.idp.Sub = "mallory-sub"
	r, _ := e.signIn()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("an unbound identity while signed in = %d", r.StatusCode)
	}
	after, _ := e.st.ListIdentities(t.Context(), "")
	if len(after) != len(before) || len(after) != 1 || after[0].Subject != "alice-sub" {
		t.Fatalf("identities changed: %v -> %v", before, after)
	}
	if !e.isSignedIn() {
		t.Fatal("a refused sign-in ended the session")
	}
}

func TestSessionIsRotatedAtSignIn(t *testing.T) {
	e := newEnv(t)
	e.signedIn()
	old := e.cookieValue(web.SessionCookie)
	e.signedIn()
	now := e.cookieValue(web.SessionCookie)
	if old == "" || now == "" || old == now {
		t.Fatalf("session id not rotated: %q -> %q", old, now)
	}
	if e.sessions() != 1 {
		t.Fatalf("%d sessions after a second sign-in, want the old one ended", e.sessions())
	}
	// the old id is dead
	req, _ := http.NewRequest("GET", e.ts.URL+"/", nil)
	req.AddCookie(&http.Cookie{Name: web.SessionCookie, Value: old})
	resp, err := e.ts.Client().Transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); strings.Contains(b, "alice") {
		t.Fatal("the replaced session id still works")
	}
	// a session id the browser fixed before login is never adopted
	fixed := strings.Repeat("B", 43)
	e2 := newEnv(t)
	u, _ := url.Parse(e2.ts.URL)
	e2.jar.SetCookies(u, []*http.Cookie{{Name: web.SessionCookie, Value: fixed, Path: "/", Secure: true}})
	e2.signedIn()
	if v := e2.cookieValue(web.SessionCookie); v == fixed || v == "" {
		t.Fatalf("a planted session id was kept: %q", v)
	}
}

func TestSessionLifetime(t *testing.T) {
	e := newEnv(t)
	e.signedIn()
	e.clk.Add(web.DefaultIdle - time.Second)
	if !e.isSignedIn() {
		t.Fatal("signed out just before the idle limit")
	}
	e.clk.Add(web.DefaultIdle) // idle for exactly the limit
	if e.isSignedIn() {
		t.Fatal("still signed in after the idle limit")
	}
	e.signedIn()
	for e.clk.Now().Sub(epoch) < web.DefaultAbs-web.DefaultIdle/2 { // keep it active
		e.clk.Add(web.DefaultIdle / 2)
		if !e.isSignedIn() {
			t.Fatalf("signed out at +%v, before the absolute limit", e.clk.Now().Sub(epoch))
		}
	}
	e.clk.Add(web.DefaultAbs) // far past
	if e.isSignedIn() {
		t.Fatal("an active session outlived the absolute limit")
	}
}

func TestSessionsDieWithTheAccount(t *testing.T) {
	e := newEnv(t)
	e.signedIn()
	if err := e.st.DisableUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	if e.isSignedIn() {
		t.Fatal("a disabled account's session lives")
	}
	e = newEnv(t)
	e.signedIn()
	if err := e.st.UnbindIdentity(t.Context(), e.idp.Issuer, "alice-sub"); err != nil {
		t.Fatal(err)
	}
	if e.isSignedIn() {
		t.Fatal("a session outlived the unbinding of its identity")
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	e.signedIn()
	csrf := csrfOf(t, e.home())
	// a GET is not a logout
	r := get(t, e.b, e.ts.URL+"/logout")
	body(t, r)
	if r.StatusCode != http.StatusMethodNotAllowed || !e.isSignedIn() {
		t.Fatalf("GET /logout = %d", r.StatusCode)
	}
	for name, form := range map[string]url.Values{
		"no token":    {},
		"wrong token": {"csrf": {strings.Repeat("A", 43)}},
		"empty token": {"csrf": {""}},
		"prefix only": {"csrf": {csrf[:10]}},
	} {
		r := e.post("/logout", form)
		body(t, r)
		if r.StatusCode != http.StatusForbidden || !e.isSignedIn() || e.sessions() != 1 {
			t.Fatalf("%s: %d, signed in %v", name, r.StatusCode, e.isSignedIn())
		}
	}
	r = e.post("/logout", url.Values{"csrf": {csrf}})
	body(t, r)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/" {
		t.Fatalf("logout = %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if c := findCookie(r, web.SessionCookie); c == nil || c.MaxAge != -1 {
		t.Fatalf("session cookie not cleared: %+v", c)
	}
	if e.isSignedIn() || e.sessions() != 0 {
		t.Fatal("the session lives after logout")
	}
	// idempotent, and no token needed when there is no session
	r = e.post("/logout", url.Values{})
	body(t, r)
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout without a session = %d", r.StatusCode)
	}
	// the token of one session does not log out another
	e.signedIn()
	r = e.post("/logout", url.Values{"csrf": {csrf}})
	body(t, r)
	if r.StatusCode != http.StatusForbidden || !e.isSignedIn() {
		t.Fatalf("a token of an ended session = %d", r.StatusCode)
	}
}

func TestLogoutBodyIsBounded(t *testing.T) {
	e := newEnv(t)
	e.signedIn()
	r := e.post("/logout", url.Values{"csrf": {strings.Repeat("a", web.MaxForm)}})
	body(t, r)
	if r.StatusCode != http.StatusBadRequest || !e.isSignedIn() {
		t.Fatalf("oversized form = %d", r.StatusCode)
	}
}

func csrfOf(t *testing.T, page string) string {
	t.Helper()
	const mark = `name="csrf" value="`
	i := strings.Index(page, mark)
	if i < 0 {
		t.Fatalf("no csrf field in\n%s", page)
	}
	rest := page[i+len(mark):]
	return rest[:strings.Index(rest, `"`)]
}

func TestNextIsOnlyALocalPath(t *testing.T) {
	for next, want := range map[string]string{
		"":                                     "/",
		"/alice/repo":                          "/alice/repo",
		"/alice/repo/tree/a?b=c":               "/alice/repo/tree/a?b=c",
		"//evil.example":                       "/",
		"/\\evil.example":                      "/",
		"https://evil.example":                 "/",
		"evil":                                 "/",
		"/a\nb":                                "/",
		"/login":                               "/",
		"/callback?x=1":                        "/",
		"/" + strings.Repeat("a", web.MaxNext): "/",
	} {
		e := newEnv(t)
		a, _ := e.startLogin(next)
		r := get(t, e.b, e.authorize(a))
		body(t, r)
		if r.Header.Get("Location") != want {
			t.Errorf("next %q -> %q, want %q", next, r.Header.Get("Location"), want)
		}
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/":                                      "/",
		"/a":                                     "/a",
		"/a b":                                   "/a b",
		"//":                                     "",
		"/\\":                                    "",
		"/a\\b":                                  "",
		"/a\x7f":                                 "",
		"/\xff":                                  "",
		"/login":                                 "",
		"/login?x":                               "",
		"/loginx":                                "/loginx",
		"/callback":                              "",
		"/callback?x":                            "",
		"/callbackx":                             "/callbackx",
		"/:":                                     "/:",
		"/%zz":                                   "",
		"/%41":                                   "/%41",
		"/" + strings.Repeat("a", web.MaxNext-1): "/" + strings.Repeat("a", web.MaxNext-1),
	} {
		if got := web.SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSignInUnavailable(t *testing.T) {
	t.Run("no secrets key for a stored secret", func(t *testing.T) {
		e := newEnv(t)
		e.srv.Seal = nil
		_, r := e.startLogin("")
		if r.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("login = %d", r.StatusCode)
		}
	})
	t.Run("a sealed secret that does not open", func(t *testing.T) {
		e := newEnv(t)
		if err := e.st.SetOIDCClient(t.Context(), store.OIDCClient{Issuer: e.idp.Issuer, ClientID: "forge",
			RedirectURI: e.ts.URL + "/callback", SecretSealed: []byte("not a sealed secret at all, no")}); err != nil {
			t.Fatal(err)
		}
		_, r := e.startLogin("")
		if r.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("login = %d", r.StatusCode)
		}
	})
	t.Run("a bridge that publishes no S256", func(t *testing.T) {
		e := newEnv(t)
		e.idp.NoS256 = true
		_, r := e.startLogin("")
		if r.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("login = %d", r.StatusCode)
		}
	})
	t.Run("a bridge whose discovery names another issuer", func(t *testing.T) {
		e := newEnv(t)
		e.idp.DiscoveryIss = "https://other.example"
		_, r := e.startLogin("")
		if r.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("login = %d", r.StatusCode)
		}
	})
}

func httpGet(h http.Handler, path string) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w.Code
}

func TestNoRegistrationMeansNoSignIn(t *testing.T) {
	// a fresh store with no registration at all
	st, err := store.Open(t.Context(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	logs := &logBuf{}
	srv := &web.Server{Store: st, Log: slog.New(slog.NewTextHandler(logs, nil))}
	h := srv.Handler()
	defer func() {
		// the cause is the store's own: nothing registered, not a discovery failure
		if !strings.Contains(logs.String(), "not found") {
			t.Errorf("log does not say nothing is registered:\n%s", logs)
		}
	}()
	for _, p := range []string{"/login", "/callback"} {
		w := httpGet(h, p)
		want := http.StatusServiceUnavailable
		if p == "/callback" {
			want = http.StatusForbidden
		}
		if w != want {
			t.Errorf("%s with no registration = %d, want %d", p, w, want)
		}
	}
}

// A failed discovery is not retried for a few seconds, then it is.
func TestDiscoveryFailureIsRememberedBriefly(t *testing.T) {
	e := newEnv(t)
	e.idp.NoS256 = true
	if _, r := e.startLogin(""); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("login = %d", r.StatusCode)
	}
	e.idp.NoS256 = false
	e.clk.Add(9 * time.Second)
	if _, r := e.startLogin(""); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("login after 9 s = %d: the failure was not remembered", r.StatusCode)
	}
	e.clk.Add(time.Second)
	if _, r := e.startLogin(""); r.StatusCode != http.StatusFound {
		t.Fatalf("login after 10 s = %d: the failure was remembered too long", r.StatusCode)
	}
}

// A new registration is used by the next login without a restart.
func TestChangedRegistrationIsPickedUp(t *testing.T) {
	e := newEnv(t)
	if _, r := e.startLogin(""); r.StatusCode != http.StatusFound {
		t.Fatalf("login = %d", r.StatusCode)
	}
	e.clk.Add(time.Second)
	e.register(e.idp.Issuer, "another-client", e.idp.Secret)
	a, r := e.startLogin("")
	if r.StatusCode != http.StatusFound || !strings.Contains(a, "client_id=another-client") {
		t.Fatalf("the new client_id was not used: %q", a)
	}
}

func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	signedInPaths := []string{"/", "/login", "/callback", "/static/style.css", "/nowhere", "/logout"}
	for _, p := range signedInPaths {
		r := get(t, e.b, e.ts.URL+p)
		body(t, r)
		h := r.Header
		if h.Get("Content-Security-Policy") != web.CSP || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Frame-Options") != "DENY" ||
			h.Get("Strict-Transport-Security") == "" || h.Get("Cross-Origin-Opener-Policy") != "same-origin" ||
			h.Get("Cross-Origin-Resource-Policy") != "same-origin" {
			t.Errorf("%s (%d): headers %v", p, r.StatusCode, h)
		}
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "script-src", "*"} {
		if strings.Contains(web.CSP, bad) {
			t.Errorf("CSP contains %q", bad)
		}
	}
	r := get(t, e.b, e.ts.URL+"/static/style.css")
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/css") || !strings.Contains(body(t, r), "body") {
		t.Fatalf("stylesheet served as %q", ct)
	}
	if r := get(t, e.b, e.ts.URL+"/static/"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("/static/ = %d: no directory listing", r.StatusCode)
	}
}

func TestPagesHaveNoInlineScriptOrStyle(t *testing.T) {
	e := newEnv(t)
	e.signedIn()
	pages := []string{e.home()}
	r, _ := e.startLogin("")
	_ = r
	for _, b := range pages {
		for _, bad := range []string{"<script", " onclick", " style=", "<style", "javascript:"} {
			if strings.Contains(strings.ToLower(b), bad) {
				t.Errorf("page contains %q:\n%s", bad, b)
			}
		}
	}
}
