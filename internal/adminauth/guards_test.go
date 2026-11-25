package adminauth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-vcs/forge/internal/adminauth"
)

// lenientCreds delegates to fakeCreds but lets a test decide what the counter
// store says, so the verifier's own checks are the only thing under test.
type lenientCreds struct {
	*fakeCreds
	advance func(uint32) error
	called  int
}

func (l *lenientCreds) AdvanceCounter(_ context.Context, _ []byte, n uint32) error {
	l.called++
	return l.advance(n)
}

func TestTheVerifierItselfRefusesACounterRegression(t *testing.T) {
	// The store also refuses a regression; here it does not, so only the
	// verifier's own comparison can stop the call.
	e := newEnv(t)
	l := &lenientCreds{fakeCreds: e.creds, advance: func(uint32) error { return nil }}
	e.v.Credentials = l
	e.creds.c[string(e.auth.CredID)].SignCount = 10
	e.auth.Counter = 5
	e.auth.FreezeCount = true
	wantErr(t, mustFail(e.v.Verify(context.Background(), e.good(t))), adminauth.ErrCounterRegression)
	if l.called != 0 {
		t.Fatal("the counter was advanced for a refused assertion")
	}
}

func TestACounterStoreFailureRefusesTheCall(t *testing.T) {
	e := newEnv(t)
	boom := errors.New("disk full")
	e.v.Credentials = &lenientCreds{fakeCreds: e.creds, advance: func(uint32) error { return boom }}
	cred, err := e.v.Verify(context.Background(), e.good(t))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the store's error: an assertion whose counter cannot be recorded must not be accepted", err)
	}
	if cred.ID != nil {
		t.Fatal("a credential came back with the error")
	}
}

func TestANonceLongerThanIssuedIsNotItsPrefix(t *testing.T) {
	// A token longer than NonceLen must not be truncated into a valid one.
	e := newEnv(t)
	in := e.good(t)
	in.Nonce = append(append([]byte(nil), in.Nonce...), 0)
	wantErr(t, mustFail(e.v.Verify(context.Background(), in)), adminauth.ErrNonceUnknown)
}
