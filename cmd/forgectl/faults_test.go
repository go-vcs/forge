//go:build unix

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminclient"
	"github.com/go-vcs/forge/internal/fidotest"
)

// faultyForge opens sessions and hands out nonces, and fails everything else
// with a message naming the call, so that a test can tell which failure a
// command reported.
type faultyForge struct {
	adminv1.UnimplementedAdminServiceServer
	openFails bool
}

func boom(call string) error { return status.Error(codes.Internal, "boom-"+call) }

func (f *faultyForge) GetNonce(context.Context, *adminv1.GetNonceRequest) (*adminv1.GetNonceResponse, error) {
	return &adminv1.GetNonceResponse{Nonce: []byte("n")}, nil
}

func (f *faultyForge) OpenSession(context.Context, *adminv1.OpenSessionRequest) (*adminv1.OpenSessionResponse, error) {
	if f.openFails {
		return nil, boom("open")
	}
	return &adminv1.OpenSessionResponse{SessionToken: []byte("tok")}, nil
}

func (f *faultyForge) ListAdminCredentials(context.Context, *adminv1.ListAdminCredentialsRequest) (*adminv1.ListAdminCredentialsResponse, error) {
	return nil, boom("listcreds")
}

func (f *faultyForge) RevokeAdminCredential(context.Context, *adminv1.RevokeAdminCredentialRequest) (*adminv1.RevokeAdminCredentialResponse, error) {
	return nil, boom("revoke")
}

func (f *faultyForge) CreateUser(context.Context, *adminv1.CreateUserRequest) (*adminv1.CreateUserResponse, error) {
	return nil, boom("create")
}

func (f *faultyForge) ListUsers(context.Context, *adminv1.ListUsersRequest) (*adminv1.ListUsersResponse, error) {
	return nil, boom("listusers")
}

func (f *faultyForge) DisableUser(context.Context, *adminv1.DisableUserRequest) (*adminv1.DisableUserResponse, error) {
	return nil, boom("disable")
}

func (f *faultyForge) BindIdentity(context.Context, *adminv1.BindIdentityRequest) (*adminv1.BindIdentityResponse, error) {
	return nil, boom("bind")
}

func (f *faultyForge) ListIdentities(context.Context, *adminv1.ListIdentitiesRequest) (*adminv1.ListIdentitiesResponse, error) {
	return nil, boom("listids")
}

func (f *faultyForge) UnbindIdentity(context.Context, *adminv1.UnbindIdentityRequest) (*adminv1.UnbindIdentityResponse, error) {
	return nil, boom("unbind")
}

// faultyRig is a forgectl invocation against a faultyForge.
type faultyRig struct {
	f      *faultyForge
	args   []string // the global flags
	credID []byte
}

func newFaultyRig(t *testing.T) *faultyRig {
	t.Helper()
	dir := t.TempDir()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "faulty"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &faultyForge{}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}, MinVersion: tls.VersionTLS13,
	})))
	adminv1.RegisterAdminServiceServer(s, f)
	go func() { _ = s.Serve(l) }()
	t.Cleanup(s.Stop)

	auth := fidotest.New(fidotest.YubiKeyBioAAGUID)
	if _, _, _, err := auth.Make(t.Context(), rpID, nil, "k", [32]byte{}); err != nil {
		t.Fatal(err)
	}
	old := openSigner
	openSigner = func(context.Context) (adminclient.Signer, error) { return auth, nil }
	t.Cleanup(func() { openSigner = old })
	return &faultyRig{f: f, credID: auth.CredID, args: []string{
		"--server", l.Addr().String(), "--ca-file", ca, "--rp-id", rpID, "--credential-id", hex.EncodeToString(auth.CredID),
	}}
}

func (r *faultyRig) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	rg := &rig{t: t}
	return rg.run(append(append([]string(nil), r.args...), args...)...)
}

func TestServerFailuresAreReportedNotPrinted(t *testing.T) {
	r := newFaultyRig(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"credentials", "list"}, "boom-listcreds"},
		{[]string{"credentials", "revoke", "aabb"}, "boom-revoke"},
		{[]string{"users", "create", "alice"}, "boom-create"},
		{[]string{"users", "list"}, "boom-listusers"},
		{[]string{"users", "disable", "alice"}, "boom-disable"},
		{[]string{"identities", "bind", "iss", "sub", "alice"}, "boom-bind"},
		{[]string{"identities", "list"}, "boom-listids"},
		{[]string{"identities", "unbind", "iss", "sub"}, "boom-unbind"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			out, err := r.run(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if out != "" {
				t.Fatalf("a failed command printed %q", out)
			}
		})
	}
}

func TestSessionCommandsStopWhenTheSessionCannotBeOpened(t *testing.T) {
	r := newFaultyRig(t)
	r.f.openFails = true
	for _, args := range [][]string{{"credentials", "list"}, {"users", "list"}, {"identities", "list"}} {
		_, err := r.run(t, args...)
		if err == nil || !strings.Contains(err.Error(), "boom-open") {
			t.Fatalf("%v: err = %v, want the session failure", args, err)
		}
	}
}

func TestDialFailuresAreReported(t *testing.T) {
	r := newRig(t)
	r.enrol(t)
	boomErr := errors.New("cannot dial")
	oldDial, oldUnix := dial, dialUnix
	t.Cleanup(func() { dial, dialUnix = oldDial, oldUnix })

	dial = func(string, *tls.Config) (*grpc.ClientConn, error) { return nil, boomErr }
	if _, err := r.admin("users", "list"); !errors.Is(err, boomErr) {
		t.Fatalf("users list: %v", err)
	}
	dialUnix = func(string) (*grpc.ClientConn, error) { return nil, boomErr }
	if _, err := r.run("enrol", "--socket", r.sock, "--rp-id", rpID, "--name", "x"); !errors.Is(err, boomErr) {
		t.Fatalf("enrol: %v", err)
	}
}

func TestTimestampsAreDashedWhenAbsent(t *testing.T) {
	r := newRig(t)
	r.enrol(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"credentials", "list"}, "revoked=-"},
		{[]string{"users", "create", "dora"}, "created dora"},
		{[]string{"users", "list"}, "disabled=-"},
		{[]string{"users", "disable", "dora"}, "disabled dora"},
		{[]string{"users", "list"}, "disabled=20"},
	} {
		out, err := r.admin(tc.args...)
		if err != nil || !strings.Contains(out, tc.want) {
			t.Fatalf("%v printed %q (%v), want %q", tc.args, out, err, tc.want)
		}
	}
	if out, _ := r.admin("credentials", "list"); !strings.Contains(out, "created=20") {
		t.Fatalf("a set timestamp is not printed: %q", out)
	}
}

func TestPlatformSignerNeverReturnsAHalfOpenKey(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s, err := platformSigner(ctx)
	if f, ok := s.(adminclient.FIDOSigner); err == nil && ok && f.Key == nil {
		t.Fatal("a signer without a key and without an error")
	}
	if err != nil && s != nil {
		t.Fatalf("an error and a signer together: %v %v", err, s)
	}
}
