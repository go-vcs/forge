// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminclient_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminclient"
)

// fakeForge records what reaches it and answers with what the test chose.
type fakeForge struct {
	adminv1.UnimplementedAdminServiceServer
	adminv1.UnimplementedEnrolServiceServer

	mu       sync.Mutex
	nonce    []byte
	nonceErr error
	fail     error // returned by every other call when set
	calls    int   // calls that carried an envelope or an enrolment step
	envs     []*adminv1.Envelope
	finish   *adminv1.FinishEnrolRequest
}

func (f *fakeForge) seen(env *adminv1.Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.envs = append(f.envs, env)
	return f.fail
}

func (f *fakeForge) GetNonce(context.Context, *adminv1.GetNonceRequest) (*adminv1.GetNonceResponse, error) {
	if f.nonceErr != nil {
		return nil, f.nonceErr
	}
	return &adminv1.GetNonceResponse{Nonce: f.nonce}, nil
}

func (f *fakeForge) OpenSession(_ context.Context, r *adminv1.OpenSessionRequest) (*adminv1.OpenSessionResponse, error) {
	if err := f.seen(r.Envelope); err != nil {
		return nil, err
	}
	return &adminv1.OpenSessionResponse{SessionToken: []byte("tok")}, nil
}

func (f *fakeForge) CreateUser(_ context.Context, r *adminv1.CreateUserRequest) (*adminv1.CreateUserResponse, error) {
	if err := f.seen(r.Envelope); err != nil {
		return nil, err
	}
	return &adminv1.CreateUserResponse{User: &adminv1.User{Login: "ada"}}, nil
}

func (f *fakeForge) DisableUser(_ context.Context, r *adminv1.DisableUserRequest) (*adminv1.DisableUserResponse, error) {
	if err := f.seen(r.Envelope); err != nil {
		return nil, err
	}
	return &adminv1.DisableUserResponse{}, nil
}

func (f *fakeForge) BindIdentity(_ context.Context, r *adminv1.BindIdentityRequest) (*adminv1.BindIdentityResponse, error) {
	if err := f.seen(r.Envelope); err != nil {
		return nil, err
	}
	return &adminv1.BindIdentityResponse{Identity: &adminv1.Identity{Issuer: "iss"}}, nil
}

func (f *fakeForge) UnbindIdentity(_ context.Context, r *adminv1.UnbindIdentityRequest) (*adminv1.UnbindIdentityResponse, error) {
	if err := f.seen(r.Envelope); err != nil {
		return nil, err
	}
	return &adminv1.UnbindIdentityResponse{}, nil
}

func (f *fakeForge) RevokeAdminCredential(_ context.Context, r *adminv1.RevokeAdminCredentialRequest) (*adminv1.RevokeAdminCredentialResponse, error) {
	if err := f.seen(r.Envelope); err != nil {
		return nil, err
	}
	return &adminv1.RevokeAdminCredentialResponse{}, nil
}

func (f *fakeForge) BeginEnrol(context.Context, *adminv1.BeginEnrolRequest) (*adminv1.BeginEnrolResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return &adminv1.BeginEnrolResponse{Challenge: []byte("chal"), RpId: "forge.test", UserHandle: []byte("uh")}, nil
}

func (f *fakeForge) FinishEnrol(_ context.Context, r *adminv1.FinishEnrolRequest) (*adminv1.FinishEnrolResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.finish = r
	if f.fail != nil {
		return nil, f.fail
	}
	return &adminv1.FinishEnrolResponse{Credential: &adminv1.AdminCredential{Name: r.Name}}, nil
}

// stubSigner counts what it is asked and fails on request.
type stubSigner struct {
	assertErr, makeErr error
	asserts, makes     int
	rpID               string
	cred               []byte
	cdh                [32]byte
}

func (s *stubSigner) Assert(_ context.Context, rpID string, cred []byte, cdh [32]byte) ([]byte, []byte, error) {
	s.asserts++
	s.rpID, s.cred, s.cdh = rpID, cred, cdh
	if s.assertErr != nil {
		return nil, nil, s.assertErr
	}
	return []byte("ad"), []byte("sig"), nil
}

func (s *stubSigner) Make(_ context.Context, rpID string, _ []byte, _ string, _ [32]byte) (string, []byte, []byte, error) {
	s.makes++
	if s.makeErr != nil {
		return "", nil, nil, s.makeErr
	}
	return "packed", []byte("mad"), []byte("stmt"), nil
}

func cert(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func pool(t *testing.T, c tls.Certificate) *x509.CertPool {
	t.Helper()
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	p := x509.NewCertPool()
	p.AddCert(x)
	return p
}

// serve starts the fake on a loopback port; creds nil means plain text.
func serve(t *testing.T, f *fakeForge, creds credentials.TransportCredentials) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var opts []grpc.ServerOption
	if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	}
	s := grpc.NewServer(opts...)
	adminv1.RegisterAdminServiceServer(s, f)
	adminv1.RegisterEnrolServiceServer(s, f)
	go func() { _ = s.Serve(l) }()
	t.Cleanup(s.Stop)
	return l.Addr().String()
}

// tls13 returns a client of a TLS 1.3 fake forge.
func tls13(t *testing.T, f *fakeForge, s adminclient.Signer) *adminclient.Client {
	t.Helper()
	c := cert(t)
	addr := serve(t, f, credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13}))
	conn, err := adminclient.Dial(addr, &tls.Config{RootCAs: pool(t, c), ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return adminclient.New(conn, s, "forge.test", []byte("cred-1"))
}

func TestNonceReturnsServerNonceAndExporter(t *testing.T) {
	f := &fakeForge{nonce: []byte("nonce-1")}
	c := tls13(t, f, &stubSigner{})
	n, exp, err := c.Nonce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(n, []byte("nonce-1")) {
		t.Fatalf("nonce %q", n)
	}
	if len(exp) != 32 || bytes.Equal(exp, make([]byte, 32)) {
		t.Fatalf("exporter %x", exp)
	}
}

func TestNonceRefusesAConnectionThatIsNotTLS13(t *testing.T) {
	c12 := cert(t)
	cases := map[string]func(t *testing.T) *grpc.ClientConn{
		"plain text": func(t *testing.T) *grpc.ClientConn {
			addr := serve(t, &fakeForge{nonce: []byte("n")}, nil)
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			return conn
		},
		"TLS 1.2": func(t *testing.T) *grpc.ClientConn {
			addr := serve(t, &fakeForge{nonce: []byte("n")}, credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{c12}, MinVersion: tls.VersionTLS12}))
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				RootCAs: pool(t, c12), ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			})))
			if err != nil {
				t.Fatal(err)
			}
			return conn
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			conn := mk(t)
			t.Cleanup(func() { _ = conn.Close() })
			n, exp, err := adminclient.New(conn, &stubSigner{}, "forge.test", nil).Nonce(context.Background())
			if err == nil || !strings.Contains(err.Error(), "not TLS 1.3") {
				t.Fatalf("want a refusal naming TLS 1.3, got %v", err)
			}
			if n != nil || exp != nil {
				t.Fatalf("a refused connection returned %q %x", n, exp)
			}
		})
	}
}

func TestNonceServerError(t *testing.T) {
	c := tls13(t, &fakeForge{nonceErr: status.Error(codes.Unavailable, "down")}, &stubSigner{})
	n, exp, err := c.Nonce(context.Background())
	if status.Code(err) != codes.Unavailable || n != nil || exp != nil {
		t.Fatalf("got %q %x %v", n, exp, err)
	}
}

func TestNonceExportFailure(t *testing.T) {
	boom := errors.New("export boom")
	restore := adminclient.SetExport(func(*tls.ConnectionState, string, []byte, int) ([]byte, error) { return nil, boom })
	defer restore()
	c := tls13(t, &fakeForge{nonce: []byte("n")}, &stubSigner{})
	n, exp, err := c.Nonce(context.Background())
	if !errors.Is(err, boom) || n != nil || exp != nil {
		t.Fatalf("got %q %x %v", n, exp, err)
	}
}

func TestSignRefusesWhatCannotBeMarshalled(t *testing.T) {
	s := &stubSigner{}
	c := tls13(t, &fakeForge{nonce: []byte("n")}, s)
	// proto3 strings must be UTF-8; the marshal refuses this one.
	env, err := c.Sign(context.Background(), adminv1.AdminService_CreateUser_FullMethodName, &adminv1.CreateUserParams{Login: "\xff"})
	if err == nil || env != nil {
		t.Fatalf("got %v %v", env, err)
	}
	if s.asserts != 0 {
		t.Fatal("the key was asked to sign a request that could not be encoded")
	}
}

func TestSignBuildsTheEnvelope(t *testing.T) {
	s := &stubSigner{}
	c := tls13(t, &fakeForge{nonce: []byte("n-2")}, s)
	params := &adminv1.DisableUserParams{Login: "bob"}
	env, err := c.Sign(context.Background(), adminv1.AdminService_DisableUser_FullMethodName, params)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := proto.Marshal(params)
	if !bytes.Equal(env.Nonce, []byte("n-2")) || !bytes.Equal(env.Request, want) ||
		!bytes.Equal(env.CredentialId, []byte("cred-1")) ||
		!bytes.Equal(env.AuthenticatorData, []byte("ad")) || !bytes.Equal(env.Signature, []byte("sig")) {
		t.Fatalf("envelope %+v", env)
	}
	if s.rpID != "forge.test" || !bytes.Equal(s.cred, []byte("cred-1")) || s.cdh == [32]byte{} {
		t.Fatalf("the key was asked %q %q %x", s.rpID, s.cred, s.cdh)
	}
}

func TestSignedCalls(t *testing.T) {
	calls := map[string]func(c *adminclient.Client) (any, error){
		"OpenSession": func(c *adminclient.Client) (any, error) { return c.OpenSession(context.Background()) },
		"CreateUser":  func(c *adminclient.Client) (any, error) { return c.CreateUser(context.Background(), "ada", "Ada") },
		"DisableUser": func(c *adminclient.Client) (any, error) {
			return nil, c.DisableUser(context.Background(), "ada")
		},
		"BindIdentity": func(c *adminclient.Client) (any, error) {
			return c.BindIdentity(context.Background(), "iss", "sub", "ada")
		},
		"UnbindIdentity": func(c *adminclient.Client) (any, error) {
			return nil, c.UnbindIdentity(context.Background(), "iss", "sub")
		},
		"RevokeCredential": func(c *adminclient.Client) (any, error) {
			return nil, c.RevokeCredential(context.Background(), []byte("x"))
		},
	}
	for name, call := range calls {
		t.Run(name+"/ok", func(t *testing.T) {
			f := &fakeForge{nonce: []byte("n")}
			s := &stubSigner{}
			v, err := call(tls13(t, f, s))
			if err != nil {
				t.Fatal(err)
			}
			if f.calls != 1 || s.asserts != 1 || len(f.envs[0].Signature) == 0 {
				t.Fatalf("calls=%d asserts=%d", f.calls, s.asserts)
			}
			switch name {
			case "OpenSession":
				if !bytes.Equal(v.([]byte), []byte("tok")) {
					t.Fatalf("token %q", v)
				}
			case "CreateUser":
				if v.(*adminv1.User).Login != "ada" {
					t.Fatalf("user %v", v)
				}
			case "BindIdentity":
				if v.(*adminv1.Identity).Issuer != "iss" {
					t.Fatalf("identity %v", v)
				}
			}
		})
		t.Run(name+"/key refuses", func(t *testing.T) {
			f := &fakeForge{nonce: []byte("n")}
			boom := errors.New("no touch")
			v, err := call(tls13(t, f, &stubSigner{assertErr: boom}))
			if !errors.Is(err, boom) || !isNil(v) {
				t.Fatalf("got %v %v", v, err)
			}
			if f.calls != 0 {
				t.Fatal("a call went out without a signature")
			}
		})
		t.Run(name+"/no nonce", func(t *testing.T) {
			f := &fakeForge{nonceErr: status.Error(codes.Unavailable, "down")}
			s := &stubSigner{}
			v, err := call(tls13(t, f, s))
			if status.Code(err) != codes.Unavailable || !isNil(v) {
				t.Fatalf("got %v %v", v, err)
			}
			if s.asserts != 0 || f.calls != 0 {
				t.Fatal("the key was asked to sign without a nonce")
			}
		})
		t.Run(name+"/server refuses", func(t *testing.T) {
			f := &fakeForge{nonce: []byte("n"), fail: status.Error(codes.PermissionDenied, "no")}
			v, err := call(tls13(t, f, &stubSigner{}))
			if status.Code(err) != codes.PermissionDenied || !isNil(v) {
				t.Fatalf("got %v %v", v, err)
			}
		})
	}
}

// isNil is true for nil, a nil slice and a nil pointer, the three "nothing"
// the calls above return.
func isNil(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []byte:
		return x == nil
	case *adminv1.User:
		return x == nil
	case *adminv1.Identity:
		return x == nil
	}
	return false
}

func TestEnrol(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		f := &fakeForge{}
		c := tls13(t, f, nil)
		cred, err := adminclient.Enrol(ctx, c.Conn, &stubSigner{}, "laptop")
		if err != nil || cred.Name != "laptop" {
			t.Fatalf("got %v %v", cred, err)
		}
		if string(f.finish.Challenge) != "chal" || f.finish.AttestationFormat != "packed" ||
			string(f.finish.AuthenticatorData) != "mad" || string(f.finish.AttestationStatement) != "stmt" {
			t.Fatalf("finish %+v", f.finish)
		}
	})
	t.Run("begin fails", func(t *testing.T) {
		f := &fakeForge{}
		c := tls13(t, f, nil)
		// Close the connection: the first call fails.
		_ = c.Conn.Close()
		cred, err := adminclient.Enrol(ctx, c.Conn, &stubSigner{}, "laptop")
		if err == nil || cred != nil {
			t.Fatalf("got %v %v", cred, err)
		}
	})
	t.Run("key refuses", func(t *testing.T) {
		f := &fakeForge{}
		boom := errors.New("no key")
		cred, err := adminclient.Enrol(ctx, tls13(t, f, nil).Conn, &stubSigner{makeErr: boom}, "laptop")
		if !errors.Is(err, boom) || cred != nil {
			t.Fatalf("got %v %v", cred, err)
		}
		if f.finish != nil {
			t.Fatal("an enrolment was finished without a credential")
		}
	})
	t.Run("finish refused", func(t *testing.T) {
		f := &fakeForge{fail: status.Error(codes.InvalidArgument, "bad attestation")}
		cred, err := adminclient.Enrol(ctx, tls13(t, f, nil).Conn, &stubSigner{}, "laptop")
		if status.Code(err) != codes.InvalidArgument || cred != nil {
			t.Fatalf("got %v %v", cred, err)
		}
	})
}
