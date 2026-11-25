// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv_test

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminclient"
	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/store"
)

// wantStatus fails unless err carries code c and a message containing msg: a
// refusal is held by the reason it gives, not only by the fact of refusing.
func wantStatus(t *testing.T, name string, err error, c codes.Code, msg string) {
	t.Helper()
	if code(err) != c {
		t.Fatalf("%s: %v, want code %v", name, err, c)
	}
	if !strings.Contains(status.Convert(err).Message(), msg) {
		t.Fatalf("%s: message %q does not say %q", name, status.Convert(err).Message(), msg)
	}
}

// rawExec runs SQL on the forge's database file behind the store's back.
func (f *forge) rawExec(stmts string) {
	f.t.Helper()
	db, err := sql.Open("sqlite", "file:"+f.db+"?_pragma=busy_timeout(5000)")
	if err != nil {
		f.t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(stmts); err != nil {
		f.t.Fatalf("%s: %v", stmts, err)
	}
}

// session opens a read-only session on a fresh connection.
func (f *forge) session() (*adminclient.Client, []byte) {
	f.t.Helper()
	f.mustEnrol()
	c := f.dial()
	tok, err := c.OpenSession(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	return c, tok
}

// stream is a server transport stream that only knows its method.
type stream string

func (s stream) Method() string             { return string(s) }
func (stream) SetHeader(metadata.MD) error  { return nil }
func (stream) SendHeader(metadata.MD) error { return nil }
func (stream) SetTrailer(metadata.MD) error { return nil }
func withMethod(ctx context.Context) context.Context {
	return grpc.NewContextWithServerTransportStream(ctx, stream("/x/Y"))
}

func withAuth(ctx context.Context, ai credentials.AuthInfo) context.Context {
	return peer.NewContext(ctx, &peer.Peer{AuthInfo: ai})
}

func unixPeer(ctx context.Context) context.Context {
	return peer.NewContext(ctx, &peer.Peer{Addr: &net.UnixAddr{Name: "s", Net: "unix"}})
}

func TestExporterRefusals(t *testing.T) {
	ctx := t.Context()
	_, err := adminsrv.Exporter(ctx)
	wantStatus(t, "no peer", err, codes.Unauthenticated, "no peer")
	_, err = adminsrv.Exporter(withAuth(ctx, nil))
	wantStatus(t, "no TLS", err, codes.Unauthenticated, "TLS 1.3 required")
	_, err = adminsrv.Exporter(withAuth(ctx, credentials.TLSInfo{State: tls.ConnectionState{Version: tls.VersionTLS12}}))
	wantStatus(t, "TLS 1.2", err, codes.Unauthenticated, "TLS 1.3 required")
	// TLS 1.3 whose keying material cannot be exported.
	defer adminsrv.UseExporter(func(*tls.ConnectionState, string, []byte, int) ([]byte, error) {
		return nil, errors.New("no ekm")
	})()
	_, err = adminsrv.Exporter(withAuth(ctx, credentials.TLSInfo{State: tls.ConnectionState{Version: tls.VersionTLS13}}))
	wantStatus(t, "no exporter", err, codes.Unauthenticated, "no channel binding")
}

func TestHandlersRefuseAConnectionWithoutBinding(t *testing.T) {
	f := newForge(t)
	ctx := t.Context()
	_, err := f.adm.GetNonce(ctx, &adminv1.GetNonceRequest{})
	wantStatus(t, "GetNonce", err, codes.Unauthenticated, "no peer")
	_, err = f.adm.ListUsers(ctx, &adminv1.ListUsersRequest{SessionToken: []byte("t")})
	wantStatus(t, "ListUsers", err, codes.Unauthenticated, "no peer")
	// An envelope on a call that has no method is not authorized either.
	_, err = f.adm.CreateUser(ctx, &adminv1.CreateUserRequest{Envelope: &adminv1.Envelope{}})
	wantStatus(t, "no method", err, codes.Internal, "no method")
	// With a method but no binding to verify against.
	_, err = f.adm.CreateUser(withMethod(ctx), &adminv1.CreateUserRequest{Envelope: &adminv1.Envelope{}})
	wantStatus(t, "no binding", err, codes.Unauthenticated, "no peer")
}

// mutation is one signed administrative call.
type mutation struct {
	name   string
	method string
	params proto.Message
	do     func(c *adminclient.Client, env *adminv1.Envelope) error
}

func mutations() []mutation {
	ctx := context.Background()
	return []mutation{
		{"OpenSession", adminv1.AdminService_OpenSession_FullMethodName, &adminv1.OpenSessionParams{},
			func(c *adminclient.Client, e *adminv1.Envelope) error {
				_, err := c.Admin.OpenSession(ctx, &adminv1.OpenSessionRequest{Envelope: e})
				return err
			}},
		{"RevokeAdminCredential", adminv1.AdminService_RevokeAdminCredential_FullMethodName, &adminv1.RevokeAdminCredentialParams{CredentialId: []byte{9}},
			func(c *adminclient.Client, e *adminv1.Envelope) error {
				_, err := c.Admin.RevokeAdminCredential(ctx, &adminv1.RevokeAdminCredentialRequest{Envelope: e})
				return err
			}},
		{"CreateUser", adminv1.AdminService_CreateUser_FullMethodName, params("zed"),
			func(c *adminclient.Client, e *adminv1.Envelope) error { return createUser(c, e) }},
		{"DisableUser", adminv1.AdminService_DisableUser_FullMethodName, &adminv1.DisableUserParams{Login: "ghost"},
			func(c *adminclient.Client, e *adminv1.Envelope) error {
				_, err := c.Admin.DisableUser(ctx, &adminv1.DisableUserRequest{Envelope: e})
				return err
			}},
		{"BindIdentity", adminv1.AdminService_BindIdentity_FullMethodName, &adminv1.BindIdentityParams{Issuer: "i", Subject: "s", Login: "ghost"},
			func(c *adminclient.Client, e *adminv1.Envelope) error {
				_, err := c.Admin.BindIdentity(ctx, &adminv1.BindIdentityRequest{Envelope: e})
				return err
			}},
		{"UnbindIdentity", adminv1.AdminService_UnbindIdentity_FullMethodName, &adminv1.UnbindIdentityParams{Issuer: "i", Subject: "s"},
			func(c *adminclient.Client, e *adminv1.Envelope) error {
				_, err := c.Admin.UnbindIdentity(ctx, &adminv1.UnbindIdentityRequest{Envelope: e})
				return err
			}},
	}
}

func TestEveryMutationRefusesABadAssertion(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	for _, m := range mutations() {
		env := f.envelope(c, m.method, m.params, tweak{mutate: func(e *adminv1.Envelope) { e.Signature[0] ^= 1 }})
		wantStatus(t, m.name, m.do(c, env), codes.Unauthenticated, "assertion refused")
	}
	if !strings.Contains(f.logs.String(), "assertion refused") {
		t.Fatalf("a refused assertion was not logged: %s", f.logs)
	}
}

func TestEveryMutationRefusesUnparsableParameters(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	for _, m := range mutations() {
		// A truncated length-delimited field: signed correctly, so only the
		// parse can refuse it.
		env := f.envelope(c, m.method, m.params, tweak{rawReq: []byte{0x0a, 0x05, 'a'}})
		wantStatus(t, m.name, m.do(c, env), codes.InvalidArgument, "bad parameters")
	}
	f.wantUsers(0)
}

func TestMutationsOnMissingThingsAreNotFound(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	ctx := t.Context()
	wantStatus(t, "revoke", c.RevokeCredential(ctx, []byte{1, 2, 3}), codes.NotFound, "not found")
	wantStatus(t, "disable", c.DisableUser(ctx, "ghost"), codes.NotFound, "not found")
	_, err := c.BindIdentity(ctx, "https://i.example", "s", "ghost")
	wantStatus(t, "bind", err, codes.NotFound, "not found")
	wantStatus(t, "unbind", c.UnbindIdentity(ctx, "https://i.example", "s"), codes.NotFound, "not found")
}

func TestSessionLimitIsReported(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	var err error
	for i := 0; i < 100 && err == nil; i++ {
		_, err = c.OpenSession(t.Context())
	}
	if code(err) != codes.ResourceExhausted {
		t.Fatalf("100 sessions on one connection: %v, want ResourceExhausted", err)
	}
}

func TestReadsRefuseABogusSession(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	_, err := c.Admin.ListUsers(t.Context(), &adminv1.ListUsersRequest{SessionToken: []byte("bogus")})
	wantStatus(t, "bogus token", err, codes.Unauthenticated, "session refused: ")
}

func TestStoreFailuresAreInternalNotLeaked(t *testing.T) {
	cases := []struct {
		name, damage string
		read         func(c *adminclient.Client, tok []byte) error
	}{
		{"users", `ALTER TABLE users RENAME COLUMN display_name TO dn`, func(c *adminclient.Client, tok []byte) error {
			_, err := c.Admin.ListUsers(context.Background(), &adminv1.ListUsersRequest{SessionToken: tok})
			return err
		}},
		{"identities", `ALTER TABLE identities RENAME COLUMN created_at TO ca`, func(c *adminclient.Client, tok []byte) error {
			_, err := c.Admin.ListIdentities(context.Background(), &adminv1.ListIdentitiesRequest{SessionToken: tok})
			return err
		}},
		{"credentials", `ALTER TABLE admin_credentials RENAME COLUMN created_at TO ca`, func(c *adminclient.Client, tok []byte) error {
			_, err := c.Admin.ListAdminCredentials(context.Background(), &adminv1.ListAdminCredentialsRequest{SessionToken: tok})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newForge(t)
			c, tok := f.session()
			if err := tc.read(c, tok); err != nil {
				t.Fatalf("before damage: %v", err)
			}
			f.rawExec(tc.damage)
			err := tc.read(c, tok)
			wantStatus(t, tc.name, err, codes.Internal, "internal error")
		})
	}
	t.Run("credential lookup", func(t *testing.T) {
		f := newForge(t)
		c, tok := f.session()
		f.rawExec(`ALTER TABLE admin_credentials RENAME COLUMN public_key TO pk`)
		_, err := c.Admin.ListUsers(t.Context(), &adminv1.ListUsersRequest{SessionToken: tok})
		wantStatus(t, "lookup", err, codes.Internal, "credential lookup")
	})
}

func TestAuditFailures(t *testing.T) {
	t.Run("attempt row not written refuses the call", func(t *testing.T) {
		f := newForge(t)
		f.mustEnrol()
		c := f.dial()
		f.rawExec(`DROP TABLE admin_audit`)
		_, err := c.CreateUser(t.Context(), "alice", "Alice")
		wantStatus(t, "attempt", err, codes.Internal, "audit")
		f.wantUsers(0)
	})
	t.Run("outcome row not written is logged, not reported", func(t *testing.T) {
		f := newForge(t)
		f.mustEnrol()
		c := f.dial()
		f.rawExec(fmt.Sprintf(`CREATE TRIGGER nofinish BEFORE INSERT ON admin_audit WHEN NEW.outcome <> '%s' BEGIN SELECT RAISE(ABORT, 'no'); END`, store.OutcomeAttempt))
		if _, err := c.CreateUser(t.Context(), "alice", "Alice"); err != nil {
			t.Fatalf("the action ran, the caller must be told so: %v", err)
		}
		f.wantUsers(1)
		if !strings.Contains(f.logs.String(), "audit row not written") {
			t.Fatalf("the missing row was not logged: %s", f.logs)
		}
	})
}

func TestEnrolRefusesAPeerThatIsNotALocalSocket(t *testing.T) {
	f := newForge(t)
	e := f.enrol
	tcp := peer.NewContext(t.Context(), &peer.Peer{Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}})
	noAddr := peer.NewContext(t.Context(), &peer.Peer{})
	for name, ctx := range map[string]context.Context{"no peer": t.Context(), "tcp": tcp, "no address": noAddr} {
		_, err := e.BeginEnrol(ctx, &adminv1.BeginEnrolRequest{})
		wantStatus(t, name+" begin", err, codes.PermissionDenied, adminsrv.ErrNotLocal.Error())
		_, err = e.FinishEnrol(ctx, &adminv1.FinishEnrolRequest{Name: "x"})
		wantStatus(t, name+" finish", err, codes.PermissionDenied, adminsrv.ErrNotLocal.Error())
	}
	if _, err := e.BeginEnrol(unixPeer(t.Context()), &adminv1.BeginEnrolRequest{}); err != nil {
		t.Fatalf("a unix peer: %v", err)
	}
}

func TestEnrolChallengeMustHaveItsExactLength(t *testing.T) {
	f := newForge(t)
	ctx := unixPeer(t.Context())
	b, err := f.enrol.BeginEnrol(ctx, &adminv1.BeginEnrolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for name, ch := range map[string][]byte{
		"longer":  append(append([]byte{}, b.Challenge...), 0),
		"shorter": b.Challenge[:len(b.Challenge)-1],
		"empty":   nil,
	} {
		_, err := f.enrol.FinishEnrol(ctx, &adminv1.FinishEnrolRequest{Name: "x", Challenge: ch})
		wantStatus(t, name, err, codes.FailedPrecondition, "challenge unknown")
	}
	// The real challenge is still good: the refused ones did not consume it.
	_, err = f.enrol.FinishEnrol(ctx, &adminv1.FinishEnrolRequest{Name: "x", Challenge: b.Challenge})
	wantStatus(t, "real", err, codes.PermissionDenied, "attestation refused")
	if !strings.Contains(f.logs.String(), "enrolment refused") {
		t.Fatalf("the refusal was not logged: %s", f.logs)
	}
}

func TestEnrolIsLoggedAndAStoreFailureIsInternal(t *testing.T) {
	f := newForge(t)
	if _, err := f.enrolKey("one"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.logs.String(), "admin credential enrolled") {
		t.Fatalf("the enrolment was not logged: %s", f.logs)
	}
	f.rawExec(`ALTER TABLE admin_credentials RENAME COLUMN aaguid TO ag`)
	f.auth.Key = nil // a new credential, so only the store can refuse it
	_, err := f.enrolKey("two")
	wantStatus(t, "store failure", err, codes.Internal, "internal error")
}

func TestListenUnixFaults(t *testing.T) {
	t.Run("directory is a file", func(t *testing.T) {
		p := filepath.Join(shortDir(t), "f")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		l, err := adminsrv.ListenUnix(filepath.Join(p, "s"))
		if l != nil {
			l.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "must be a directory") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("directory not owned", func(t *testing.T) {
		defer adminsrv.UseEuid(os.Geteuid() + 1)()
		l, err := adminsrv.ListenUnix(filepath.Join(shortDir(t), "s"))
		if l != nil {
			l.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "not owned") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("stale socket cannot be removed", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can remove it")
		}
		d := shortDir(t)
		p := filepath.Join(d, "s")
		old, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		old.(*net.UnixListener).SetUnlinkOnClose(false)
		old.Close()
		if err := os.Chmod(d, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(d, 0o700) })
		l, err := adminsrv.ListenUnix(p)
		if l != nil {
			l.Close()
		}
		if !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("%v, want a permission error", err)
		}
	})
	t.Run("listen fails", func(t *testing.T) {
		p := filepath.Join(shortDir(t), strings.Repeat("a", 200)) // longer than sun_path
		l, err := adminsrv.ListenUnix(p)
		if l != nil {
			l.Close()
		}
		if err == nil || l != nil {
			t.Fatalf("%v %v", l, err)
		}
	})
	t.Run("chmod fails", func(t *testing.T) {
		boom := errors.New("chmod boom")
		defer adminsrv.UseChmod(func(string, fs.FileMode) error { return boom })()
		p := filepath.Join(shortDir(t), "s")
		l, err := adminsrv.ListenUnix(p)
		if l != nil {
			l.Close()
		}
		if !errors.Is(err, boom) || l != nil {
			t.Fatalf("%v %v", l, err)
		}
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the half-made socket was left behind: %v", err)
		}
	})
}

type noSys struct{ fs.FileInfo }

func (noSys) Sys() any { return nil }

func TestOwnedBy(t *testing.T) {
	fi, err := os.Stat(shortDir(t))
	if err != nil {
		t.Fatal(err)
	}
	me := os.Geteuid()
	if !adminsrv.OwnedBy(fi, me) || adminsrv.OwnedBy(fi, me+1) {
		t.Fatal("ownership misread")
	}
	if adminsrv.OwnedBy(noSys{fi}, me) {
		t.Fatal("a file whose owner cannot be read was called owned")
	}
}
