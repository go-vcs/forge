// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package adminsrv implements the admin gRPC API and the local enrolment API.
package adminsrv

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminauth"
	"github.com/go-vcs/forge/internal/store"
)

// Bounds.
const (
	MaxMessageSize = 64 << 10
	MaxRequestLen  = 16 << 10 // the serialized parameters inside an envelope
)

// Admin is the AdminService implementation.
type Admin struct {
	adminv1.UnimplementedAdminServiceServer
	Store    *store.Store
	Verifier *adminauth.Verifier
	Nonces   *adminauth.Nonces
	Sessions *adminauth.Sessions
	Log      *slog.Logger
}

// exportKeyingMaterial is a variable so that a test can make the export fail,
// which a completed TLS 1.3 handshake never does.
var exportKeyingMaterial = (*tls.ConnectionState).ExportKeyingMaterial

// Exporter returns the RFC 9266 channel-binding value of the connection the
// call arrived on, and refuses anything that is not TLS 1.3.
func Exporter(ctx context.Context) ([]byte, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || ti.State.Version != tls.VersionTLS13 {
		return nil, status.Error(codes.Unauthenticated, "TLS 1.3 required")
	}
	b, err := exportKeyingMaterial(&ti.State, adminauth.ExporterLabel, nil, adminauth.ExporterLen)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "no channel binding")
	}
	return b, nil
}

func (a *Admin) logf(msg string, args ...any) {
	if a.Log != nil {
		a.Log.Info(msg, args...)
	}
}

// act is an authorized administrative call, whose outcome is audited.
type act struct {
	cred     adminauth.Credential
	method   string
	sum      [32]byte
	exporter []byte // the channel binding the assertion was verified against
}

// finish records how an authorized call ended, from the error it is about to
// return (nil is success). The attempt row already exists, so a failure to
// write this one is logged and does not change what the caller is told: the
// action has run.
func (a *Admin) finish(ctx context.Context, x *act, err error) {
	outcome := store.OutcomeSuccess
	if err != nil {
		outcome = store.OutcomeFailure
	}
	// The call's context may be cancelled by now; the row is still owed.
	if e := a.Store.Audit(context.WithoutCancel(ctx), x.cred.ID, x.method, x.sum[:], outcome); e != nil {
		a.logf("audit row not written", "method", x.method, "outcome", outcome, "error", e.Error())
	}
}

// authorize verifies the envelope of a mutating call and writes its attempt
// row. On success the raw parameter bytes are returned for unmarshalling: the
// signature covered those exact bytes. The caller must then call finish.
func (a *Admin) authorize(ctx context.Context, env *adminv1.Envelope) ([]byte, *act, error) {
	if env == nil || len(env.Request) > MaxRequestLen {
		return nil, nil, status.Error(codes.InvalidArgument, "missing or oversized envelope")
	}
	method, ok := grpc.Method(ctx)
	if !ok {
		return nil, nil, status.Error(codes.Internal, "no method")
	}
	exp, err := Exporter(ctx)
	if err != nil {
		return nil, nil, err
	}
	cred, err := a.Verifier.Verify(ctx, adminauth.Input{
		Method: method, Nonce: env.Nonce, Request: env.Request, Exporter: exp,
		Assertion: adminauth.Assertion{
			CredentialID: env.CredentialId, AuthenticatorData: env.AuthenticatorData, Signature: env.Signature,
		},
	})
	if err != nil {
		if !adminauth.IsRefusal(err) {
			// The store failed while the assertion was being checked. The peer
			// has proved nothing yet, so it is told nothing of the cause.
			a.logf("assertion not checked", "method", method, "error", err.Error())
			return nil, nil, status.Error(codes.Internal, "internal error")
		}
		a.logf("assertion refused", "method", method, "reason", err.Error())
		return nil, nil, status.Error(codes.Unauthenticated, "assertion refused: "+err.Error())
	}
	x := &act{cred: cred, method: method, sum: sha256.Sum256(env.Request), exporter: exp}
	if err := a.Store.Audit(ctx, cred.ID, method, x.sum[:], store.OutcomeAttempt); err != nil {
		return nil, nil, status.Error(codes.Internal, "audit")
	}
	return env.Request, x, nil
}

// readOnly checks the session token of a read-only call, and that the
// credential that opened the session is still active: revoking a credential
// ends its sessions at once.
func (a *Admin) readOnly(ctx context.Context, token []byte) error {
	exp, err := Exporter(ctx)
	if err != nil {
		return err
	}
	owner, err := a.Sessions.Check(token, exp)
	if err != nil {
		return status.Error(codes.Unauthenticated, "session refused: "+err.Error())
	}
	if _, err := a.Verifier.Credentials.ActiveCredential(ctx, owner); err != nil {
		if errors.Is(err, adminauth.ErrUnknownCredential) {
			return status.Error(codes.Unauthenticated, "session refused: its credential is revoked")
		}
		return status.Error(codes.Internal, "credential lookup")
	}
	return nil
}

func parse(raw []byte, m proto.Message) error {
	if err := proto.Unmarshal(raw, m); err != nil {
		return status.Error(codes.InvalidArgument, "bad parameters")
	}
	return nil
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return status.Error(codes.NotFound, "not found")
	case errors.Is(err, store.ErrExists):
		return status.Error(codes.AlreadyExists, "already exists")
	case errors.Is(err, store.ErrLastCredential):
		return status.Error(codes.FailedPrecondition, "refusing to revoke the last active admin credential")
	case errors.Is(err, store.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, "internal error")
}

// GetNonce implements AdminService.
func (a *Admin) GetNonce(ctx context.Context, _ *adminv1.GetNonceRequest) (*adminv1.GetNonceResponse, error) {
	exp, err := Exporter(ctx)
	if err != nil {
		return nil, err
	}
	n, until := a.Nonces.Issue(exp)
	return &adminv1.GetNonceResponse{Nonce: n, ExpiresAt: timestamppb.New(until)}, nil
}

// OpenSession implements AdminService.
func (a *Admin) OpenSession(ctx context.Context, r *adminv1.OpenSessionRequest) (_ *adminv1.OpenSessionResponse, err error) {
	raw, x, err := a.authorize(ctx, r.GetEnvelope())
	if err != nil {
		return nil, err
	}
	defer func() { a.finish(ctx, x, err) }()
	if err := parse(raw, &adminv1.OpenSessionParams{}); err != nil {
		return nil, err
	}
	tok, until, err := a.Sessions.Open(x.exporter, x.cred.ID)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}
	return &adminv1.OpenSessionResponse{SessionToken: tok, ExpiresAt: timestamppb.New(until)}, nil
}

func credPB(c store.AdminCredential) *adminv1.AdminCredential {
	out := &adminv1.AdminCredential{
		CredentialId: c.ID, Name: c.Name, Aaguid: c.AAGUID, SignCount: c.SignCount,
		CreatedAt: timestamppb.New(c.CreatedAt),
	}
	if !c.RevokedAt.IsZero() {
		out.RevokedAt = timestamppb.New(c.RevokedAt)
	}
	return out
}

// ListAdminCredentials implements AdminService.
func (a *Admin) ListAdminCredentials(ctx context.Context, r *adminv1.ListAdminCredentialsRequest) (*adminv1.ListAdminCredentialsResponse, error) {
	if err := a.readOnly(ctx, r.GetSessionToken()); err != nil {
		return nil, err
	}
	cs, err := a.Store.ListCredentials(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &adminv1.ListAdminCredentialsResponse{}
	for _, c := range cs {
		out.Credentials = append(out.Credentials, credPB(c))
	}
	return out, nil
}

// RevokeAdminCredential implements AdminService.
func (a *Admin) RevokeAdminCredential(ctx context.Context, r *adminv1.RevokeAdminCredentialRequest) (_ *adminv1.RevokeAdminCredentialResponse, err error) {
	raw, x, err := a.authorize(ctx, r.GetEnvelope())
	if err != nil {
		return nil, err
	}
	defer func() { a.finish(ctx, x, err) }()
	var p adminv1.RevokeAdminCredentialParams
	if err := parse(raw, &p); err != nil {
		return nil, err
	}
	if err := a.Store.RevokeCredential(ctx, p.CredentialId); err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.RevokeAdminCredentialResponse{}, nil
}

func userPB(u store.User) *adminv1.User {
	out := &adminv1.User{Login: u.Login, DisplayName: u.DisplayName, CreatedAt: timestamppb.New(u.CreatedAt)}
	if !u.DisabledAt.IsZero() {
		out.DisabledAt = timestamppb.New(u.DisabledAt)
	}
	return out
}

// CreateUser implements AdminService.
func (a *Admin) CreateUser(ctx context.Context, r *adminv1.CreateUserRequest) (_ *adminv1.CreateUserResponse, err error) {
	raw, x, err := a.authorize(ctx, r.GetEnvelope())
	if err != nil {
		return nil, err
	}
	defer func() { a.finish(ctx, x, err) }()
	var p adminv1.CreateUserParams
	if err := parse(raw, &p); err != nil {
		return nil, err
	}
	u, err := a.Store.CreateUser(ctx, p.Login, p.DisplayName)
	if err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.CreateUserResponse{User: userPB(u)}, nil
}

// ListUsers implements AdminService.
func (a *Admin) ListUsers(ctx context.Context, r *adminv1.ListUsersRequest) (*adminv1.ListUsersResponse, error) {
	if err := a.readOnly(ctx, r.GetSessionToken()); err != nil {
		return nil, err
	}
	us, err := a.Store.ListUsers(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := &adminv1.ListUsersResponse{}
	for _, u := range us {
		out.Users = append(out.Users, userPB(u))
	}
	return out, nil
}

// DisableUser implements AdminService.
func (a *Admin) DisableUser(ctx context.Context, r *adminv1.DisableUserRequest) (_ *adminv1.DisableUserResponse, err error) {
	raw, x, err := a.authorize(ctx, r.GetEnvelope())
	if err != nil {
		return nil, err
	}
	defer func() { a.finish(ctx, x, err) }()
	var p adminv1.DisableUserParams
	if err := parse(raw, &p); err != nil {
		return nil, err
	}
	if err := a.Store.DisableUser(ctx, p.Login); err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.DisableUserResponse{}, nil
}

func identityPB(i store.Identity) *adminv1.Identity {
	return &adminv1.Identity{Issuer: i.Issuer, Subject: i.Subject, Login: i.Login, CreatedAt: timestamppb.New(i.CreatedAt)}
}

// BindIdentity implements AdminService.
func (a *Admin) BindIdentity(ctx context.Context, r *adminv1.BindIdentityRequest) (_ *adminv1.BindIdentityResponse, err error) {
	raw, x, err := a.authorize(ctx, r.GetEnvelope())
	if err != nil {
		return nil, err
	}
	defer func() { a.finish(ctx, x, err) }()
	var p adminv1.BindIdentityParams
	if err := parse(raw, &p); err != nil {
		return nil, err
	}
	i, err := a.Store.BindIdentity(ctx, p.Issuer, p.Subject, p.Login)
	if err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.BindIdentityResponse{Identity: identityPB(i)}, nil
}

// ListIdentities implements AdminService.
func (a *Admin) ListIdentities(ctx context.Context, r *adminv1.ListIdentitiesRequest) (*adminv1.ListIdentitiesResponse, error) {
	if err := a.readOnly(ctx, r.GetSessionToken()); err != nil {
		return nil, err
	}
	is, err := a.Store.ListIdentities(ctx, r.GetLogin())
	if err != nil {
		return nil, mapErr(err)
	}
	out := &adminv1.ListIdentitiesResponse{}
	for _, i := range is {
		out.Identities = append(out.Identities, identityPB(i))
	}
	return out, nil
}

// UnbindIdentity implements AdminService.
func (a *Admin) UnbindIdentity(ctx context.Context, r *adminv1.UnbindIdentityRequest) (_ *adminv1.UnbindIdentityResponse, err error) {
	raw, x, err := a.authorize(ctx, r.GetEnvelope())
	if err != nil {
		return nil, err
	}
	defer func() { a.finish(ctx, x, err) }()
	var p adminv1.UnbindIdentityParams
	if err := parse(raw, &p); err != nil {
		return nil, err
	}
	if err := a.Store.UnbindIdentity(ctx, p.Issuer, p.Subject); err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.UnbindIdentityResponse{}, nil
}
