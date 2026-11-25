// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package adminclient is the client of the admin API: it builds the signed
// envelope of each mutating call and asks a [Signer] (a FIDO2 key) to sign it.
package adminclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminauth"
)

// Signer produces FIDO2 assertions and attestations. The hardware
// implementation is [FIDOSigner]; tests use a software authenticator.
type Signer interface {
	// Assert returns authenticator data and an ES256 signature, with user
	// verification, over authenticatorData || cdh.
	Assert(ctx context.Context, rpID string, credentialID []byte, cdh [32]byte) (authData, signature []byte, err error)
	// Make creates a credential and returns the attestation object's parts.
	Make(ctx context.Context, rpID string, userHandle []byte, name string, cdh [32]byte) (format string, authData, attStmt []byte, err error)
}

// Client talks to the admin API.
type Client struct {
	Conn         *grpc.ClientConn
	Admin        adminv1.AdminServiceClient
	Signer       Signer
	RPID         string
	CredentialID []byte
}

// Dial connects over TLS 1.3 only. cfg is cloned; its MinVersion is forced.
func Dial(target string, cfg *tls.Config) (*grpc.ClientConn, error) {
	c := cfg.Clone()
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{"h2"}
	return grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(c)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1<<20)))
}

// New returns a client.
func New(conn *grpc.ClientConn, s Signer, rpID string, credentialID []byte) *Client {
	return &Client{Conn: conn, Admin: adminv1.NewAdminServiceClient(conn), Signer: s, RPID: rpID, CredentialID: credentialID}
}

// Nonce asks for a nonce and returns it with the connection's exporter value.
func (c *Client) Nonce(ctx context.Context) (nonce, exporter []byte, err error) {
	var p peer.Peer
	resp, err := c.Admin.GetNonce(ctx, &adminv1.GetNonceRequest{}, grpc.Peer(&p))
	if err != nil {
		return nil, nil, err
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || ti.State.Version != tls.VersionTLS13 {
		return nil, nil, errors.New("adminclient: connection is not TLS 1.3")
	}
	exp, err := ti.State.ExportKeyingMaterial(adminauth.ExporterLabel, nil, adminauth.ExporterLen)
	if err != nil {
		return nil, nil, err
	}
	return resp.Nonce, exp, nil
}

// Sign builds the envelope for method (the full gRPC method name) carrying
// params. The key is asked for a touch and a verification.
func (c *Client) Sign(ctx context.Context, method string, params proto.Message) (*adminv1.Envelope, error) {
	nonce, exp, err := c.Nonce(ctx)
	if err != nil {
		return nil, err
	}
	req, err := proto.Marshal(params)
	if err != nil {
		return nil, err
	}
	cdh := adminauth.ClientDataHash(method, nonce, req, exp)
	ad, sig, err := c.Signer.Assert(ctx, c.RPID, c.CredentialID, cdh)
	if err != nil {
		return nil, fmt.Errorf("adminclient: signing: %w", err)
	}
	return &adminv1.Envelope{Nonce: nonce, Request: req, CredentialId: c.CredentialID, AuthenticatorData: ad, Signature: sig}, nil
}

// OpenSession signs one assertion and returns a read-only session token.
func (c *Client) OpenSession(ctx context.Context) ([]byte, error) {
	env, err := c.Sign(ctx, adminv1.AdminService_OpenSession_FullMethodName, &adminv1.OpenSessionParams{})
	if err != nil {
		return nil, err
	}
	r, err := c.Admin.OpenSession(ctx, &adminv1.OpenSessionRequest{Envelope: env})
	if err != nil {
		return nil, err
	}
	return r.SessionToken, nil
}

// CreateUser, DisableUser, BindIdentity, UnbindIdentity and RevokeCredential
// are the signed calls.

// CreateUser creates a user.
func (c *Client) CreateUser(ctx context.Context, login, display string) (*adminv1.User, error) {
	env, err := c.Sign(ctx, adminv1.AdminService_CreateUser_FullMethodName, &adminv1.CreateUserParams{Login: login, DisplayName: display})
	if err != nil {
		return nil, err
	}
	r, err := c.Admin.CreateUser(ctx, &adminv1.CreateUserRequest{Envelope: env})
	if err != nil {
		return nil, err
	}
	return r.User, nil
}

// DisableUser disables a user.
func (c *Client) DisableUser(ctx context.Context, login string) error {
	env, err := c.Sign(ctx, adminv1.AdminService_DisableUser_FullMethodName, &adminv1.DisableUserParams{Login: login})
	if err != nil {
		return err
	}
	_, err = c.Admin.DisableUser(ctx, &adminv1.DisableUserRequest{Envelope: env})
	return err
}

// BindIdentity binds (issuer, subject) to a user.
func (c *Client) BindIdentity(ctx context.Context, issuer, subject, login string) (*adminv1.Identity, error) {
	env, err := c.Sign(ctx, adminv1.AdminService_BindIdentity_FullMethodName, &adminv1.BindIdentityParams{Issuer: issuer, Subject: subject, Login: login})
	if err != nil {
		return nil, err
	}
	r, err := c.Admin.BindIdentity(ctx, &adminv1.BindIdentityRequest{Envelope: env})
	if err != nil {
		return nil, err
	}
	return r.Identity, nil
}

// UnbindIdentity removes a binding.
func (c *Client) UnbindIdentity(ctx context.Context, issuer, subject string) error {
	env, err := c.Sign(ctx, adminv1.AdminService_UnbindIdentity_FullMethodName, &adminv1.UnbindIdentityParams{Issuer: issuer, Subject: subject})
	if err != nil {
		return err
	}
	_, err = c.Admin.UnbindIdentity(ctx, &adminv1.UnbindIdentityRequest{Envelope: env})
	return err
}

// RevokeCredential revokes an admin credential.
func (c *Client) RevokeCredential(ctx context.Context, id []byte) error {
	env, err := c.Sign(ctx, adminv1.AdminService_RevokeAdminCredential_FullMethodName, &adminv1.RevokeAdminCredentialParams{CredentialId: id})
	if err != nil {
		return err
	}
	_, err = c.Admin.RevokeAdminCredential(ctx, &adminv1.RevokeAdminCredentialRequest{Envelope: env})
	return err
}
