// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminsrv

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/secretbox"
	"github.com/go-vcs/forge/internal/store"
)

// OIDCSecretPurpose is the secretbox purpose of the stored client secret.
const OIDCSecretPurpose = "go-vcs oidc client secret v1"

// sealStatus is the answer to a secret that could not be sealed: no key is the
// caller's to fix, anything else is the server's.
func sealStatus(err error) error {
	if errors.Is(err, secretbox.ErrNoKey) {
		return status.Error(codes.FailedPrecondition, "the server has no secrets key (--secrets-key or credential secrets.key): it will not store a secret in clear")
	}
	return status.Error(codes.Internal, "internal error")
}

// GetOIDCClient implements AdminService. The secret is never returned.
func (a *Admin) GetOIDCClient(ctx context.Context, r *adminv1.GetOIDCClientRequest) (*adminv1.GetOIDCClientResponse, error) {
	if err := a.readOnly(ctx, r.GetSessionToken()); err != nil {
		return nil, err
	}
	c, err := a.Store.GetOIDCClient(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return &adminv1.GetOIDCClientResponse{}, nil
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.GetOIDCClientResponse{Client: &adminv1.OIDCClient{
		Issuer: c.Issuer, ClientId: c.ClientID, RedirectUri: c.RedirectURI,
		HasSecret: len(c.SecretSealed) > 0, UpdatedAt: timestamppb.New(c.UpdatedAt),
	}}, nil
}

// SetOIDCClient implements AdminService. The secret is sealed before it is
// stored; without a sealing key a secret is refused, never stored in clear.
func (a *Admin) SetOIDCClient(ctx context.Context, r *adminv1.SetOIDCClientRequest) (_ *adminv1.SetOIDCClientResponse, err error) {
	raw, x, err := a.authorize(ctx, r.GetEnvelope())
	if err != nil {
		return nil, err
	}
	defer func() { a.finish(ctx, x, err) }()
	var p adminv1.SetOIDCClientParams
	if err := parse(raw, &p); err != nil {
		return nil, err
	}
	if len(p.ClientSecret) > store.MaxClientSecret {
		return nil, status.Error(codes.InvalidArgument, "client secret too long")
	}
	c := store.OIDCClient{Issuer: p.Issuer, ClientID: p.ClientId, RedirectURI: p.RedirectUri}
	if len(p.ClientSecret) > 0 {
		if c.SecretSealed, err = a.Seal.Seal(p.ClientSecret, OIDCSecretPurpose); err != nil {
			return nil, sealStatus(err)
		}
	}
	if err := a.Store.SetOIDCClient(ctx, c); err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.SetOIDCClientResponse{}, nil
}
