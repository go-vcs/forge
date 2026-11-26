// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminsrv

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/store"
)

func sshKeyPB(k store.SSHKey) *adminv1.SSHKey {
	return &adminv1.SSHKey{
		Fingerprint: k.Key.Fingerprint, Login: k.Login, KeyType: k.Key.Type,
		SecurityKey: k.Key.SecurityKey, Comment: k.Key.Comment, CreatedAt: timestamppb.New(k.CreatedAt),
	}
}

// AddSSHKey implements AdminService.
func (a *Admin) AddSSHKey(ctx context.Context, r *adminv1.AddSSHKeyRequest) (_ *adminv1.AddSSHKeyResponse, err error) {
	raw, x, err := a.authorize(ctx, r.GetEnvelope())
	if err != nil {
		return nil, err
	}
	defer func() { a.finish(ctx, x, err) }()
	var p adminv1.AddSSHKeyParams
	if err := parse(raw, &p); err != nil {
		return nil, err
	}
	k, err := a.Store.AddSSHKey(ctx, p.Login, p.PublicKey)
	if err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.AddSSHKeyResponse{Key: sshKeyPB(k)}, nil
}

// ListSSHKeys implements AdminService.
func (a *Admin) ListSSHKeys(ctx context.Context, r *adminv1.ListSSHKeysRequest) (*adminv1.ListSSHKeysResponse, error) {
	if err := a.readOnly(ctx, r.GetSessionToken()); err != nil {
		return nil, err
	}
	ks, err := a.Store.ListSSHKeys(ctx, r.GetLogin())
	if err != nil {
		return nil, mapErr(err)
	}
	out := &adminv1.ListSSHKeysResponse{}
	for _, k := range ks {
		out.Keys = append(out.Keys, sshKeyPB(k))
	}
	return out, nil
}

// RemoveSSHKey implements AdminService.
func (a *Admin) RemoveSSHKey(ctx context.Context, r *adminv1.RemoveSSHKeyRequest) (_ *adminv1.RemoveSSHKeyResponse, err error) {
	raw, x, err := a.authorize(ctx, r.GetEnvelope())
	if err != nil {
		return nil, err
	}
	defer func() { a.finish(ctx, x, err) }()
	var p adminv1.RemoveSSHKeyParams
	if err := parse(raw, &p); err != nil {
		return nil, err
	}
	if err := a.Store.RemoveSSHKey(ctx, p.Fingerprint); err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.RemoveSSHKeyResponse{}, nil
}

// GetPolicy implements AdminService.
func (a *Admin) GetPolicy(ctx context.Context, r *adminv1.GetPolicyRequest) (*adminv1.GetPolicyResponse, error) {
	if err := a.readOnly(ctx, r.GetSessionToken()); err != nil {
		return nil, err
	}
	p, err := a.Store.GetPolicy(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.GetPolicyResponse{Policy: &adminv1.Policy{RequireSkSshKeys: p.RequireSKKeys}}, nil
}

// SetPolicy implements AdminService.
func (a *Admin) SetPolicy(ctx context.Context, r *adminv1.SetPolicyRequest) (_ *adminv1.SetPolicyResponse, err error) {
	raw, x, err := a.authorize(ctx, r.GetEnvelope())
	if err != nil {
		return nil, err
	}
	defer func() { a.finish(ctx, x, err) }()
	var p adminv1.SetPolicyParams
	if err := parse(raw, &p); err != nil {
		return nil, err
	}
	if err := a.Store.SetPolicy(ctx, store.Policy{RequireSKKeys: p.GetPolicy().GetRequireSkSshKeys()}); err != nil {
		return nil, mapErr(err)
	}
	return &adminv1.SetPolicyResponse{}, nil
}
