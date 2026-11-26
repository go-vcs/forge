// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv_test

import (
	"testing"

	"google.golang.org/grpc/codes"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/sshtest"
)

func TestSSHKeysAndPolicyThroughTheAPI(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	ctx := t.Context()
	if _, err := c.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatal(err)
	}
	k := sshtest.NewEd25519(t)
	got, err := c.AddSSHKey(ctx, "alice", k.Line+" laptop")
	if err != nil || got.Fingerprint != k.Fingerprint || got.Login != "alice" || got.SecurityKey || got.Comment != "laptop" || got.CreatedAt == nil {
		t.Fatalf("AddSSHKey = %+v, %v", got, err)
	}
	if _, err := c.AddSSHKey(ctx, "alice", k.Line); code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate = %v", err)
	}
	if _, err := c.AddSSHKey(ctx, "ghost", sshtest.NewEd25519(t).Line); code(err) != codes.NotFound {
		t.Fatalf("unknown user = %v", err)
	}
	if _, err := c.AddSSHKey(ctx, "alice", `no-pty `+k.Line); code(err) != codes.InvalidArgument {
		t.Fatalf("options = %v", err)
	}

	tok, err := c.OpenSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := c.Admin.ListSSHKeys(ctx, &adminv1.ListSSHKeysRequest{SessionToken: tok})
	if err != nil || len(ks.Keys) != 1 || ks.Keys[0].Fingerprint != k.Fingerprint {
		t.Fatalf("ListSSHKeys = %v, %v", ks, err)
	}
	if _, err := c.Admin.ListSSHKeys(ctx, &adminv1.ListSSHKeysRequest{}); code(err) != codes.Unauthenticated {
		t.Fatalf("list without a session = %v", err)
	}

	// The policy: default off, then on, and a plain key is refused.
	p, err := c.Admin.GetPolicy(ctx, &adminv1.GetPolicyRequest{SessionToken: tok})
	if err != nil || p.Policy.RequireSkSshKeys {
		t.Fatalf("default policy = %v, %v", p, err)
	}
	if _, err := c.Admin.GetPolicy(ctx, &adminv1.GetPolicyRequest{}); code(err) != codes.Unauthenticated {
		t.Fatalf("policy without a session = %v", err)
	}
	if err := c.SetPolicy(ctx, &adminv1.Policy{RequireSkSshKeys: true}); err != nil {
		t.Fatal(err)
	}
	if p, err = c.Admin.GetPolicy(ctx, &adminv1.GetPolicyRequest{SessionToken: tok}); err != nil || !p.Policy.RequireSkSshKeys {
		t.Fatalf("policy after set = %v, %v", p, err)
	}
	if _, err := c.AddSSHKey(ctx, "alice", sshtest.NewEd25519(t).Line); code(err) != codes.InvalidArgument {
		t.Fatalf("plain key under the policy = %v", err)
	}
	if sk, err := c.AddSSHKey(ctx, "alice", sshtest.SKLine(t)); err != nil || !sk.SecurityKey {
		t.Fatalf("sk key = %v, %v", sk, err)
	}

	if err := c.RemoveSSHKey(ctx, k.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveSSHKey(ctx, k.Fingerprint); code(err) != codes.NotFound {
		t.Fatalf("remove twice = %v", err)
	}
}

// Every mutating SSH call needs the FIDO2 envelope: without one nothing changes.
func TestSSHKeyCallsRefuseWithoutAnEnvelope(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	ctx := t.Context()
	if _, err := c.CreateUser(ctx, "alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Admin.AddSSHKey(ctx, &adminv1.AddSSHKeyRequest{}); code(err) != codes.InvalidArgument {
		t.Fatalf("AddSSHKey without envelope = %v", err)
	}
	if _, err := c.Admin.RemoveSSHKey(ctx, &adminv1.RemoveSSHKeyRequest{}); code(err) != codes.InvalidArgument {
		t.Fatalf("RemoveSSHKey without envelope = %v", err)
	}
	if _, err := c.Admin.SetPolicy(ctx, &adminv1.SetPolicyRequest{}); code(err) != codes.InvalidArgument {
		t.Fatalf("SetPolicy without envelope = %v", err)
	}
	// An envelope for another method is refused too.
	env := f.envelope(c, createMethod, &adminv1.AddSSHKeyParams{Login: "alice", PublicKey: sshtest.NewEd25519(t).Line}, tweak{})
	if _, err := c.Admin.AddSSHKey(ctx, &adminv1.AddSSHKeyRequest{Envelope: env}); code(err) != codes.Unauthenticated {
		t.Fatalf("envelope signed for CreateUser accepted: %v", err)
	}
	tok, _ := c.OpenSession(ctx)
	if ks, err := c.Admin.ListSSHKeys(ctx, &adminv1.ListSSHKeysRequest{SessionToken: tok}); err != nil || len(ks.Keys) != 0 {
		t.Fatalf("keys exist after refused calls: %v %v", ks, err)
	}
}

func TestSSHKeyBadParameters(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	for name, call := range map[string]func(env *adminv1.Envelope) error{
		"add": func(e *adminv1.Envelope) error {
			_, err := c.Admin.AddSSHKey(t.Context(), &adminv1.AddSSHKeyRequest{Envelope: e})
			return err
		},
		"remove": func(e *adminv1.Envelope) error {
			_, err := c.Admin.RemoveSSHKey(t.Context(), &adminv1.RemoveSSHKeyRequest{Envelope: e})
			return err
		},
		"policy": func(e *adminv1.Envelope) error {
			_, err := c.Admin.SetPolicy(t.Context(), &adminv1.SetPolicyRequest{Envelope: e})
			return err
		},
	} {
		method := map[string]string{
			"add": adminv1.AdminService_AddSSHKey_FullMethodName, "remove": adminv1.AdminService_RemoveSSHKey_FullMethodName,
			"policy": adminv1.AdminService_SetPolicy_FullMethodName,
		}[name]
		env := f.envelope(c, method, nil, tweak{rawReq: []byte{0xff, 0xff}})
		if err := call(env); code(err) != codes.InvalidArgument {
			t.Fatalf("%s with garbage parameters = %v", name, err)
		}
	}
}
