// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminauth_test

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminauth"
)

// patch applies a mutation to b: truncate to trunc bytes when 0 < trunc < len,
// then xor one byte.
func patch(b []byte, off, x, trunc int) []byte {
	out := append([]byte(nil), b...)
	if trunc > 0 && trunc < len(out) {
		out = out[:trunc]
	}
	if len(out) > 0 && x != 0 {
		if off < 0 {
			off = -off
		}
		out[off%len(out)] ^= byte(x)
	}
	return out
}

// FuzzVerify mutates a valid call field by field (or replaces a field outright)
// and checks that Verify never panics and accepts only a call whose request,
// nonce, credential and authenticator data are exactly the signed ones. (The
// signature field is excluded from that equality: ECDSA signatures are
// malleable, and a different encoding of a valid signature is still valid.)
func FuzzVerify(f *testing.F) {
	f.Add(0, 0, 0, 0, []byte(nil))
	f.Add(1, 36, 1, 0, []byte(nil))
	f.Add(2, 5, 255, 0, []byte(nil))
	f.Add(3, 0, 1, 0, []byte(nil))
	f.Add(4, 31, 128, 0, []byte(nil))
	f.Add(1, 0, 0, 10, []byte(nil))
	f.Add(6, 0, 0, 0, []byte("not authenticator data"))
	f.Add(7, 0, 0, 0, bytes.Repeat([]byte{0x30}, 200))
	f.Fuzz(func(t *testing.T, sel, off, x, trunc int, raw []byte) {
		e := newEnv(t)
		good := e.good(t)
		in := good
		in.CredentialID = append([]byte(nil), good.CredentialID...)
		in.AuthenticatorData = append([]byte(nil), good.AuthenticatorData...)
		in.Signature = append([]byte(nil), good.Signature...)
		in.Request = append([]byte(nil), good.Request...)
		in.Nonce = append([]byte(nil), good.Nonce...)
		if sel < 0 {
			sel = -sel
		}
		switch sel % 10 {
		case 0:
			in.CredentialID = patch(good.CredentialID, off, x, trunc)
		case 1:
			in.AuthenticatorData = patch(good.AuthenticatorData, off, x, trunc)
		case 2:
			in.Signature = patch(good.Signature, off, x, trunc)
		case 3:
			in.Request = patch(good.Request, off, x, trunc)
		case 4:
			in.Nonce = patch(good.Nonce, off, x, trunc)
		case 5:
			in.CredentialID = raw
		case 6:
			in.AuthenticatorData = raw
		case 7:
			in.Signature = raw
		case 8:
			in.Request = raw
		case 9:
			in.Nonce = raw
		}
		_, err := e.v.Verify(context.Background(), in)
		if err != nil {
			return
		}
		if !bytes.Equal(in.Request, good.Request) || !bytes.Equal(in.Nonce, good.Nonce) ||
			!bytes.Equal(in.CredentialID, good.CredentialID) || !bytes.Equal(in.AuthenticatorData, good.AuthenticatorData) {
			t.Fatalf("accepted a call that differs from the signed one: %+v", in)
		}
	})
}

// FuzzEnvelope feeds arbitrary bytes through the protobuf envelope parser and
// into Verify. No such input can be a valid assertion, so every one must be
// refused, and none may panic.
func FuzzEnvelope(f *testing.F) {
	good, _ := proto.Marshal(&adminv1.Envelope{
		Nonce: bytes.Repeat([]byte{1}, 32), Request: []byte("r"), CredentialId: []byte("c"),
		AuthenticatorData: bytes.Repeat([]byte{2}, 37), Signature: bytes.Repeat([]byte{3}, 70),
	})
	f.Add(good)
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Add(bytes.Repeat([]byte{0x0a, 0x00}, 100))
	e := newEnv(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		var env adminv1.Envelope
		if proto.Unmarshal(b, &env) != nil {
			return
		}
		_, err := e.v.Verify(context.Background(), adminauth.Input{
			Method: method, Nonce: env.Nonce, Request: env.Request, Exporter: exporterA,
			Assertion: adminauth.Assertion{CredentialID: env.CredentialId, AuthenticatorData: env.AuthenticatorData, Signature: env.Signature},
		})
		if err == nil {
			t.Fatalf("an arbitrary envelope was accepted: %x", b)
		}
	})
}
