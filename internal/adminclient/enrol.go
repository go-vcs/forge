// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminclient

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminauth"
)

// DialUnix connects to the local enrolment socket. The transport is a Unix
// socket protected by file permissions, so there is no TLS.
func DialUnix(path string) (*grpc.ClientConn, error) {
	return grpc.NewClient("passthrough:///enrol", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}))
}

// Enrol registers a new credential on the key with the forge behind conn and
// returns what the server stored.
func Enrol(ctx context.Context, conn grpc.ClientConnInterface, s Signer, name string) (*adminv1.AdminCredential, error) {
	e := adminv1.NewEnrolServiceClient(conn)
	b, err := e.BeginEnrol(ctx, &adminv1.BeginEnrolRequest{})
	if err != nil {
		return nil, err
	}
	cdh := adminauth.EnrolClientDataHash(b.Challenge, name)
	format, ad, stmt, err := s.Make(ctx, b.RpId, b.UserHandle, name, cdh)
	if err != nil {
		return nil, err
	}
	r, err := e.FinishEnrol(ctx, &adminv1.FinishEnrolRequest{
		Challenge: b.Challenge, Name: name, AuthenticatorData: ad, AttestationFormat: format, AttestationStatement: stmt,
	})
	if err != nil {
		return nil, err
	}
	return r.Credential, nil
}
