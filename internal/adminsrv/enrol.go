// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminsrv

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminauth"
	"github.com/go-vcs/forge/internal/attest"
	"github.com/go-vcs/forge/internal/store"
)

// Enrolment bounds.
const (
	ChallengeTTL        = 5 * time.Minute
	MaxOpenChallenges   = 8
	maxAttestationBytes = 16 << 10
)

// Enrol is the EnrolService implementation. It must only be registered on a
// local Unix socket, and refuses any other peer even if it is not.
type Enrol struct {
	adminv1.UnimplementedEnrolServiceServer
	Store  *store.Store
	Policy *attest.Policy
	RPID   string
	Log    *slog.Logger
	Now    func() time.Time

	mu         sync.Mutex
	challenges map[[adminauth.NonceLen]byte]time.Time
}

// ErrNotLocal is the refusal for an enrolment attempt that did not arrive over
// a Unix socket.
var ErrNotLocal = errors.New("enrolment is only possible over the local socket")

func (e *Enrol) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// requireLocal refuses any peer whose transport is not a Unix socket.
func requireLocal(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil || p.Addr.Network() != "unix" {
		return status.Error(codes.PermissionDenied, ErrNotLocal.Error())
	}
	return nil
}

// BeginEnrol implements EnrolService.
func (e *Enrol) BeginEnrol(ctx context.Context, _ *adminv1.BeginEnrolRequest) (*adminv1.BeginEnrolResponse, error) {
	if err := requireLocal(ctx); err != nil {
		return nil, err
	}
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.challenges == nil {
		e.challenges = map[[adminauth.NonceLen]byte]time.Time{}
	}
	for k, exp := range e.challenges {
		if !now.Before(exp) {
			delete(e.challenges, k)
		}
	}
	if len(e.challenges) >= MaxOpenChallenges {
		return nil, status.Error(codes.ResourceExhausted, "too many open enrolments")
	}
	var ch [adminauth.NonceLen]byte
	var uh [16]byte
	rand.Read(ch[:]) // crypto/rand.Read never returns an error (it aborts the program instead)
	rand.Read(uh[:])
	exp := now.Add(ChallengeTTL)
	e.challenges[ch] = exp
	return &adminv1.BeginEnrolResponse{RpId: e.RPID, UserHandle: uh[:], Challenge: ch[:], ExpiresAt: timestamppb.New(exp)}, nil
}

func (e *Enrol) take(ch []byte) bool {
	if len(ch) != adminauth.NonceLen {
		return false
	}
	var k [adminauth.NonceLen]byte
	copy(k[:], ch)
	e.mu.Lock()
	defer e.mu.Unlock()
	exp, ok := e.challenges[k]
	delete(e.challenges, k)
	return ok && e.now().Before(exp)
}

// FinishEnrol implements EnrolService.
func (e *Enrol) FinishEnrol(ctx context.Context, r *adminv1.FinishEnrolRequest) (*adminv1.FinishEnrolResponse, error) {
	if err := requireLocal(ctx); err != nil {
		return nil, err
	}
	if len(r.AttestationStatement) > maxAttestationBytes || len(r.AuthenticatorData) > attest.MaxAuthDataLen {
		return nil, status.Error(codes.InvalidArgument, "oversized attestation")
	}
	if err := store.ValidName(r.Name); err != nil {
		return nil, mapErr(err)
	}
	if !e.take(r.Challenge) {
		return nil, status.Error(codes.FailedPrecondition, "challenge unknown, used or expired")
	}
	res, err := e.Policy.Verify(r.AttestationFormat, r.AuthenticatorData, r.AttestationStatement,
		adminauth.EnrolClientDataHash(r.Challenge, r.Name))
	if err != nil {
		if e.Log != nil {
			e.Log.Info("enrolment refused", "reason", err.Error())
		}
		return nil, status.Error(codes.PermissionDenied, "attestation refused: "+err.Error())
	}
	c, err := e.Store.AddCredential(ctx, res.CredentialID, res.PublicKey, res.AAGUID, r.Name)
	if err != nil {
		return nil, mapErr(err)
	}
	if e.Log != nil {
		e.Log.Info("admin credential enrolled", "aaguid", res.AAGUID, "name", r.Name)
	}
	return &adminv1.FinishEnrolResponse{Credential: credPB(c)}, nil
}
