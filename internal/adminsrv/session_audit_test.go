// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv_test

import (
	"testing"

	"google.golang.org/grpc/codes"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/store"
)

func TestRevokingACredentialEndsItsSessionsAtOnce(t *testing.T) {
	f := newForge(t)
	first, err := f.enrolKey("first")
	if err != nil {
		t.Fatal(err)
	}
	c1 := f.dial() // signs with the first key
	tok1, err := c1.OpenSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.auth.Key = nil // the next enrolment is a different credential
	if _, err := f.enrolKey("second"); err != nil {
		t.Fatal(err)
	}
	c2 := f.dial() // signs with the second key
	tok2, err := c2.OpenSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	readAll := func(which string, tok []byte, want codes.Code) {
		t.Helper()
		c := c1
		if which == "second" {
			c = c2
		}
		ctx := t.Context()
		_, e1 := c.Admin.ListUsers(ctx, &adminv1.ListUsersRequest{SessionToken: tok})
		_, e2 := c.Admin.ListIdentities(ctx, &adminv1.ListIdentitiesRequest{SessionToken: tok})
		_, e3 := c.Admin.ListAdminCredentials(ctx, &adminv1.ListAdminCredentialsRequest{SessionToken: tok})
		for i, e := range []error{e1, e2, e3} {
			if code(e) != want {
				t.Fatalf("%s session, read %d: %v, want %v", which, i, e, want)
			}
		}
	}
	readAll("first", tok1, codes.OK)
	readAll("second", tok2, codes.OK)

	// The second key revokes the first: the first key's open session dies on
	// its very next read, and the second key's session is untouched.
	if err := c2.RevokeCredential(t.Context(), first.CredentialId); err != nil {
		t.Fatal(err)
	}
	readAll("first", tok1, codes.Unauthenticated)
	readAll("second", tok2, codes.OK)
}

func TestAuditRecordsTheAttemptAndItsOutcome(t *testing.T) {
	f := newForge(t)
	f.mustEnrol()
	c := f.dial()
	ctx := t.Context()

	// A refused assertion leaves no row: nothing was authorized.
	bad := f.envelope(c, createMethod, params("nope"), tweak{mutate: func(e *adminv1.Envelope) { e.Signature[0] ^= 1 }})
	if err := createUser(c, bad); code(err) != codes.Unauthenticated {
		t.Fatalf("bad signature: %v", err)
	}
	if n, _ := f.st.AuditCount(ctx); n != 0 {
		t.Fatalf("a refused assertion left %d audit rows", n)
	}

	if _, err := c.CreateUser(ctx, "alice", "Alice"); err != nil { // succeeds
		t.Fatal(err)
	}
	if _, err := c.CreateUser(ctx, "alice", "again"); code(err) != codes.AlreadyExists { // fails after authorization
		t.Fatalf("duplicate: %v", err)
	}

	rows, err := f.st.AuditRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{store.OutcomeAttempt, store.OutcomeSuccess, store.OutcomeAttempt, store.OutcomeFailure}
	if len(rows) != len(want) {
		t.Fatalf("%d rows, want %d: %+v", len(rows), len(want), rows)
	}
	for i, r := range rows {
		if r.Outcome != want[i] || r.Method != createMethod || string(r.CredentialID) != string(f.auth.CredID) {
			t.Fatalf("row %d = %+v, want %s %s", i, r, createMethod, want[i])
		}
	}
}
