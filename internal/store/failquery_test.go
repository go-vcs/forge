// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store_test

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/go-vcs/forge/internal/store"
)

// failQueries wraps the real driver: once fail is set, statements still run but
// every query that returns rows fails.
var failQueries atomic.Bool

type queryFailDriver struct{ driver.Driver }

func (d queryFailDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	return queryFailConn{c}, nil
}

type queryFailConn struct{ driver.Conn }

func (c queryFailConn) Prepare(q string) (driver.Stmt, error) {
	s, err := c.Conn.Prepare(q)
	if err != nil {
		return nil, err
	}
	return queryFailStmt{s}, nil
}

type queryFailStmt struct{ driver.Stmt }

func (s queryFailStmt) Query(args []driver.Value) (driver.Rows, error) {
	if failQueries.Load() {
		return nil, errors.New("injected query failure")
	}
	return s.Stmt.Query(args)
}

func init() {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		panic(err)
	}
	sql.Register("sqlite-failquery", queryFailDriver{db.Driver()})
	db.Close()
}

func TestRevokeReportsAFailedLookup(t *testing.T) {
	defer store.UseDriver("sqlite-failquery")()
	s, err := store.Open(t.Context(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	failQueries.Store(true)
	defer failQueries.Store(false)
	// No such credential: the update matches nothing, then the lookup that tells
	// "unknown" from "last" fails, and that failure is what the caller gets.
	err = s.RevokeCredential(t.Context(), []byte{9})
	wantErr(t, "RevokeCredential", err, "injected query failure")
}
