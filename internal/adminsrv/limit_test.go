// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminsrv_test

import (
	"errors"
	"net"
	"testing"

	"github.com/go-vcs/forge/internal/adminsrv"
)

type namedAddr string

func (a namedAddr) Network() string { return "test" }
func (a namedAddr) String() string  { return string(a) }

type fakeConn struct {
	net.Conn
	addr   net.Addr
	closed bool
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.addr }
func (c *fakeConn) Close() error         { c.closed = true; return nil }

// queueListener hands out its connections, then fails with errDone.
type queueListener struct {
	net.Listener
	conns []net.Conn
}

var errDone = errors.New("listener done")

func (l *queueListener) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, errDone
	}
	c := l.conns[0]
	l.conns = l.conns[1:]
	return c, nil
}

func TestLimitListenerKeepsAddressesWithoutAPortApart(t *testing.T) {
	a, b := &fakeConn{addr: namedAddr("peer-a")}, &fakeConn{addr: namedAddr("peer-b")}
	ln := adminsrv.LimitListener(&queueListener{conns: []net.Conn{a, b}}, 10, 1)
	for _, want := range []*fakeConn{a, b} {
		c, err := ln.Accept()
		if err != nil {
			t.Fatalf("Accept: %v (two different peers share no per-host slot)", err)
		}
		if c == nil || want.closed {
			t.Fatalf("a connection of a distinct peer was refused")
		}
	}
}

func TestLimitListenerPassesTheListenerErrorOn(t *testing.T) {
	ln := adminsrv.LimitListener(&queueListener{}, 10, 1)
	c, err := ln.Accept()
	if !errors.Is(err, errDone) || c != nil {
		t.Fatalf("Accept = %v, %v; want the listener's error and no connection", c, err)
	}
}
