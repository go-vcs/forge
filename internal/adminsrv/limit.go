// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminsrv

import (
	"net"
	"sync"
)

// Connection caps of the admin listener.
const (
	MaxConns        = 256
	MaxConnsPerHost = 16
)

// LimitListener wraps ln so that at most maxTotal connections are open at once,
// and at most maxPerHost from one remote host. A connection over either cap is
// closed at once, unserved: waiting would let a peer that holds its slots idle
// keep every administrator out, while a refusal costs the server nothing. The
// per-host cap keeps one address from taking the total.
func LimitListener(ln net.Listener, maxTotal, maxPerHost int) net.Listener {
	return &limited{Listener: ln, maxTotal: maxTotal, maxPerHost: maxPerHost, perHost: map[string]int{}}
}

type limited struct {
	net.Listener
	maxTotal, maxPerHost int

	mu      sync.Mutex
	total   int
	perHost map[string]int
}

func hostOf(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

func (l *limited) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host := hostOf(c.RemoteAddr())
		l.mu.Lock()
		if l.total >= l.maxTotal || l.perHost[host] >= l.maxPerHost {
			l.mu.Unlock()
			c.Close()
			continue
		}
		l.total++
		l.perHost[host]++
		l.mu.Unlock()
		return &limitedConn{Conn: c, l: l, host: host}, nil
	}
}

type limitedConn struct {
	net.Conn
	l    *limited
	host string
	once sync.Once
}

func (c *limitedConn) Close() error {
	c.once.Do(func() {
		c.l.mu.Lock()
		c.l.total--
		if c.l.perHost[c.host]--; c.l.perHost[c.host] == 0 {
			delete(c.l.perHost, c.host)
		}
		c.l.mu.Unlock()
	})
	return c.Conn.Close()
}
