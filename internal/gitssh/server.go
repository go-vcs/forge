// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package gitssh serves git clone and fetch (protocol v2, git-upload-pack) over
// SSH, in process, with golang.org/x/crypto/ssh. A client signs in with a
// public key a user registered through the admin API; the only thing it can do
// afterwards is run git-upload-pack on a repository it may read. There is no
// shell, no pty, no subsystem, no forwarding of any kind, no other channel.
package gitssh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/gitrepo"
)

// Authenticator maps a key fingerprint to the account that registered it.
type Authenticator interface {
	AuthenticateSSHKey(ctx context.Context, fingerprint string) (login string, err error)
}

// Bounds on one connection.
const (
	MaxAuthTries     = 3
	MaxPreExec       = 16 // channel requests tolerated before the exec
	MaxEnvValueLen   = 256
	DefaultHandshake = 10 * time.Second
	DefaultIdle      = 30 * time.Second // from the session channel to its exec
)

// Server is the SSH git server.
type Server struct {
	Auth     Authenticator
	Repos    *gitrepo.Service
	Sessions *gitrepo.Limiter // keyed by account; Total and PerKey caps
	HostKey  ssh.Signer
	Log      *slog.Logger

	// RequestTimeout bounds one whole git session (0: gitrepo's default).
	RequestTimeout time.Duration
	// Handshake bounds the SSH handshake and authentication (0: 10 s).
	Handshake time.Duration
	// Idle bounds the wait for the exec once a session channel is open (0: 30 s).
	Idle time.Duration
	// MaxConns and MaxConnsPerHost cap open TCP connections (0: the admin
	// listener's caps).
	MaxConns, MaxConnsPerHost int
}

func (s *Server) config(ctx context.Context) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		MaxAuthTries:  MaxAuthTries,
		ServerVersion: "SSH-2.0-govcs-forge",
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			login, err := s.Auth.AuthenticateSSHKey(ctx, ssh.FingerprintSHA256(key))
			if err != nil {
				// The reason (unknown key, disabled user, policy) stays in the
				// server: the client learns only that the key was not accepted.
				s.Log.Debug("ssh key refused", "remote", c.RemoteAddr().String(), "err", err)
				return nil, errors.New("key not accepted")
			}
			return &ssh.Permissions{Extensions: map[string]string{"login": login}}, nil
		},
	}
	cfg.AddHostKey(s.HostKey)
	return cfg
}

// Serve accepts connections on ln until ctx ends or ln fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	maxConns, perHost := s.MaxConns, s.MaxConnsPerHost
	if maxConns == 0 {
		maxConns = adminsrv.MaxConns
	}
	if perHost == 0 {
		perHost = adminsrv.MaxConnsPerHost
	}
	ln = adminsrv.LimitListener(ln, maxConns, perHost)
	cfg := s.config(ctx)
	go func() { <-ctx.Done(); ln.Close() }()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, cfg, c)
		}()
	}
}

func (s *Server) handle(ctx context.Context, cfg *ssh.ServerConfig, nc net.Conn) {
	defer nc.Close()
	hs := s.Handshake
	if hs <= 0 {
		hs = DefaultHandshake
	}
	nc.SetDeadline(time.Now().Add(hs))
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	nc.SetDeadline(time.Time{})
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	login := conn.Permissions.Extensions["login"]
	go ssh.DiscardRequests(reqs) // global requests, port forwarding among them: all refused

	var active sync.Mutex // one session channel at a time per connection
	var wg sync.WaitGroup
	defer wg.Wait()
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "only session channels are accepted")
			continue
		}
		if !active.TryLock() {
			nch.Reject(ssh.ResourceShortage, "one session at a time")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			active.Unlock()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer active.Unlock()
			s.session(ctx, login, ch, creqs)
		}()
	}
}

// reply answers a channel request when it asked for an answer.
func reply(r *ssh.Request, ok bool) {
	if r.WantReply {
		r.Reply(ok, nil)
	}
}

func (s *Server) session(ctx context.Context, login string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	idle := s.Idle
	if idle <= 0 {
		idle = DefaultIdle
	}
	timer := time.AfterFunc(idle, func() { ch.Close() })
	defer timer.Stop()

	var v2 bool
	for n := 0; ; n++ {
		var r *ssh.Request
		select {
		case r = <-reqs:
		case <-ctx.Done():
			return
		}
		if r == nil || n >= MaxPreExec {
			return
		}
		switch r.Type {
		case "env":
			var e struct{ Name, Value string }
			ok := ssh.Unmarshal(r.Payload, &e) == nil && e.Name == "GIT_PROTOCOL" && len(e.Value) <= MaxEnvValueLen
			if ok {
				v2 = wantsV2(e.Value)
			}
			reply(r, ok)
		case "exec":
			var e struct{ Command string }
			if ssh.Unmarshal(r.Payload, &e) != nil {
				reply(r, false)
				return
			}
			reply(r, true)
			timer.Stop()
			s.run(ctx, login, e.Command, v2, ch)
			return
		default: // pty-req, shell, subsystem, x11-req, auth-agent-req@openssh.com, window-change, signal...
			reply(r, false)
		}
	}
}

func exit(ch ssh.Channel, status uint32) {
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}

func fail(ch ssh.Channel, format string, a ...any) {
	fmt.Fprintf(ch.Stderr(), "forge: "+format+"\n", a...)
	exit(ch, 1)
}

func (s *Server) run(ctx context.Context, login, command string, v2 bool, ch ssh.Channel) {
	name, err := ParseExec(command)
	if err != nil {
		fail(ch, "%v", err)
		return
	}
	if !v2 {
		fail(ch, "git protocol version 2 is required (git 2.26 or later; set GIT_PROTOCOL=version=2)")
		return
	}
	srv, err := s.Repos.Open(name, login)
	if err != nil {
		fail(ch, "%v: %s", err, name)
		return
	}
	release, err := s.Sessions.Acquire(login)
	if err != nil {
		fail(ch, "%v: try again later", err)
		return
	}
	defer release()
	ctx, cancel := gitrepo.WithTimeout(ctx, s.RequestTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { ch.Close() }) // unblocks a read or write on a stalled client
	defer stop()
	if err := srv.Serve(ctx, ch, ch); err != nil {
		s.Log.Info("git session ended", "login", login, "repo", name.String(), "err", err)
		if ctx.Err() == nil {
			exit(ch, 1)
		}
		return
	}
	exit(ch, 0)
}
