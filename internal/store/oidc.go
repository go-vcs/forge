// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-authn/harden/redirect"
)

// OIDCClient is the forge's registration at the identity bridge.
type OIDCClient struct {
	Issuer, ClientID, RedirectURI string
	// SecretSealed is secretbox ciphertext; nil for a public client.
	SecretSealed []byte
	UpdatedAt    time.Time
}

// Limits of an OIDC registration.
const (
	MaxClientIDLen    = 256
	MaxRedirectURILen = 512
	MaxClientSecret   = 1024
)

// ValidRedirectURI accepts an absolute https (or loopback http) URL with no
// fragment or userinfo (RFC 6749 §3.1.2).
func ValidRedirectURI(s string) error {
	if err := validText("redirect_uri", s, MaxRedirectURILen, false); err != nil {
		return err
	}
	u, err := url.Parse(s)
	if err != nil || u.Fragment != "" || u.User != nil || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("%w: redirect_uri must be an absolute URL without fragment or userinfo", ErrInvalid)
	}
	if err := redirect.HTTPSOrLoopback(s); err != nil {
		return fmt.Errorf("%w: redirect_uri: %v", ErrInvalid, err)
	}
	return nil
}

// SetOIDCClient replaces the registration.
func (s *Store) SetOIDCClient(ctx context.Context, c OIDCClient) error {
	if err := ValidIssuer(c.Issuer); err != nil {
		return err
	}
	if err := validText("client_id", c.ClientID, MaxClientIDLen, false); err != nil {
		return err
	}
	if err := ValidRedirectURI(c.RedirectURI); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO oidc_client (id, issuer, client_id, redirect_uri, secret_sealed, updated_at)
		VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET issuer = excluded.issuer, client_id = excluded.client_id,
		redirect_uri = excluded.redirect_uri, secret_sealed = excluded.secret_sealed, updated_at = excluded.updated_at`,
		c.Issuer, c.ClientID, c.RedirectURI, c.SecretSealed, s.now().Unix())
	return err
}

// GetOIDCClient returns the registration, or ErrNotFound.
func (s *Store) GetOIDCClient(ctx context.Context) (OIDCClient, error) {
	var (
		c   OIDCClient
		at  int64
		sec []byte
	)
	err := s.db.QueryRowContext(ctx, `SELECT issuer, client_id, redirect_uri, secret_sealed, updated_at FROM oidc_client WHERE id = 1`).
		Scan(&c.Issuer, &c.ClientID, &c.RedirectURI, &sec, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return OIDCClient{}, ErrNotFound
	}
	if err != nil {
		return OIDCClient{}, err
	}
	c.SecretSealed = sec
	c.UpdatedAt = time.Unix(at, 0).UTC()
	return c, nil
}

// LoginForIdentity returns the login an (issuer, subject) is bound to, if the
// account is enabled. Every other case, unbound included, is ErrNotAuthorized:
// a sign-in never creates an account and the reason is not an oracle.
func (s *Store) LoginForIdentity(ctx context.Context, issuer, subject string) (string, error) {
	var login string
	err := s.db.QueryRowContext(ctx, `SELECT u.login FROM identities i JOIN users u ON u.id = i.user_id
		WHERE i.issuer = ? AND i.subject = ? AND u.disabled_at IS NULL`, issuer, subject).Scan(&login)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotAuthorized
	}
	return login, err
}
