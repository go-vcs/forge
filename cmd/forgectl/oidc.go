// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminclient"
	"github.com/go-vcs/forge/internal/store"
)

// promptSecret reads a secret from the terminal without echo. Tests replace it.
var promptSecret = func(cmd *cobra.Command, label string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("stdin is not a terminal: give the secret on an inherited file descriptor with --secret-fd")
	}
	fmt.Fprint(cmd.ErrOrStderr(), label)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	return b, err
}

// openFD opens an inherited descriptor. Tests replace it.
var openFD = func(fd int) io.ReadCloser { return os.NewFile(uintptr(fd), "secret-fd") }

// readSecretFD reads one bounded secret from fd and drops one trailing newline.
func readSecretFD(fd int) ([]byte, error) {
	if fd < 3 {
		return nil, errors.New("--secret-fd must be an inherited descriptor, 3 or above")
	}
	f := openFD(fd)
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, store.MaxClientSecret+2))
	if err != nil {
		return nil, fmt.Errorf("--secret-fd: %w", err)
	}
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	if len(b) > store.MaxClientSecret {
		return nil, fmt.Errorf("--secret-fd: longer than %d bytes", store.MaxClientSecret)
	}
	return b, nil
}

func oidcCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "oidc", Short: "the web sign-in registration at the identity bridge"}
	c.AddCommand(&cobra.Command{
		Use: "show", Short: "show the registration (the secret is never shown)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.session(cmd, func(ctx context.Context, cl *adminclient.Client, tok []byte) error {
				r, err := cl.Admin.GetOIDCClient(ctx, &adminv1.GetOIDCClientRequest{SessionToken: tok})
				if err != nil {
					return err
				}
				if r.Client == nil {
					fmt.Fprintln(cmd.OutOrStdout(), "no OIDC client registered")
					return nil
				}
				k := r.Client
				fmt.Fprintf(cmd.OutOrStdout(), "issuer=%s client-id=%s redirect-uri=%s secret=%t updated=%s\n",
					k.Issuer, k.ClientId, k.RedirectUri, k.HasSecret, ts(k.UpdatedAt, k.UpdatedAt != nil))
				return nil
			})
		},
	})
	var (
		issuer, clientID, redirectURI string
		secretFD                      int
		public                        bool
	)
	set := &cobra.Command{
		Use: "set-client", Short: "replace the registration; the secret comes from a no-echo prompt or --secret-fd, never argv", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var secret []byte
			switch {
			case public && secretFD != 0:
				return errors.New("--public and --secret-fd are exclusive")
			case public:
			case secretFD != 0:
				var err error
				if secret, err = readSecretFD(secretFD); err != nil {
					return err
				}
			default:
				var err error
				if secret, err = promptSecret(cmd, "client secret: "); err != nil {
					return err
				}
			}
			if !public && len(secret) == 0 {
				return errors.New("empty secret: use --public for a client without one")
			}
			return o.signed(cmd, func(ctx context.Context, cl *adminclient.Client) error {
				if err := cl.SetOIDCClient(ctx, issuer, clientID, redirectURI, secret); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "registered %s at %s\n", clientID, issuer)
				return nil
			})
		},
	}
	f := set.Flags()
	f.StringVar(&issuer, "issuer", "", "bridge issuer `URL` (https)")
	f.StringVar(&clientID, "client-id", "", "client `id`")
	f.StringVar(&redirectURI, "redirect-uri", "", "the forge's callback `URL`, https://<forge>/callback")
	f.IntVar(&secretFD, "secret-fd", 0, "read the secret from this inherited file descriptor (3 or above)")
	f.BoolVar(&public, "public", false, "a public client: no secret, PKCE only")
	for _, n := range []string{"issuer", "client-id", "redirect-uri"} {
		_ = set.MarkFlagRequired(n)
	}
	c.AddCommand(set)
	return c
}
