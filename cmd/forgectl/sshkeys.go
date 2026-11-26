// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminclient"
	"github.com/go-vcs/forge/internal/sshkeys"
)

// readKeyFile reads one public key line from path, or from stdin for "-". The
// read is bounded: a public key is never large.
func readKeyFile(cmd *cobra.Command, path string) (string, error) {
	var r io.Reader = cmd.InOrStdin()
	if path != "-" {
		f, err := openFile(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, sshkeys.MaxLineLen+1))
	if err != nil {
		return "", err
	}
	if len(b) > sshkeys.MaxLineLen {
		return "", fmt.Errorf("%s: longer than %d bytes", path, sshkeys.MaxLineLen)
	}
	return string(b), nil
}

func sshKeysCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "ssh-keys", Short: "register, list and remove users' SSH public keys"}
	c.AddCommand(&cobra.Command{
		Use: "add <login> <public-key-file|->", Short: "register a public key (an authorized_keys line, no options) for a user",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			line, err := readKeyFile(cmd, args[1])
			if err != nil {
				return err
			}
			return o.signed(cmd, func(ctx context.Context, cl *adminclient.Client) error {
				k, err := cl.AddSSHKey(ctx, args[0], line)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "added %s %s to %s\n", k.KeyType, k.Fingerprint, k.Login)
				return nil
			})
		},
	})
	var login string
	list := &cobra.Command{
		Use: "list", Short: "list SSH keys, optionally of one user", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.session(cmd, func(ctx context.Context, cl *adminclient.Client, tok []byte) error {
				r, err := cl.Admin.ListSSHKeys(ctx, &adminv1.ListSSHKeysRequest{SessionToken: tok, Login: login})
				if err != nil {
					return err
				}
				for _, k := range r.Keys {
					fmt.Fprintf(cmd.OutOrStdout(), "%s %s %s sk=%t %q created=%s\n", k.Fingerprint, k.Login, k.KeyType,
						k.SecurityKey, k.Comment, ts(k.CreatedAt, k.CreatedAt != nil))
				}
				return nil
			})
		},
	}
	list.Flags().StringVar(&login, "login", "", "only the keys of this `user`")
	c.AddCommand(list)
	c.AddCommand(&cobra.Command{
		Use: "remove <fingerprint>", Short: "remove an SSH key (SHA256:...)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.signed(cmd, func(ctx context.Context, cl *adminclient.Client) error {
				if err := cl.RemoveSSHKey(ctx, args[0]); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", args[0])
				return nil
			})
		},
	})
	return c
}

func policyCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "policy", Short: "show and change forge-wide settings"}
	c.AddCommand(&cobra.Command{
		Use: "show", Short: "show the settings", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.session(cmd, func(ctx context.Context, cl *adminclient.Client, tok []byte) error {
				r, err := cl.Admin.GetPolicy(ctx, &adminv1.GetPolicyRequest{SessionToken: tok})
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "require-sk-ssh-keys=%t\n", r.GetPolicy().GetRequireSkSshKeys())
				return nil
			})
		},
	})
	var requireSK bool
	set := &cobra.Command{
		Use: "set", Short: "replace the settings (every flag is stated: unstated means false)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.signed(cmd, func(ctx context.Context, cl *adminclient.Client) error {
				if err := cl.SetPolicy(ctx, &adminv1.Policy{RequireSkSshKeys: requireSK}); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "require-sk-ssh-keys=%t\n", requireSK)
				return nil
			})
		},
	}
	set.Flags().BoolVar(&requireSK, "require-sk-ssh-keys", false, "accept only FIDO-backed (sk-) SSH keys")
	c.AddCommand(set)
	return c
}
