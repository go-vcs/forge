package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
	"github.com/go-vcs/forge/internal/adminclient"
)

// openSigner opens the hardware key. Tests replace it.
var openSigner = platformSigner

// openFile is a variable so that a test can make a read fail.
var openFile = func(path string) (io.ReadCloser, error) { return os.Open(path) }

// dial and dialUnix are variables so that a test can make a dial fail, which
// grpc.NewClient does only for a target it cannot parse.
var (
	dial     = adminclient.Dial
	dialUnix = adminclient.DialUnix
)

type options struct {
	server, caFile, serverName, rpID, credentialID, socket string
}

// RootCmd returns the forgectl command.
func RootCmd() *cobra.Command {
	var o options
	root := &cobra.Command{
		Use:           "forgectl",
		Short:         "administer a go-vcs forge with a FIDO2 key",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	pf := root.PersistentFlags()
	pf.StringVar(&o.server, "server", "", "admin API `host:port` (TLS 1.3)")
	pf.StringVar(&o.caFile, "ca-file", "", "PEM `file` of the CA that signed the server certificate (default: system roots)")
	pf.StringVar(&o.serverName, "server-name", "", "expected server certificate `name` (default: the host of --server)")
	pf.StringVar(&o.rpID, "rp-id", "", "relying party `id` the key is enrolled for")
	pf.StringVar(&o.credentialID, "credential-id", "", "administrator credential id, in `hex` (printed by enrol)")
	pf.StringVar(&o.socket, "socket", "", "enrolment Unix socket `path` (enrol only)")

	root.AddCommand(enrolCmd(&o), credentialsCmd(&o), usersCmd(&o), identitiesCmd(&o), sshKeysCmd(&o), policyCmd(&o), oidcCmd(&o))
	return root
}

func (o *options) need(names ...string) error {
	vals := map[string]string{"--server": o.server, "--rp-id": o.rpID, "--credential-id": o.credentialID, "--socket": o.socket}
	for _, n := range names {
		if vals[n] == "" {
			return fmt.Errorf("%s is required", n)
		}
	}
	return nil
}

func (o *options) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: o.serverName}
	if o.caFile != "" {
		b, err := os.ReadFile(o.caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("%s holds no PEM certificate", o.caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// client dials the admin API and binds the hardware key.
func (o *options) client(ctx context.Context) (*adminclient.Client, func(), error) {
	if err := o.need("--server", "--rp-id", "--credential-id"); err != nil {
		return nil, nil, err
	}
	id, err := hex.DecodeString(o.credentialID)
	if err != nil || len(id) == 0 {
		return nil, nil, errors.New("--credential-id must be non-empty hex")
	}
	cfg, err := o.tlsConfig()
	if err != nil {
		return nil, nil, err
	}
	signer, err := openSigner(ctx)
	if err != nil {
		return nil, nil, err
	}
	conn, err := dial(o.server, cfg)
	if err != nil {
		return nil, nil, err
	}
	return adminclient.New(conn, signer, o.rpID, id), func() { conn.Close() }, nil
}

// session runs fn with a read-only session token (one touch).
func (o *options) session(cmd *cobra.Command, fn func(ctx context.Context, c *adminclient.Client, token []byte) error) error {
	ctx := cmd.Context()
	c, closeFn, err := o.client(ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	tok, err := c.OpenSession(ctx)
	if err != nil {
		return err
	}
	return fn(ctx, c, tok)
}

// signed runs fn on a client; fn performs one signed call (one touch).
func (o *options) signed(cmd *cobra.Command, fn func(ctx context.Context, c *adminclient.Client) error) error {
	ctx := cmd.Context()
	c, closeFn, err := o.client(ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	return fn(ctx, c)
}

func ts(t interface{ AsTime() time.Time }, ok bool) string {
	if !ok {
		return "-"
	}
	return t.AsTime().UTC().Format(time.RFC3339)
}

func enrolCmd(o *options) *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "enrol",
		Short: "enrol the attached key as an administrator (local socket only)",
		Long: `enrol creates a credential on the attached key and registers it with the
forge over its local Unix socket. The key's attestation is verified by the
forge against the FIDO MDS3 blob and its AAGUID allowlist. Run it on the forge
host, as the user that owns the socket directory.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.need("--rp-id", "--socket"); err != nil {
				return err
			}
			if name == "" {
				return errors.New("--name is required")
			}
			ctx := cmd.Context()
			signer, err := openSigner(ctx)
			if err != nil {
				return err
			}
			conn, err := dialUnix(o.socket)
			if err != nil {
				return err
			}
			defer conn.Close()
			cred, err := adminclient.Enrol(ctx, conn, signer, name)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "enrolled %s\ncredential-id %s\naaguid %s\n", cred.Name, hex.EncodeToString(cred.CredentialId), cred.Aaguid)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "`label` for the key (required)")
	return cmd
}

func credentialsCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "credentials", Short: "list and revoke administrator keys"}
	c.AddCommand(&cobra.Command{
		Use: "list", Short: "list administrator credentials", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.session(cmd, func(ctx context.Context, cl *adminclient.Client, tok []byte) error {
				r, err := cl.Admin.ListAdminCredentials(ctx, &adminv1.ListAdminCredentialsRequest{SessionToken: tok})
				if err != nil {
					return err
				}
				for _, k := range r.Credentials {
					fmt.Fprintf(cmd.OutOrStdout(), "%s %s aaguid=%s count=%d created=%s revoked=%s\n",
						hex.EncodeToString(k.CredentialId), k.Name, k.Aaguid, k.SignCount,
						ts(k.CreatedAt, k.CreatedAt != nil), ts(k.RevokedAt, k.RevokedAt != nil))
				}
				return nil
			})
		},
	})
	c.AddCommand(&cobra.Command{
		Use: "revoke <credential-id-hex>", Short: "revoke an administrator credential", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := hex.DecodeString(args[0])
			if err != nil || len(id) == 0 {
				return errors.New("the credential id must be non-empty hex")
			}
			return o.signed(cmd, func(ctx context.Context, cl *adminclient.Client) error {
				if err := cl.RevokeCredential(ctx, id); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "revoked %s\n", args[0])
				return nil
			})
		},
	})
	return c
}

func usersCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "users", Short: "create, list and disable users"}
	var display string
	create := &cobra.Command{
		Use: "create <login>", Short: "create a user", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.signed(cmd, func(ctx context.Context, cl *adminclient.Client) error {
				u, err := cl.CreateUser(ctx, args[0], display)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "created %s\n", u.Login)
				return nil
			})
		},
	}
	create.Flags().StringVar(&display, "display-name", "", "display `name`")
	c.AddCommand(create)
	c.AddCommand(&cobra.Command{
		Use: "list", Short: "list users", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.session(cmd, func(ctx context.Context, cl *adminclient.Client, tok []byte) error {
				r, err := cl.Admin.ListUsers(ctx, &adminv1.ListUsersRequest{SessionToken: tok})
				if err != nil {
					return err
				}
				for _, u := range r.Users {
					fmt.Fprintf(cmd.OutOrStdout(), "%s %q created=%s disabled=%s\n", u.Login, u.DisplayName,
						ts(u.CreatedAt, u.CreatedAt != nil), ts(u.DisabledAt, u.DisabledAt != nil))
				}
				return nil
			})
		},
	})
	c.AddCommand(&cobra.Command{
		Use: "disable <login>", Short: "disable a user", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.signed(cmd, func(ctx context.Context, cl *adminclient.Client) error {
				if err := cl.DisableUser(ctx, args[0]); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "disabled %s\n", args[0])
				return nil
			})
		},
	})
	return c
}

func identitiesCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "identities", Short: "bind external identities (issuer, subject) to users"}
	c.AddCommand(&cobra.Command{
		Use: "bind <issuer> <subject> <login>", Short: "bind an (issuer, subject) pair to a user; never an e-mail address", Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.signed(cmd, func(ctx context.Context, cl *adminclient.Client) error {
				if _, err := cl.BindIdentity(ctx, args[0], args[1], args[2]); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "bound %s %s to %s\n", args[0], args[1], args[2])
				return nil
			})
		},
	})
	var login string
	list := &cobra.Command{
		Use: "list", Short: "list identity bindings, optionally of one user", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.session(cmd, func(ctx context.Context, cl *adminclient.Client, tok []byte) error {
				r, err := cl.Admin.ListIdentities(ctx, &adminv1.ListIdentitiesRequest{SessionToken: tok, Login: login})
				if err != nil {
					return err
				}
				for _, i := range r.Identities {
					fmt.Fprintf(cmd.OutOrStdout(), "%s %s %s\n", i.Issuer, i.Subject, i.Login)
				}
				return nil
			})
		},
	}
	list.Flags().StringVar(&login, "login", "", "only the identities of this `user`")
	c.AddCommand(list)
	c.AddCommand(&cobra.Command{
		Use: "unbind <issuer> <subject>", Short: "remove an identity binding", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.signed(cmd, func(ctx context.Context, cl *adminclient.Client) error {
				if err := cl.UnbindIdentity(ctx, args[0], args[1]); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "unbound %s %s\n", args[0], args[1])
				return nil
			})
		},
	})
	return c
}
