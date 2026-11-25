package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-authn/fido/mds"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/go-vcs/forge/internal/adminauth"
	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/attest"
	"github.com/go-vcs/forge/internal/store"
)

// loadRoots reads and VERIFIES an MDS3 blob (FIDO Alliance signature chain,
// pinned root, CRLs, expiry) and serves attestation roots from it. Tests
// replace it; there is no flag that skips the verification.
var loadRoots = verifiedRoots

// tlsConfig builds the server's TLS configuration. Tests replace it to prove
// NewAdminServer's refusal of anything below TLS 1.3 stops serve.
var tlsConfig = adminsrv.TLSConfig

func verifiedRoots(path string) (attest.Roots, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blob, err := mds.Verify(b, mds.Options{})
	if err != nil {
		return nil, fmt.Errorf("MDS3 blob %s: %w", path, err)
	}
	return attest.MDSRoots{Blob: blob}, nil
}

// RootCmd returns the forge command.
func RootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "forge",
		Short:         "go-vcs forge server",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(serveCmd())
	return root
}

type serveConfig struct {
	db, adminListen, tlsCert, tlsKey, enrolSocket, rpID, mdsBlob string
	aaguids                                                      []string
}

func serveCmd() *cobra.Command {
	var c serveConfig
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "serve the admin API (TLS 1.3, FIDO2 per call) and the local enrolment socket",
		Long: `serve listens for the admin gRPC API on --admin-listen (TLS 1.3 only) and
for enrolment on --enrol-socket (a Unix socket, mode 0600, in a private
directory). Every mutating call must carry a FIDO2 assertion; enrolment
verifies the key's attestation against the verified MDS3 blob and --aaguid.

Secrets are read from files: the TLS key from --tls-key or, if absent, from the
systemd credential "tls.key" ($CREDENTIALS_DIRECTORY). None is taken from
arguments, the environment or a URL.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), c)
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.db, "db", "", "SQLite database `file` (required)")
	f.StringVar(&c.adminListen, "admin-listen", "127.0.0.1:8443", "admin API listen `address`")
	f.StringVar(&c.tlsCert, "tls-cert", "", "TLS certificate chain PEM `file` (required)")
	f.StringVar(&c.tlsKey, "tls-key", "", "TLS private key PEM `file` (default: systemd credential tls.key)")
	f.StringVar(&c.enrolSocket, "enrol-socket", "", "enrolment Unix socket `path` (required)")
	f.StringVar(&c.rpID, "rp-id", "", "WebAuthn relying party `id` the keys are bound to (required)")
	f.StringArrayVar(&c.aaguids, "aaguid", nil, "allowed authenticator model `AAGUID` (repeatable, at least one)")
	f.StringVar(&c.mdsBlob, "mds-blob", "", "FIDO MDS3 blob `file`, verified at start (required)")
	return cmd
}

// syncWriter serializes writes from several goroutines.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func (c serveConfig) validate() error {
	for _, r := range []struct{ name, v string }{
		{"--db", c.db}, {"--tls-cert", c.tlsCert}, {"--enrol-socket", c.enrolSocket},
		{"--rp-id", c.rpID}, {"--mds-blob", c.mdsBlob}, {"--admin-listen", c.adminListen},
	} {
		if r.v == "" {
			return fmt.Errorf("%s is required", r.name)
		}
	}
	if len(c.aaguids) == 0 {
		return errors.New("at least one --aaguid is required: enrolment has no \"accept any key\" mode")
	}
	return nil
}

func serve(ctx context.Context, stdout, stderr io.Writer, c serveConfig) error {
	if err := c.validate(); err != nil {
		return err
	}
	var allow [][16]byte
	for _, s := range c.aaguids {
		a, err := attest.ParseAAGUID(s)
		if err != nil {
			return fmt.Errorf("--aaguid %q: %w", s, err)
		}
		allow = append(allow, a)
	}
	roots, err := loadRoots(c.mdsBlob)
	if err != nil {
		return err
	}
	policy, err := attest.NewPolicy(c.rpID, allow, roots, nil)
	if err != nil {
		return err
	}
	keyPath, err := adminsrv.ResolveFile(c.tlsKey, "tls.key")
	if err != nil {
		return err
	}
	cert, err := adminsrv.LoadTLS(c.tlsCert, keyPath)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, c.db, nil)
	if err != nil {
		return err
	}
	defer st.Close()

	log := slog.New(slog.NewTextHandler(&syncWriter{w: stderr}, nil))
	nonces := adminauth.NewNonces(time.Now, time.Minute, 4096)
	admin := &adminsrv.Admin{
		Store:    st,
		Verifier: &adminauth.Verifier{RPID: c.rpID, Credentials: st, Nonces: nonces},
		Nonces:   nonces,
		Sessions: adminauth.NewSessions(time.Now, 10*time.Minute, 8, 256),
		Log:      log,
	}
	adminSrv, err := adminsrv.NewAdminServer(tlsConfig(cert), admin)
	if err != nil {
		return err
	}
	enrolSrv := adminsrv.NewEnrolServer(&adminsrv.Enrol{Store: st, Policy: policy, RPID: c.rpID, Log: log})

	adminLn, err := net.Listen("tcp", c.adminListen)
	if err != nil {
		return err
	}
	enrolLn, err := adminsrv.ListenUnix(c.enrolSocket)
	if err != nil {
		adminLn.Close()
		return err
	}
	out := &syncWriter{w: stdout}
	fmt.Fprintf(out, "admin listening on %s\n", adminLn.Addr())
	fmt.Fprintf(out, "enrolment listening on %s\n", c.enrolSocket)

	errc := make(chan error, 2)
	run := func(s *grpc.Server, ln net.Listener) { errc <- s.Serve(ln) }
	go run(adminSrv, adminsrv.LimitListener(adminLn, adminsrv.MaxConns, adminsrv.MaxConnsPerHost))
	go run(enrolSrv, enrolLn)

	var first error
	select {
	case <-ctx.Done():
	case first = <-errc:
	}
	adminSrv.GracefulStop()
	enrolSrv.GracefulStop()
	return first
}
