package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-authn/fido/mds"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/go-vcs/forge/internal/adminauth"
	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/attest"
	"github.com/go-vcs/forge/internal/githttp"
	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gitssh"
	"github.com/go-vcs/forge/internal/secretbox"
	"github.com/go-vcs/forge/internal/store"
	"github.com/go-vcs/forge/internal/web"
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
	secretsKey                                                   string
	aaguids                                                      []string

	// git transports (milestone 2): off unless --ssh-listen is given
	sshListen, sshHostKey, reposRoot, gitBin string
	httpListen                               string
	// web UI and sign-in (milestone 3): off unless --web-listen is given
	webListen                          string
	gitTimeout                         time.Duration
	gitSessions, gitSessionsPerAccount int
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
	f.StringVar(&c.secretsKey, "secrets-key", "", "`file` holding the 32-byte key that encrypts stored secrets, mode 0600 (default: systemd credential secrets.key; without one no secret can be stored)")
	f.StringVar(&c.sshListen, "ssh-listen", "", "serve git clone and fetch over SSH on this `address` (off when empty)")
	f.StringVar(&c.sshHostKey, "ssh-host-key", "", "SSH host key `file`, an ed25519 OpenSSH private key, mode 0600, never generated (default: systemd credential ssh_host_key)")
	f.StringVar(&c.reposRoot, "repos-root", "", "`directory` holding <owner>/<name>.git bare repositories (required with --ssh-listen)")
	f.StringVar(&c.httpListen, "http-listen", "", "serve anonymous git clone and fetch of public repositories over smart HTTP (TLS 1.3, protocol v2) on this `address` (off when empty)")
	f.StringVar(&c.webListen, "web-listen", "", "serve the web UI and OIDC sign-in (TLS 1.3) on this `address` (off when empty); the sign-in client is registered with `forgectl oidc set`")
	f.StringVar(&c.gitBin, "git", "", "git `executable` (default: git on PATH)")
	f.DurationVar(&c.gitTimeout, "git-timeout", gitrepo.DefaultRequestDuration, "longest a git session may last")
	f.IntVar(&c.gitSessions, "git-sessions", gitrepo.DefaultTotalSessions, "most git sessions at once, in total")
	f.IntVar(&c.gitSessionsPerAccount, "git-sessions-per-account", gitrepo.DefaultSessionsPerKey, "most git sessions at once for one account")
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
	if c.sshListen != "" || c.httpListen != "" {
		if c.reposRoot == "" {
			return errors.New("--repos-root is required with --ssh-listen and --http-listen")
		}
		if c.gitSessions < 1 || c.gitSessionsPerAccount < 1 || c.gitTimeout <= 0 {
			return errors.New("--git-sessions, --git-sessions-per-account and --git-timeout must be positive")
		}
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

	seal, err := loadSealer(c.secretsKey)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(&syncWriter{w: stderr}, nil))
	nonces := adminauth.NewNonces(time.Now, time.Minute, 4096)
	admin := &adminsrv.Admin{
		Store:    st,
		Verifier: &adminauth.Verifier{RPID: c.rpID, Credentials: st, Nonces: nonces},
		Nonces:   nonces,
		Sessions: adminauth.NewSessions(time.Now, 10*time.Minute, 8, 256),
		Log:      log,
		Seal:     seal,
	}
	adminSrv, err := adminsrv.NewAdminServer(tlsConfig(cert), admin)
	if err != nil {
		return err
	}
	enrolSrv := adminsrv.NewEnrolServer(&adminsrv.Enrol{Store: st, Policy: policy, RPID: c.rpID, Log: log})

	var sshSrv *gitssh.Server
	if c.sshListen != "" {
		if sshSrv, err = newSSHServer(c, st, log); err != nil {
			return err
		}
	}

	var httpSrv *http.Server
	if c.httpListen != "" {
		if httpSrv, err = newHTTPServer(c, tlsConfig(cert), log); err != nil {
			return err
		}
	}

	var webSrv *http.Server
	if c.webListen != "" {
		webSrv = newWebServer(tlsConfig(cert), st, seal, log)
	}

	adminLn, err := net.Listen("tcp", c.adminListen)
	if err != nil {
		return err
	}
	enrolLn, err := adminsrv.ListenUnix(c.enrolSocket)
	if err != nil {
		adminLn.Close()
		return err
	}
	var sshLn, httpLn, webLn net.Listener
	closeAll := func() {
		for _, l := range []net.Listener{adminLn, enrolLn, sshLn, httpLn, webLn} {
			if l != nil {
				l.Close()
			}
		}
	}
	if sshSrv != nil {
		if sshLn, err = net.Listen("tcp", c.sshListen); err != nil {
			closeAll()
			return err
		}
	}
	if httpSrv != nil {
		if httpLn, err = net.Listen("tcp", c.httpListen); err != nil {
			closeAll()
			return err
		}
	}
	if webSrv != nil {
		if webLn, err = net.Listen("tcp", c.webListen); err != nil {
			closeAll()
			return err
		}
	}
	out := &syncWriter{w: stdout}
	fmt.Fprintf(out, "admin listening on %s\n", adminLn.Addr())
	fmt.Fprintf(out, "enrolment listening on %s\n", c.enrolSocket)

	errc := make(chan error, 5)
	run := func(s *grpc.Server, ln net.Listener) { errc <- s.Serve(ln) }
	go run(adminSrv, adminsrv.LimitListener(adminLn, adminsrv.MaxConns, adminsrv.MaxConnsPerHost))
	go run(enrolSrv, enrolLn)
	sshCtx, stopSSH := context.WithCancel(ctx)
	defer stopSSH()
	sshDone := make(chan struct{})
	if sshSrv != nil {
		fmt.Fprintf(out, "git over SSH listening on %s\n", sshLn.Addr())
		go func() { defer close(sshDone); errc <- sshSrv.Serve(sshCtx, sshLn) }()
	} else {
		close(sshDone)
	}
	httpDone := make(chan struct{})
	if httpSrv != nil {
		fmt.Fprintf(out, "git over HTTP listening on %s\n", httpLn.Addr())
		go func() {
			defer close(httpDone)
			// the certificate is already in the TLS config
			if err := httpSrv.ServeTLS(httpLn, "", ""); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	} else {
		close(httpDone)
	}
	webDone := make(chan struct{})
	if webSrv != nil {
		fmt.Fprintf(out, "web listening on %s\n", webLn.Addr())
		go func() {
			defer close(webDone)
			if err := webSrv.ServeTLS(webLn, "", ""); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	} else {
		close(webDone)
	}

	var first error
	select {
	case <-ctx.Done():
	case first = <-errc:
	}
	adminSrv.GracefulStop()
	enrolSrv.GracefulStop()
	stopSSH()
	<-sshDone
	if httpSrv != nil {
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = httpSrv.Shutdown(shut)
		cancel()
		_ = httpSrv.Close()
	}
	<-httpDone
	if webSrv != nil {
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = webSrv.Shutdown(shut)
		cancel()
		_ = webSrv.Close()
	}
	<-webDone
	return first
}

// newWebServer builds the web listener: TLS 1.3 only (the session cookie is
// Secure), HTTP/1.1, every timeout set.
func newWebServer(tc *tls.Config, st *store.Store, seal *secretbox.Box, log *slog.Logger) *http.Server {
	h := (&web.Server{Store: st, Seal: seal, Log: log}).Handler()
	tc = tc.Clone()
	tc.NextProtos = []string{"http/1.1"}
	return &http.Server{
		Handler:           h,
		TLSConfig:         tc,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// newHTTPServer builds the smart HTTP server. TLS 1.3 only, HTTP/1.1, and every
// timeout set: a client that dawdles holds nothing for long.
func newHTTPServer(c serveConfig, tc *tls.Config, log *slog.Logger) (*http.Server, error) {
	repos := &gitrepo.Service{Root: c.reposRoot, Git: c.gitBin}
	if err := repos.Validate(); err != nil {
		return nil, err
	}
	tc = tc.Clone()
	tc.NextProtos = []string{"http/1.1"}
	return &http.Server{
		Handler: &githttp.Handler{
			Repos:          repos,
			Sessions:       &gitrepo.Limiter{Total: c.gitSessions, PerKey: c.gitSessionsPerAccount},
			Log:            log,
			RequestTimeout: c.gitTimeout,
		},
		TLSConfig:         tc,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}, nil
}

// newSSHServer builds the git-over-SSH server: the host key must exist (it is
// never generated here), the repositories root must be a directory.
func newSSHServer(c serveConfig, st *store.Store, log *slog.Logger) (*gitssh.Server, error) {
	keyPath, err := adminsrv.ResolveFile(c.sshHostKey, "ssh_host_key")
	if err != nil {
		return nil, fmt.Errorf("--ssh-host-key: %w", err)
	}
	hostKey, err := gitssh.LoadHostKey(keyPath)
	if err != nil {
		return nil, err
	}
	repos := &gitrepo.Service{Root: c.reposRoot, Git: c.gitBin}
	if err := repos.Validate(); err != nil {
		return nil, err
	}
	return &gitssh.Server{
		Auth:           st,
		Repos:          repos,
		Sessions:       &gitrepo.Limiter{Total: c.gitSessions, PerKey: c.gitSessionsPerAccount},
		HostKey:        hostKey,
		Log:            log,
		RequestTimeout: c.gitTimeout,
	}, nil
}
