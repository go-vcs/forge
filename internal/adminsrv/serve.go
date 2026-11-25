// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminsrv

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	adminv1 "github.com/go-vcs/forge/api/admin/v1"
)

// TLSConfig is the server TLS configuration: TLS 1.3 only (the channel
// binding of the signed calls needs its exporter), no session tickets so a
// resumed connection cannot inherit another's binding.
func TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{cert},
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2"},
	}
}

func serverOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxRecvMsgSize(MaxMessageSize),
		grpc.MaxSendMsgSize(4 * MaxMessageSize),
		grpc.MaxConcurrentStreams(32),
		grpc.ConnectionTimeout(10 * time.Second),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: time.Minute, MaxConnectionAge: time.Hour}),
	}
}

// NewAdminServer returns the network server of AdminService. EnrolService is
// not registered on it, so enrolment is unreachable over the network.
func NewAdminServer(tlsCfg *tls.Config, a *Admin) (*grpc.Server, error) {
	if tlsCfg == nil || tlsCfg.MinVersion < tls.VersionTLS13 {
		return nil, fmt.Errorf("adminsrv: the admin API requires a TLS 1.3 configuration")
	}
	s := grpc.NewServer(append(serverOptions(), grpc.Creds(credentials.NewTLS(tlsCfg)))...)
	adminv1.RegisterAdminServiceServer(s, a)
	return s, nil
}

// NewEnrolServer returns the server of EnrolService, for a Unix socket
// listener only.
func NewEnrolServer(e *Enrol) *grpc.Server {
	s := grpc.NewServer(serverOptions()...)
	adminv1.RegisterEnrolServiceServer(s, e)
	return s
}

// LoadTLS reads a certificate and key from files. The key file must be a
// regular file (no symbolic link) owned by this process's effective user and
// not accessible to group or others. A systemd credential file (mode 0400) passes
// this check like any other private file; there is no exemption.
func LoadTLS(certFile, keyFile string) (tls.Certificate, error) {
	key, err := readSecretFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(cert, key)
}

// CredentialsEnv names the systemd credentials directory variable.
const CredentialsEnv = "CREDENTIALS_DIRECTORY"

// ResolveFile returns the path of a secret: the explicit path when given,
// else the credential name inside $CREDENTIALS_DIRECTORY. The secret itself is
// never taken from argv or the environment, only its location.
func ResolveFile(explicit, credential string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	dir := os.Getenv(CredentialsEnv)
	if dir == "" || credential == "" {
		return "", fmt.Errorf("no path given and no systemd credential %q available", credential)
	}
	p := filepath.Join(dir, filepath.Base(credential))
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("systemd credential %q: %w", credential, err)
	}
	return p, nil
}
