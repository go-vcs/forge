// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"

	"github.com/go-vcs/forge/internal/adminsrv"
	"github.com/go-vcs/forge/internal/secretbox"
)

// loadSealer reads the secrets key from --secrets-key or the systemd credential
// "secrets.key". With neither it returns nil, and the admin API then refuses to
// store any secret rather than store it in clear.
func loadSealer(explicit string) (*secretbox.Box, error) {
	if explicit == "" && os.Getenv(adminsrv.CredentialsEnv) == "" {
		return nil, nil
	}
	p, err := adminsrv.ResolveFile(explicit, "secrets.key")
	if err != nil {
		if explicit == "" {
			return nil, nil // credentials directory without that credential
		}
		return nil, fmt.Errorf("--secrets-key: %w", err)
	}
	b, err := adminsrv.ReadSecretFile(p)
	if err != nil {
		return nil, err
	}
	box, err := secretbox.New(b)
	if err != nil {
		return nil, fmt.Errorf("secrets key %s: %w", p, err)
	}
	return box, nil
}
