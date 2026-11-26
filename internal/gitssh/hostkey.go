// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package gitssh

import (
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/go-vcs/forge/internal/adminsrv"
)

// LoadHostKey reads the server's SSH host key from an OpenSSH private key file
// that must be a regular file, not a symbolic link, owned by this user and
// closed to group and others (the check the TLS key gets). The key must be
// ed25519 and carry no passphrase. It is never generated here: a host key made
// silently at start would change on every redeploy and teach clients to ignore
// the warning. Make it once with ssh-keygen -t ed25519 -f <file>
// with an empty passphrase.
func LoadHostKey(path string) (ssh.Signer, error) {
	b, err := adminsrv.ReadSecretFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("ssh host key %s: %w", path, err)
	}
	if t := signer.PublicKey().Type(); t != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("ssh host key %s is %s: only ssh-ed25519 is accepted", path, t)
	}
	return signer, nil
}
