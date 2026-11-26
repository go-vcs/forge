// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package sshkeys parses and classifies the SSH public keys users register.
// The accepted set is deliberately small: no DSA, no certificates, no
// authorized_keys options (a registered key grants exactly "authenticate as the
// account", nothing a line could widen), no short RSA keys.
package sshkeys

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Bounds.
const (
	// MaxLineLen bounds a registered authorized_keys line.
	MaxLineLen = 8 << 10
	// MaxCommentLen bounds the comment kept with a key.
	MaxCommentLen = 128
	// MinRSABits is the smallest RSA modulus accepted.
	MinRSABits = 3072
)

// ErrInvalid wraps every refusal of a key.
var ErrInvalid = errors.New("invalid ssh public key")

// Key is a parsed, accepted public key.
type Key struct {
	// Type is the SSH algorithm name.
	Type string
	// Blob is the key in SSH wire format.
	Blob []byte
	// Fingerprint is "SHA256:<unpadded base64>".
	Fingerprint string
	// Comment is the trailing comment of the line, possibly empty.
	Comment string
	// SecurityKey is true for the FIDO-backed "sk-" types.
	SecurityKey bool
	// Public is the key itself, for the SSH server's comparison.
	Public ssh.PublicKey
}

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// IsSecurityKeyType reports whether an SSH algorithm name is a FIDO-backed key.
func IsSecurityKeyType(t string) bool {
	return t == ssh.KeyAlgoSKED25519 || t == ssh.KeyAlgoSKECDSA256
}

// Allowed reports whether an SSH key algorithm name is one the forge accepts.
func Allowed(t string) bool {
	switch t {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA:
		return true
	}
	return false
}

// Parse reads one authorized_keys line of the form "<type> <base64> [comment]".
// A line with options in front, a certificate, an algorithm outside the
// accepted set, a short RSA key, or a trailing blob is refused.
func Parse(line string) (Key, error) {
	if len(line) > MaxLineLen {
		return Key{}, refuse("line longer than %d bytes", MaxLineLen)
	}
	if !utf8.ValidString(line) {
		return Key{}, refuse("not UTF-8")
	}
	line = strings.TrimSpace(line)
	if strings.ContainsAny(line, "\r\n") {
		return Key{}, refuse("want exactly one line")
	}
	typ, rest, _ := strings.Cut(line, " ")
	if !Allowed(typ) {
		return Key{}, refuse("algorithm %q is not accepted", clip(typ))
	}
	b64, comment, _ := strings.Cut(rest, " ")
	comment = strings.TrimSpace(comment)
	if len(comment) > MaxCommentLen {
		return Key{}, refuse("comment longer than %d bytes", MaxCommentLen)
	}
	for _, r := range comment {
		if r < 0x20 || r == 0x7f {
			return Key{}, refuse("comment has a control character")
		}
	}
	// ParseAuthorizedKey would accept options and skip leading garbage, so the
	// line is rebuilt without the comment: type and blob are all it may hold.
	// typ is an accepted key type and the text holds no newline, so there are
	// no options and no tail; ParseAuthorizedKey itself refuses a blob whose
	// encoded type is not typ.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(typ + " " + b64))
	if err != nil {
		return Key{}, refuse("%v", err)
	}
	if typ == ssh.KeyAlgoRSA {
		// An "ssh-rsa" key from the parser is always a *rsa.PublicKey.
		if pub.(ssh.CryptoPublicKey).CryptoPublicKey().(*rsa.PublicKey).N.BitLen() < MinRSABits {
			return Key{}, refuse("RSA keys need at least %d bits", MinRSABits)
		}
	}
	return Key{
		Type: typ, Blob: pub.Marshal(), Fingerprint: ssh.FingerprintSHA256(pub),
		Comment: comment, SecurityKey: IsSecurityKeyType(typ), Public: pub,
	}, nil
}

// ParseBlob rebuilds a Key from its wire encoding, as stored.
func ParseBlob(blob []byte, comment string) (Key, error) {
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return Key{}, refuse("%v", err)
	}
	return Key{
		Type: pub.Type(), Blob: blob, Fingerprint: ssh.FingerprintSHA256(pub),
		Comment: comment, SecurityKey: IsSecurityKeyType(pub.Type()), Public: pub,
	}, nil
}

func clip(s string) string {
	if len(s) > 48 {
		return s[:48] + "..."
	}
	return s
}
