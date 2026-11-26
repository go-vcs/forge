// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package sshkeys_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/go-vcs/forge/internal/sshkeys"
)

func line(t *testing.T, pub ssh.PublicKey, comment string) string {
	t.Helper()
	l := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		l += " " + comment
	}
	return l
}

// skED25519 builds the wire encoding of an sk-ssh-ed25519@openssh.com key
// (PROTOCOL.u2f: string type, string key, string application).
func skED25519(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Name, Key, App string
	}{ssh.KeyAlgoSKED25519, string(pub), "ssh:"})
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseAccepted(t *testing.T) {
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	edk, _ := ssh.NewPublicKey(ed)
	ec, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	eck, _ := ssh.NewPublicKey(&ec.PublicKey)
	rk, err := rsa.GenerateKey(rand.Reader, sshkeys.MinRSABits)
	if err != nil {
		t.Fatal(err)
	}
	rkk, _ := ssh.NewPublicKey(&rk.PublicKey)
	sk := skED25519(t)
	for _, c := range []struct {
		name string
		pub  ssh.PublicKey
		sk   bool
	}{
		{"ed25519", edk, false}, {"ecdsa-384", eck, false}, {"rsa-3072", rkk, false}, {"sk-ed25519", sk, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			k, err := sshkeys.Parse(line(t, c.pub, "laptop key"))
			if err != nil {
				t.Fatal(err)
			}
			if k.Type != c.pub.Type() || k.SecurityKey != c.sk || k.Comment != "laptop key" ||
				k.Fingerprint != ssh.FingerprintSHA256(c.pub) || !strings.HasPrefix(k.Fingerprint, "SHA256:") {
				t.Fatalf("unexpected key %+v", k)
			}
			b, err := sshkeys.ParseBlob(k.Blob, "x")
			if err != nil || b.Fingerprint != k.Fingerprint || b.SecurityKey != c.sk || b.Comment != "x" {
				t.Fatalf("ParseBlob = %+v, %v", b, err)
			}
		})
	}
}

func TestParseRefused(t *testing.T) {
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	edk, _ := ssh.NewPublicKey(ed)
	good := line(t, edk, "")
	short, _ := rsa.GenerateKey(rand.Reader, 2048)
	shortk, _ := ssh.NewPublicKey(&short.PublicKey)
	typ, b64, _ := strings.Cut(good, " ")
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	_ = other
	for name, in := range map[string]string{
		"empty":            "",
		"blank":            "   ",
		"two lines":        good + "\n" + good,
		"nul":              good + " a\x00b",
		"options":          `command="rm -rf /" ` + good,
		"unknown type":     "ssh-dss " + b64,
		"type mismatch":    "ecdsa-sha2-nistp256 " + b64,
		"not base64":       typ + " !!!!",
		"no blob":          typ,
		"truncated blob":   typ + " " + b64[:20],
		"short rsa":        line(t, shortk, ""),
		"control comment":  good + " a\x07b",
		"long comment":     good + " " + strings.Repeat("c", sshkeys.MaxCommentLen+1),
		"long line":        good + " " + strings.Repeat("c", sshkeys.MaxLineLen),
		"bad utf8":         good + " \xff\xfe",
		"cert":             "ssh-ed25519-cert-v01@openssh.com " + b64,
		"trailing garbage": typ + " " + b64 + "AAAA" + b64,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sshkeys.Parse(in)
			if !errors.Is(err, sshkeys.ErrInvalid) {
				t.Fatalf("Parse(%.60q) err = %v, want ErrInvalid", in, err)
			}
		})
	}
	if _, err := sshkeys.ParseBlob([]byte("junk"), ""); !errors.Is(err, sshkeys.ErrInvalid) {
		t.Fatalf("ParseBlob(junk) = %v", err)
	}
}

func TestParseBounds(t *testing.T) {
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	edk, _ := ssh.NewPublicKey(ed)
	good := line(t, edk, "")
	// Padding is trimmed, so only the length bound can refuse it.
	if _, err := sshkeys.Parse(good + strings.Repeat(" ", sshkeys.MaxLineLen)); !errors.Is(err, sshkeys.ErrInvalid) {
		t.Fatalf("padded line err = %v", err)
	}
	if _, err := sshkeys.Parse(good + strings.Repeat(" ", sshkeys.MaxLineLen-len(good))); err != nil {
		t.Fatalf("line of exactly the bound refused: %v", err)
	}
	// A real certificate has a matching declared type: only the allowed set refuses it.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cert := &ssh.Certificate{Key: edk, CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	if _, err := sshkeys.Parse(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))); !errors.Is(err, sshkeys.ErrInvalid) {
		t.Fatalf("certificate err = %v", err)
	}
	// A long algorithm name is clipped in the message.
	_, err := sshkeys.Parse(strings.Repeat("x", 500) + " AAAA")
	if err == nil || len(err.Error()) > 200 || !strings.Contains(err.Error(), "...") {
		t.Fatalf("long type err = %v", err)
	}
	_, err = sshkeys.Parse(strings.Repeat("x", 48) + " AAAA")
	if err == nil || strings.Contains(err.Error(), "...") {
		t.Fatalf("48-byte type must not be clipped: %v", err)
	}
}

func TestIsSecurityKeyType(t *testing.T) {
	for typ, want := range map[string]bool{
		ssh.KeyAlgoSKED25519: true, ssh.KeyAlgoSKECDSA256: true,
		ssh.KeyAlgoED25519: false, ssh.KeyAlgoRSA: false, "": false,
	} {
		if sshkeys.IsSecurityKeyType(typ) != want {
			t.Errorf("IsSecurityKeyType(%q) != %v", typ, want)
		}
	}
	if sshkeys.Allowed("ssh-dss") || !sshkeys.Allowed(ssh.KeyAlgoSKECDSA256) {
		t.Error("Allowed set wrong")
	}
}

func FuzzParse(f *testing.F) {
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	edk, _ := ssh.NewPublicKey(ed)
	f.Add(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(edk))) + " c")
	f.Add(`from="*" ssh-ed25519 AAAA`)
	f.Add("sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t")
	f.Fuzz(func(t *testing.T, in string) {
		k, err := sshkeys.Parse(in)
		if err != nil {
			if !errors.Is(err, sshkeys.ErrInvalid) {
				t.Fatalf("error not ErrInvalid: %v", err)
			}
			return
		}
		if !sshkeys.Allowed(k.Type) || k.Public == nil || len(k.Comment) > sshkeys.MaxCommentLen {
			t.Fatalf("accepted %+v", k)
		}
		if b, err := sshkeys.ParseBlob(k.Blob, k.Comment); err != nil || b.Fingerprint != k.Fingerprint {
			t.Fatalf("blob does not round trip: %v", err)
		}
	})
}
