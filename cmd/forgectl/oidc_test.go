// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/go-vcs/forge/internal/secretbox"
	"github.com/go-vcs/forge/internal/store"
	"github.com/go-vcs/forge/internal/web"
)

// The help text names the path the router serves: a registration made from it
// must reach the callback.
func TestRedirectURIHelpNamesTheRoutersCallback(t *testing.T) {
	r := newRig(t)
	out, err := r.admin("oidc", "set-client", "--help")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://<forge>" + web.CallbackPath
	if !strings.Contains(out, want) {
		t.Fatalf("help does not say %q:\n%s", want, out)
	}
	if strings.Contains(out, "/auth/callback") {
		t.Fatalf("help still names /auth/callback:\n%s", out)
	}
}

func testBox(t *testing.T) *secretbox.Box {
	t.Helper()
	b, err := secretbox.New(bytes.Repeat([]byte{3}, secretbox.KeyLen))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOIDCSetClientSecretSources(t *testing.T) {
	r := newRig(t)
	r.enrol(t)
	base := []string{"oidc", "set-client", "--issuer", "https://login.example", "--client-id", "forge", "--redirect-uri", "https://forge.example/auth/callback"}

	// the prompt
	old := promptSecret
	t.Cleanup(func() { promptSecret = old })
	promptSecret = func(*cobra.Command, string) ([]byte, error) { return []byte("from-prompt"), nil }
	out, err := r.admin(base...)
	if err != nil || !strings.Contains(out, "registered forge") {
		t.Fatalf("prompt: %q %v", out, err)
	}
	if strings.Contains(out, "from-prompt") {
		t.Fatal("secret echoed")
	}
	out, err = r.admin("oidc", "show")
	if err != nil || !strings.Contains(out, "secret=true") || strings.Contains(out, "from-prompt") {
		t.Fatalf("show: %q %v", out, err)
	}

	// a failing prompt, an empty one
	promptSecret = func(*cobra.Command, string) ([]byte, error) { return nil, errors.New("no tty") }
	if _, err := r.admin(base...); err == nil || !strings.Contains(err.Error(), "no tty") {
		t.Fatalf("prompt failure = %v", err)
	}
	promptSecret = func(*cobra.Command, string) ([]byte, error) { return nil, nil }
	if _, err := r.admin(base...); err == nil || !strings.Contains(err.Error(), "empty secret") {
		t.Fatalf("empty = %v", err)
	}

	// the descriptor
	oldFD := openFD
	t.Cleanup(func() { openFD = oldFD })
	openFD = func(int) io.ReadCloser { return io.NopCloser(strings.NewReader("from-fd\n")) }
	if _, err := r.admin(append(base, "--secret-fd", "3")...); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []string{"1", "2", "-1"} {
		if _, err := r.admin(append(base, "--secret-fd", fd)...); err == nil || !strings.Contains(err.Error(), "3 or above") {
			t.Fatalf("fd %s = %v", fd, err)
		}
	}
	openFD = func(int) io.ReadCloser {
		return io.NopCloser(strings.NewReader(strings.Repeat("a", store.MaxClientSecret+1)))
	}
	if _, err := r.admin(append(base, "--secret-fd", "3")...); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("long secret = %v", err)
	}
	openFD = func(int) io.ReadCloser { return io.NopCloser(errReader{}) }
	if _, err := r.admin(append(base, "--secret-fd", "3")...); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("read failure = %v", err)
	}

	// public, and the exclusive flags
	if _, err := r.admin(append(base, "--public")...); err != nil {
		t.Fatal(err)
	}
	out, _ = r.admin("oidc", "show")
	if !strings.Contains(out, "secret=false") {
		t.Fatalf("public show: %q", out)
	}
	if _, err := r.admin(append(base, "--public", "--secret-fd", "3")...); err == nil {
		t.Fatal("--public with --secret-fd accepted")
	}
	// there is no secret flag at all
	if _, err := r.admin(append(base, "--secret", "x")...); err == nil {
		t.Fatal("a --secret flag exists")
	}
}

func TestOIDCShowWhenUnset(t *testing.T) {
	r := newRig(t)
	r.enrol(t)
	out, err := r.admin("oidc", "show")
	if err != nil || !strings.Contains(out, "no OIDC client") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestOIDCServerRefusalsReachTheOperator(t *testing.T) {
	r := newRig(t)
	r.enrol(t)
	if _, err := r.admin("oidc", "set-client", "--public", "--issuer", "http://insecure.example", "--client-id", "forge", "--redirect-uri", "https://forge.example/cb"); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("set-client with an http issuer = %v", err)
	}
	r.rawExec(`DROP TABLE oidc_client`)
	if _, err := r.admin("oidc", "show"); err == nil {
		t.Fatal("show hid a storage failure")
	}
}

func TestPromptRefusesANonTerminal(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetErr(io.Discard)
	if _, err := promptSecret(cmd, "x: "); err == nil || !strings.Contains(err.Error(), "--secret-fd") {
		t.Fatalf("prompt on a non-terminal = %v", err)
	}
}

func TestRealOpenFDRefusesAClosedDescriptor(t *testing.T) {
	if _, err := io.ReadAll(openFD(9999)); err == nil {
		t.Fatal("read from a closed descriptor succeeded")
	}
}
