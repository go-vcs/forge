//go:build unix

package main

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-vcs/forge/internal/sshkeys"
	"github.com/go-vcs/forge/internal/sshtest"
)

func TestSSHKeysAndPolicyCommands(t *testing.T) {
	r := newRig(t)
	r.enrol(t)
	if _, err := r.admin("users", "create", "alice"); err != nil {
		t.Fatal(err)
	}
	k := sshtest.NewEd25519(t)
	pub := filepath.Join(t.TempDir(), "id.pub")
	if err := os.WriteFile(pub, []byte(k.Line+" me@laptop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		args []string
		want string
	}{
		{[]string{"ssh-keys", "add", "alice", pub}, "added ssh-ed25519 " + k.Fingerprint + " to alice"},
		{[]string{"ssh-keys", "list"}, k.Fingerprint + " alice ssh-ed25519 sk=false \"me@laptop\""},
		{[]string{"ssh-keys", "list", "--login", "alice"}, k.Fingerprint},
		{[]string{"policy", "show"}, "require-sk-ssh-keys=false"},
		{[]string{"policy", "set", "--require-sk-ssh-keys"}, "require-sk-ssh-keys=true"},
		{[]string{"policy", "show"}, "require-sk-ssh-keys=true"},
		{[]string{"ssh-keys", "remove", k.Fingerprint}, "removed " + k.Fingerprint},
	} {
		out, err := r.admin(step.args...)
		if err != nil || !strings.Contains(out, step.want) {
			t.Fatalf("%v printed %q, %v; want %q", step.args, out, err, step.want)
		}
	}
	if _, err := r.admin("ssh-keys", "add", "alice", pub); err == nil {
		t.Fatal("a plain key was added under the sk policy")
	}
	if out, _ := r.admin("ssh-keys", "list"); strings.Contains(out, k.Fingerprint) {
		t.Fatalf("removed key still listed: %q", out)
	}
}

func TestReadKeyFile(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), sshkeys.MaxLineLen+1), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRig(t)
	r.enrol(t)
	// The client refuses before anything is sent: the message names the file.
	if _, err := r.admin("ssh-keys", "add", "alice", big); err == nil || !strings.Contains(err.Error(), big+": longer than") {
		t.Fatalf("oversized key file = %v", err)
	}
	if _, err := r.admin("ssh-keys", "add", "alice", filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("a missing key file = %v", err)
	}
	// "-" reads standard input.
	k := sshtest.NewEd25519(t)
	if _, err := r.admin("users", "create", "alice"); err != nil {
		t.Fatal(err)
	}
	c := RootCmd()
	var out bytes.Buffer
	c.SetIn(strings.NewReader(k.Line))
	c.SetOut(&out)
	c.SetErr(io.Discard)
	c.SetArgs([]string{"--server", r.addr, "--ca-file", r.caFile, "--rp-id", rpID, "--credential-id", hexID(r), "ssh-keys", "add", "alice", "-"})
	if err := c.ExecuteContext(t.Context()); err != nil || !strings.Contains(out.String(), k.Fingerprint) {
		t.Fatalf("stdin add: %q %v", out.String(), err)
	}
	// A read error is reported.
	old := openFile
	defer func() { openFile = old }()
	openFile = func(string) (io.ReadCloser, error) { return io.NopCloser(errReader{}), nil }
	if _, err := r.admin("ssh-keys", "add", "alice", "x"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("read error = %v", err)
	}
}

func (r *rig) rawExec(stmts string) {
	r.t.Helper()
	db, err := sql.Open("sqlite", "file:"+r.dbPath)
	if err != nil {
		r.t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(stmts); err != nil {
		r.t.Fatalf("%s: %v", stmts, err)
	}
}

// A refusal of the server reaches the operator as an error, with nothing printed
// as if it had worked.
func TestSSHKeyCommandsReportServerFailures(t *testing.T) {
	r := newRig(t)
	r.enrol(t)
	if out, err := r.admin("ssh-keys", "remove", "SHA256:nope"); err == nil || out != "" {
		t.Fatalf("removing an unknown key printed %q, %v", out, err)
	}
	r.rawExec(`DROP TABLE settings; DROP TABLE ssh_keys`)
	for _, args := range [][]string{
		{"ssh-keys", "list"}, {"policy", "show"}, {"policy", "set", "--require-sk-ssh-keys"},
	} {
		if out, err := r.admin(args...); err == nil || out != "" {
			t.Fatalf("%v printed %q, %v; want an error and no output", args, out, err)
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func hexID(r *rig) string { return hex.EncodeToString(r.auth.CredID) }
