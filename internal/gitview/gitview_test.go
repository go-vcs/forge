// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package gitview_test

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-vcs/forge/internal/gittest"
	"github.com/go-vcs/forge/internal/gitview"
)

// The test binary stands in for git in the tests of the limits: the repository
// is given it as its Git program and it misbehaves on demand.
// The scenario is the repository's Dir.
func TestMain(m *testing.M) {
	if len(os.Args) > 6 && os.Args[1] == "--no-pager" {
		scen, cmd, oid := strings.TrimPrefix(os.Args[2], "--git-dir="), os.Args[5], os.Args[len(os.Args)-1]
		good := oid + "\x1f\x1fa\x1f1\x1fmsg\n" // what `show` prints for a commit with no parent
		switch {
		case scen == "hang":
			time.Sleep(time.Hour)
		case scen == "endless" && cmd == "cat-file": // never stops
			w := bufio.NewWriter(os.Stdout)
			chunk := []byte(strings.Repeat("x", 4096))
			for {
				if _, err := w.Write(chunk); err != nil {
					os.Exit(0)
				}
			}
		case scen == "tree-garbage" && cmd == "ls-tree":
			os.Stdout.WriteString("garbage\x00")
			os.Exit(0)
		case scen == "size-garbage" && cmd == "cat-file":
			os.Stdout.WriteString("abc\n")
			os.Exit(0)
		case scen == "size-negative" && cmd == "cat-file":
			os.Stdout.WriteString("-5\n")
			os.Exit(0)
		case scen == "show-short" && cmd == "show":
			os.Stdout.WriteString("x")
			os.Exit(0)
		case scen == "show-wrong-oid" && cmd == "show":
			os.Stdout.WriteString(strings.Repeat("b", 40) + "\x1f\x1fa\x1f1\x1fmsg\n")
			os.Exit(0)
		case scen == "show-bad-time" && cmd == "show":
			os.Stdout.WriteString(oid + "\x1f\x1fa\x1fxx\x1fmsg\n")
			os.Exit(0)
		case strings.HasPrefix(scen, "show-") && cmd == "diff-tree" && scen != "show-diff-fails" && scen != "show-diff-hangs":
			os.Exit(0) // an empty diff: the failure under test is in `show`
		case scen == "show-diff-fails" && cmd == "show":
			os.Stdout.WriteString(good)
			os.Exit(0)
		case scen == "show-diff-hangs" && cmd == "show":
			os.Stdout.WriteString(good)
			os.Exit(0)
		case scen == "show-diff-hangs" && cmd == "diff-tree":
			time.Sleep(time.Hour)
		}
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func fake(scenario string, timeout time.Duration) *gitview.Repo {
	return &gitview.Repo{Dir: scenario, Git: os.Args[0], Timeout: timeout}
}

var anOID = strings.Repeat("a", 40)

func realRepo(t *testing.T) (*gitview.Repo, string) {
	t.Helper()
	root := t.TempDir()
	work := gittest.NewRepo(t, root, "alice", "r", true)
	return &gitview.Repo{Dir: filepath.Join(root, "alice", "r.git")}, work
}

func TestCleanPath(t *testing.T) {
	ok := map[string]string{"": "", "/": "", "a": "a", "a/": "a", "a/b/c.txt": "a/b/c.txt", "é/ü": "é/ü", "a b": "a b", "a:b": "a:b", ".hidden": ".hidden", "a..b": "a..b"}
	for in, want := range ok {
		if got, err := gitview.CleanPath(in); err != nil || got != want {
			t.Errorf("CleanPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"..", ".", "a/..", "../a", "a/./b", "a//b", "/a", "a\\b", "a\x00b", "a\nb", "a\tb", "a\x7fb", "\xff", "a/\xc3", "a\u0080\x01",
		strings.Repeat("a", gitview.MaxPathLen+1), strings.Repeat("a/", gitview.MaxDepth) + "a", "�"}
	for _, in := range bad {
		if got, err := gitview.CleanPath(in); !errors.Is(err, gitview.ErrBadPath) {
			t.Errorf("CleanPath(%q) = %q, %v; want ErrBadPath", in, got, err)
		}
	}
	// the bounds themselves are allowed
	for _, in := range []string{strings.Repeat("a", gitview.MaxPathLen), strings.TrimSuffix(strings.Repeat("a/", gitview.MaxDepth), "/")} {
		if _, err := gitview.CleanPath(in); err != nil {
			t.Errorf("CleanPath(%d bytes): %v", len(in), err)
		}
	}
}

func FuzzCleanPath(f *testing.F) {
	for _, s := range []string{"a/b", "../x", "a\x00", "a//b", strings.Repeat("a/", 70)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		p, err := gitview.CleanPath(in)
		if err != nil {
			return
		}
		if len(p) > gitview.MaxPathLen || !utf8.ValidString(p) || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
			t.Fatalf("%q -> %q", in, p)
		}
		if p == "" {
			return
		}
		segs := strings.Split(p, "/")
		if len(segs) > gitview.MaxDepth {
			t.Fatalf("%q -> %q: depth", in, p)
		}
		for _, s := range segs {
			if s == "" || s == "." || s == ".." {
				t.Fatalf("%q -> %q: segment %q", in, p, s)
			}
		}
		for _, r := range p {
			if r < 0x20 || r == 0x7f || r == '\\' || r == utf8.RuneError {
				t.Fatalf("%q -> %q: rune %q", in, p, r)
			}
		}
	})
}

func TestResolve(t *testing.T) {
	r, work := realRepo(t)
	ctx := t.Context()
	head := gittest.Git(t, work, "rev-parse", "main")
	for _, ref := range []string{"main", "v1", "HEAD", head} {
		if got, err := r.Resolve(ctx, ref); err != nil || got != head {
			t.Errorf("Resolve(%q) = %q, %v", ref, got, err)
		}
	}
	// well-formed names that name nothing (a short or upper-case id is a name)
	for _, ref := range []string{"nope", strings.Repeat("a", 40), head[:39], strings.ToUpper(head), "head"} {
		if _, err := r.Resolve(ctx, ref); !errors.Is(err, gitview.ErrNotFound) {
			t.Errorf("Resolve(%q): %v", ref, err)
		}
	}
	// nothing that is not a short name, HEAD or a full id reaches git
	for _, ref := range []string{"", "-x", "--help", "a..b", "main^", "main~1", "main:f.txt", "refs/heads/main", "@{u}", "ma in", "main\n",
		strings.Repeat("a", 101), "--end-of-options"} {
		if _, err := r.Resolve(ctx, ref); !errors.Is(err, gitview.ErrBadPath) {
			t.Errorf("Resolve(%q): %v, want ErrBadPath", ref, err)
		}
	}
	// a branch and a tag of the same name: the branch wins, as for git
	gittest.Git(t, work, "tag", "same", "main~1")
	gittest.Git(t, work, "branch", "same", "main")
	gittest.Git(t, work, "push", "-q", r.Dir, "refs/heads/same:refs/heads/same", "refs/tags/same:refs/tags/same")
	if got, err := r.Resolve(ctx, "same"); err != nil || got != head {
		t.Errorf("Resolve(same) = %q, %v", got, err)
	}
}

func FuzzResolve(f *testing.F) {
	root := f.TempDir()
	gittest.NewRepo(f, root, "alice", "r", true)
	r := &gitview.Repo{Dir: filepath.Join(root, "alice", "r.git")}
	for _, s := range []string{"main", "v1", "HEAD", "-x", "a..b", strings.Repeat("0", 40)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ref string) {
		id, err := r.Resolve(t.Context(), ref)
		if err == nil && len(id) != 40 {
			t.Fatalf("Resolve(%q) = %q", ref, id)
		}
	})
}

func TestTreeBlobLogShow(t *testing.T) {
	r, work := realRepo(t)
	if err := os.MkdirAll(filepath.Join(work, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "d", "g.txt"), []byte("g\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gittest.Git(t, work, "add", "-A")
	gittest.Git(t, work, "commit", "-q", "-m", "four\n\nbody line")
	gittest.Git(t, work, "push", "-q", r.Dir, "main")
	ctx := t.Context()
	oid, err := r.Resolve(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	es, trunc, err := r.Tree(ctx, oid, "")
	if err != nil || trunc || len(es) != 3 || es[0].Name != "d" || !es[0].IsDir() || es[0].Size != -1 || es[1].Name != "a.txt" || es[2].Name != "f.txt" || es[2].Size != 1200 {
		t.Errorf("Tree: %+v %v %v", es, trunc, err)
	}
	if es, _, err = r.Tree(ctx, oid, "d"); err != nil || len(es) != 1 || es[0].Name != "g.txt" {
		t.Errorf("Tree d: %+v %v", es, err)
	}
	for _, p := range []string{"nope", "f.txt"} { // a missing path, and a file
		if _, _, err := r.Tree(ctx, oid, p); err == nil {
			t.Errorf("Tree(%q): no error", p)
		}
	}
	if k, err := r.Kind(ctx, oid, "d"); err != nil || k != "tree" {
		t.Errorf("Kind d: %q %v", k, err)
	}
	if k, err := r.Kind(ctx, oid, "a.txt"); err != nil || k != "blob" {
		t.Errorf("Kind a.txt: %q %v", k, err)
	}
	if _, err := r.Kind(ctx, "main", "a.txt"); !errors.Is(err, gitview.ErrBadPath) {
		t.Errorf("Kind with a ref instead of an id: %v", err)
	}
	if n, err := r.BlobSize(ctx, oid, "f.txt"); err != nil || n != 1200 {
		t.Errorf("BlobSize: %d %v", n, err)
	}
	b, cut, err := r.Blob(ctx, oid, "f.txt", 10)
	if err != nil || !cut || len(b) != 10 {
		t.Errorf("Blob limit: %d %v %v", len(b), cut, err)
	}
	if b, cut, err = r.Blob(ctx, oid, "f.txt", 1200); err != nil || cut || len(b) != 1200 {
		t.Errorf("Blob exact: %d %v %v", len(b), cut, err)
	}
	if _, _, err = r.Blob(ctx, oid, "nope", 10); !errors.Is(err, gitview.ErrNotFound) {
		t.Errorf("Blob missing: %v", err)
	}
	cs, more, err := r.Log(ctx, oid, 0)
	if err != nil || more || len(cs) != 4 || cs[0].Subject != "four" || cs[3].Subject != "one" || cs[0].Author != "t" || !cs[0].Time.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Log: %+v %v %v", cs, more, err)
	}
	if cs, _, err = r.Log(ctx, oid, 3); err != nil || len(cs) != 1 || cs[0].Subject != "one" {
		t.Errorf("Log skip: %+v %v", cs, err)
	}
	for _, skip := range []int{-1, gitview.MaxSkip + 1} {
		if _, _, err = r.Log(ctx, oid, skip); !errors.Is(err, gitview.ErrBadPath) {
			t.Errorf("Log skip %d: %v", skip, err)
		}
	}
	d, err := r.Show(ctx, oid)
	if err != nil || d.Subject != "four" || !strings.Contains(d.Message, "body line") || len(d.Parents) != 1 || !strings.Contains(d.Diff, "+++ b/a.txt") || d.DiffTruncated {
		t.Errorf("Show: %+v %v", d, err)
	}
	root, _ := r.Resolve(ctx, cs[0].ID)
	if d, err = r.Show(ctx, root); err != nil || len(d.Parents) != 0 || !strings.Contains(d.Diff, "+one") { // --root
		t.Errorf("Show root: %+v %v", d, err)
	}
	// the user's own git configuration and an external diff driver do not matter
	t.Setenv("GIT_EXTERNAL_DIFF", "/bin/false")
	t.Setenv("GIT_PAGER", "/bin/false")
	if d, err = r.Show(ctx, oid); err != nil || !strings.Contains(d.Diff, "+++ b/a.txt") {
		t.Errorf("Show under a hostile environment: %v", err)
	}
}

func TestIsText(t *testing.T) {
	big := strings.Repeat("é", gitview.MaxBlobView) // cut at the limit, in the middle of a rune
	for in, want := range map[string]bool{"": true, "abc\n": true, "é": true, "a\x00b": false, "\xff": false, "\xc3": false,
		big[:gitview.MaxBlobView]: true, big[:gitview.MaxBlobView-1]: false, "a" + big[:gitview.MaxBlobView-1]: true} {
		name := in
		if len(name) > 8 {
			name = name[:8]
		}
		if got := gitview.IsText([]byte(in)); got != want {
			t.Errorf("IsText(%q..., %d bytes) = %v", name, len(in), got)
		}
	}
	// a NUL after git's 8000-byte window does not make a file binary, as for git
	if !gitview.IsText([]byte(strings.Repeat("a", 8000) + "\x00")) {
		t.Error("NUL past 8000 bytes")
	}
	if gitview.IsText([]byte(strings.Repeat("a", 7999) + "\x00")) {
		t.Error("NUL inside 8000 bytes")
	}
}

func TestOutputIsCutAndTheProcessKilled(t *testing.T) {
	start := time.Now()
	b, cut, err := fake("endless", 0).Blob(t.Context(), anOID, "f", 1000)
	if err != nil || !cut || len(b) != 1000 {
		t.Fatalf("len %d, cut %v, err %v", len(b), cut, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestTimeout(t *testing.T) {
	start := time.Now()
	r := fake("hang", 200*time.Millisecond)
	ctx := t.Context()
	// every operation reports the deadline as such, not as "not found"
	calls := map[string]func() error{
		"Resolve":  func() error { _, err := r.Resolve(ctx, "main"); return err },
		"Kind":     func() error { _, err := r.Kind(ctx, anOID, "f"); return err },
		"Tree":     func() error { _, _, err := r.Tree(ctx, anOID, ""); return err },
		"BlobSize": func() error { _, err := r.BlobSize(ctx, anOID, "f"); return err },
		"Blob":     func() error { _, _, err := r.Blob(ctx, anOID, "f", 10); return err },
		"Log":      func() error { _, _, err := r.Log(ctx, anOID, 0); return err },
		"Show":     func() error { _, err := r.Show(ctx, anOID); return err },
		"Show diff": func() error {
			_, err := fake("show-diff-hangs", 200*time.Millisecond).Show(ctx, anOID)
			return err
		},
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	// the caller's own cancellation counts too
	cctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := fake("hang", 0).Kind(cctx, anOID, "f"); err == nil {
		t.Error("a cancelled context did not stop the command")
	}
}

// What git prints is parsed strictly: a line that is not what it should be is an
// error, never a half-filled page.
func TestGitOutputIsChecked(t *testing.T) {
	ctx := t.Context()
	if _, _, err := fake("tree-garbage", 0).Tree(ctx, anOID, ""); err == nil || errors.Is(err, gitview.ErrNotFound) {
		t.Errorf("Tree of garbage: %v", err)
	}
	for _, s := range []string{"size-garbage", "size-negative"} {
		if n, err := fake(s, 0).BlobSize(ctx, anOID, "f"); !errors.Is(err, gitview.ErrNotFound) {
			t.Errorf("BlobSize %s: %d, %v", s, n, err)
		}
	}
	for _, s := range []string{"show-short", "show-wrong-oid", "show-bad-time", "show-diff-fails"} {
		if d, err := fake(s, 0).Show(ctx, anOID); err == nil {
			t.Errorf("Show %s: %+v", s, d)
		}
	}
}

// Only a full commit id reaches the commands that take one.
func TestOnlyIDsReachCommands(t *testing.T) {
	r, _ := realRepo(t)
	ctx := t.Context()
	for _, bad := range []string{"main", "HEAD", "-x", "--help", "", anOID[:39], strings.ToUpper(anOID)} {
		calls := map[string]func() error{
			"Kind":     func() error { _, err := r.Kind(ctx, bad, ""); return err },
			"Tree":     func() error { _, _, err := r.Tree(ctx, bad, ""); return err },
			"BlobSize": func() error { _, err := r.BlobSize(ctx, bad, "f.txt"); return err },
			"Blob":     func() error { _, _, err := r.Blob(ctx, bad, "f.txt", 10); return err },
			"Log":      func() error { _, _, err := r.Log(ctx, bad, 0); return err },
			"Show":     func() error { _, err := r.Show(ctx, bad); return err },
		}
		for name, call := range calls {
			if err := call(); !errors.Is(err, gitview.ErrBadPath) {
				t.Errorf("%s(%q): %v", name, bad, err)
			}
		}
	}
}

// A submodule is neither a tree nor a blob: it is listed, and it has no page.
func TestSubmoduleEntry(t *testing.T) {
	r, work := realRepo(t)
	head := gittest.Git(t, work, "rev-parse", "HEAD")
	gittest.Git(t, work, "update-index", "--add", "--cacheinfo", "160000,"+head+",sub")
	gittest.Git(t, work, "commit", "-q", "-m", "submodule")
	gittest.Git(t, work, "push", "-q", r.Dir, "main")
	ctx := t.Context()
	oid, err := r.Resolve(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Kind(ctx, oid, "sub"); !errors.Is(err, gitview.ErrNotFound) {
		t.Errorf("Kind of a submodule: %v", err)
	}
	es, _, err := r.Tree(ctx, oid, "")
	if err != nil || len(es) != 2 || es[1].Name != "sub" || es[1].Type != "commit" || es[1].Size != -1 {
		t.Errorf("Tree: %+v %v", es, err)
	}
}

func TestNoGit(t *testing.T) {
	r := &gitview.Repo{Dir: t.TempDir(), Git: filepath.Join(t.TempDir(), "no-such-git")}
	// a git that cannot start is a failure of ours, not a missing ref
	if _, err := r.Resolve(t.Context(), "main"); err == nil || errors.Is(err, gitview.ErrNotFound) {
		t.Errorf("Resolve without git: %v", err)
	}
	if _, _, err := r.Tree(t.Context(), strings.Repeat("a", 40), ""); err == nil {
		t.Error("Tree without git: no error")
	}
}
