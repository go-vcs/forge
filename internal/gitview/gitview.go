// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package gitview reads a bare repository for the web pages: a commit's tree, a
// blob, the log, one commit's diff. It runs the git program, read-only, and
// keeps every answer bounded.
//
// Rules it keeps, each with a test:
//
//   - a path from a URL is cleaned before git sees it: no empty, "." or ".."
//     segment, no control character, no backslash, valid UTF-8, bounded in length
//     and depth;
//   - a ref is a short name or an object id from a fixed alphabet, resolved to a
//     commit id first; every later command takes that id, so no argument that
//     comes from a user can start with "-";
//   - the output of a command is read through a limit and the process is killed
//     when it is reached, and every command has a deadline;
//   - git runs with no user or system configuration and no terminal.
package gitview

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Bounds. A page never holds more than these, whatever the repository holds.
const (
	MaxTreeEntries = 5000
	MaxBlobView    = 256 << 10 // a blob shown in a page
	MaxRaw         = 4 << 20   // a blob served raw
	MaxDiff        = 256 << 10
	MaxMessage     = 64 << 10
	LogPage        = 50
	MaxSkip        = 10000
	MaxPathLen     = 1024
	MaxDepth       = 64
	maxListing     = 2 << 20 // bytes of ls-tree or log output
	maxHeader      = 128 << 10
	DefaultTimeout = 10 * time.Second
)

// ErrNotFound is every answer of "no such ref, path or object".
var ErrNotFound = errors.New("gitview: not found")

// ErrBadPath is a path or ref the rules above refuse.
var ErrBadPath = errors.New("gitview: invalid path or ref")

var (
	refRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	hexRE = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// CleanPath checks a path inside a tree. "" is the root; one trailing "/" is
// dropped.
func CleanPath(p string) (string, error) {
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "", nil
	}
	if len(p) > MaxPathLen || !utf8.ValidString(p) {
		return "", ErrBadPath
	}
	segs := strings.Split(p, "/")
	if len(segs) > MaxDepth {
		return "", ErrBadPath
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return "", ErrBadPath
		}
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' || r == utf8.RuneError {
			return "", ErrBadPath
		}
	}
	return p, nil
}

// Repo is one bare repository.
type Repo struct {
	Dir string
	// Git is the git executable ("" for the one on PATH).
	Git string
	// Timeout bounds one command (0: DefaultTimeout).
	Timeout time.Duration
}

func (r *Repo) env() []string {
	return []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "HOME=" + os.DevNull}
}

// run executes git and returns at most limit bytes of its output; truncated says
// the limit was reached (the process is then killed, and its exit status does
// not count).
func (r *Repo) run(ctx context.Context, limit int, args ...string) (out []byte, truncated bool, err error) {
	d := r.Timeout
	if d <= 0 {
		d = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	g := r.Git
	if g == "" {
		g = "git"
	}
	full := append([]string{"--no-pager", "--git-dir=" + r.Dir, "-c", "core.quotepath=off"}, args...)
	c := exec.CommandContext(ctx, g, full...)
	c.Env = r.env()
	w := &capWriter{limit: limit, stop: cancel}
	c.Stdout = w
	c.WaitDelay = 2 * time.Second // a child that keeps the pipe open does not hold the page
	werr := c.Run()
	var exit *exec.ExitError
	switch {
	case w.cut:
		return w.buf, true, nil
	case ctx.Err() != nil:
		return nil, false, ctx.Err()
	case errors.As(werr, &exit): // git ran and said no: no such ref, path or object
		return nil, false, ErrNotFound
	case werr != nil: // git could not be run
		return nil, false, werr
	}
	return w.buf, false, nil
}

// capWriter keeps at most limit bytes and, at the first byte past them, stops
// the process: a command that has said more than a page can hold has no more to
// say that we would read.
type capWriter struct {
	buf   []byte
	limit int
	cut   bool
	stop  context.CancelFunc
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.limit - len(w.buf); len(p) > room {
		w.buf = append(w.buf, p[:room]...)
		w.cut = true
		w.stop()
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

// Resolve turns a ref ("HEAD", a branch, a tag, or a full object id) into the
// id of a commit.
func (r *Repo) Resolve(ctx context.Context, ref string) (string, error) {
	var cands []string
	switch {
	case ref == "HEAD":
		cands = []string{"HEAD"}
	case hexRE.MatchString(ref):
		cands = []string{ref}
	case refRE.MatchString(ref) && !strings.Contains(ref, ".."):
		cands = []string{"refs/heads/" + ref, "refs/tags/" + ref}
	default:
		return "", ErrBadPath
	}
	for _, c := range cands {
		out, _, err := r.run(ctx, 256, "rev-parse", "--verify", "--quiet", "--end-of-options", c+"^{commit}")
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil { // a timeout, or a git that cannot run: not "no such ref"
			return "", err
		}
		if id := strings.TrimSpace(string(out)); hexRE.MatchString(id) {
			return id, nil
		}
	}
	return "", ErrNotFound
}

func checkOID(oid string) error {
	if !hexRE.MatchString(oid) {
		return ErrBadPath
	}
	return nil
}

func spec(oid, p string) string { return oid + ":" + p }

// Kind is "tree" or "blob" for the object at p in the commit oid.
func (r *Repo) Kind(ctx context.Context, oid, p string) (string, error) {
	if err := checkOID(oid); err != nil {
		return "", err
	}
	out, _, err := r.run(ctx, 64, "cat-file", "-t", spec(oid, p))
	if err != nil {
		return "", err
	}
	k := strings.TrimSpace(string(out))
	if k != "tree" && k != "blob" {
		return "", ErrNotFound
	}
	return k, nil
}

// Entry is one line of a directory.
type Entry struct {
	Mode, Type, ID, Name string
	Size                 int64 // -1 for a directory or a submodule
}

// IsDir reports whether the entry is a directory.
func (e Entry) IsDir() bool { return e.Type == "tree" }

// Tree lists the directory at p, directories first, then by name. At most
// MaxTreeEntries are returned; truncated says there were more.
func (r *Repo) Tree(ctx context.Context, oid, p string) (es []Entry, truncated bool, err error) {
	if err := checkOID(oid); err != nil {
		return nil, false, err
	}
	out, cut, err := r.run(ctx, maxListing, "ls-tree", "-z", "-l", "--end-of-options", spec(oid, p))
	if err != nil {
		return nil, false, err
	}
	truncated = cut
	for len(out) > 0 {
		rec, rest, ok := bytes.Cut(out, []byte{0})
		if !ok { // the last record was cut: drop it
			break
		}
		out = rest
		e, ok := parseEntry(string(rec))
		if !ok {
			return nil, false, fmt.Errorf("gitview: malformed ls-tree record")
		}
		if len(es) == MaxTreeEntries {
			truncated = true
			break
		}
		es = append(es, e)
	}
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].IsDir() != es[j].IsDir() {
			return es[i].IsDir()
		}
		return es[i].Name < es[j].Name
	})
	return es, truncated, nil
}

// parseEntry reads "<mode> <type> <id> <size>\t<name>".
func parseEntry(rec string) (Entry, bool) {
	meta, name, ok := strings.Cut(rec, "\t")
	if !ok || name == "" {
		return Entry{}, false
	}
	fields := strings.Fields(meta)
	if len(fields) != 4 {
		return Entry{}, false
	}
	var f [4]string // a copy, so that a guard lost in a change makes a wrong entry, not a crash
	copy(f[:], fields)
	e := Entry{Mode: f[0], Type: f[1], ID: f[2], Name: name, Size: -1}
	if f[3] != "-" {
		n, err := strconv.ParseInt(f[3], 10, 64)
		if err != nil || n < 0 {
			return Entry{}, false
		}
		e.Size = n
	}
	return e, true
}

// BlobSize is the size of the blob at p.
func (r *Repo) BlobSize(ctx context.Context, oid, p string) (int64, error) {
	if err := checkOID(oid); err != nil {
		return 0, err
	}
	out, _, err := r.run(ctx, 32, "cat-file", "-s", spec(oid, p))
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || n < 0 {
		return 0, ErrNotFound
	}
	return n, nil
}

// Blob returns at most limit bytes of the blob at p.
func (r *Repo) Blob(ctx context.Context, oid, p string, limit int) ([]byte, bool, error) {
	if err := checkOID(oid); err != nil {
		return nil, false, err
	}
	return r.run(ctx, limit, "cat-file", "blob", spec(oid, p))
}

// IsText applies git's own test for a binary file (a NUL in the first 8000
// bytes) and refuses what is not UTF-8, which a page could not show faithfully.
func IsText(b []byte) bool {
	head := b
	if len(head) > 8000 {
		head = head[:8000]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	// a cut at the limit may split a rune: only the complete part is judged
	if len(b) >= MaxBlobView {
		for i := 0; i < utf8.UTFMax && len(b) > 0 && !utf8.Valid(b); i++ {
			b = b[:len(b)-1]
		}
	}
	return utf8.Valid(b)
}

// Commit is one line of the log.
type Commit struct {
	ID, Author, Subject string
	Time                time.Time
}

// Log returns up to LogPage commits reachable from oid, skipping skip; more
// says there are older ones.
func (r *Repo) Log(ctx context.Context, oid string, skip int) (cs []Commit, more bool, err error) {
	if err := checkOID(oid); err != nil {
		return nil, false, err
	}
	if skip < 0 || skip > MaxSkip {
		return nil, false, ErrBadPath
	}
	out, _, err := r.run(ctx, maxListing, "log", "--no-color", "--no-show-signature", "-n", strconv.Itoa(LogPage+1),
		"--skip="+strconv.Itoa(skip), "--format=%H%x1f%an%x1f%at%x1f%s%x1e", "--end-of-options", oid, "--")
	if err != nil {
		return nil, false, err
	}
	for _, rec := range strings.Split(string(out), "\x1e") {
		rec = strings.TrimPrefix(rec, "\n")
		f := strings.Split(rec, "\x1f")
		if len(f) != 4 || !hexRE.MatchString(f[0]) {
			continue
		}
		at, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			continue
		}
		cs = append(cs, Commit{ID: f[0], Author: f[1], Subject: f[3], Time: time.Unix(at, 0).UTC()})
	}
	if len(cs) > LogPage {
		cs, more = cs[:LogPage], true
	}
	return cs, more, nil
}

// Detail is one commit with its message and its diff against its first parent.
type Detail struct {
	Commit
	Parents       []string
	Message       string
	Diff          string
	DiffTruncated bool
}

// Show returns the commit oid with a bounded diff. A merge shows no diff.
func (r *Repo) Show(ctx context.Context, oid string) (Detail, error) {
	if err := checkOID(oid); err != nil {
		return Detail{}, err
	}
	out, _, err := r.run(ctx, maxHeader, "show", "-s", "--no-color", "--no-show-signature",
		"--format=%H%x1f%P%x1f%an%x1f%at%x1f%B", "--end-of-options", oid)
	if err != nil {
		return Detail{}, err
	}
	// A short answer leaves the last fields empty, which the id and the time
	// below refuse.
	var f [5]string
	copy(f[:], strings.SplitN(string(out), "\x1f", 5))
	if f[0] != oid {
		return Detail{}, ErrNotFound
	}
	at, err := strconv.ParseInt(f[3], 10, 64)
	if err != nil {
		return Detail{}, ErrNotFound
	}
	d := Detail{Commit: Commit{ID: oid, Author: f[2], Time: time.Unix(at, 0).UTC()}, Parents: strings.Fields(f[1]),
		Message: strings.TrimRight(f[4], "\n")}
	if len(d.Message) > MaxMessage {
		d.Message = strings.ToValidUTF8(d.Message[:MaxMessage], "�")
	}
	d.Subject, _, _ = strings.Cut(d.Message, "\n")
	diff, cut, err := r.run(ctx, MaxDiff, "diff-tree", "-p", "--root", "--no-commit-id", "--no-ext-diff", "--no-textconv",
		"-M", "--end-of-options", oid)
	if err != nil {
		return Detail{}, err
	}
	d.Diff, d.DiffTruncated = strings.ToValidUTF8(string(diff), "�"), cut
	return d, nil
}
