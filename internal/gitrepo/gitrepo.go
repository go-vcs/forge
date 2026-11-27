// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package gitrepo maps a repository name received from a git client to a bare
// repository on disk, decides who may read it, and bounds how many fetches run
// at once. SSH and smart HTTP both go through it, so they refuse the same names
// and apply the same rule.
//
// Repositories live at <root>/<owner>/<name>.git. Until milestone 4 (push) they
// are created outside the forge with `git init --bare`. There is no ACL yet:
// an account reads its own repositories, and anyone reads one that holds the
// file git-daemon-export-ok (git's own "public" marker, honoured by git daemon
// and http-backend).
package gitrepo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-vcs/gitproto"

	"github.com/go-vcs/forge/internal/store"
)

// PublicMarker is the file whose presence in a repository makes it public.
const PublicMarker = "git-daemon-export-ok"

// ErrNotFound is returned for a repository that does not exist and for one the
// caller may not read: the two are indistinguishable on purpose, so a name
// cannot be probed.
var ErrNotFound = errors.New("repository not found")

// ErrBusy is returned when a concurrency cap is reached.
var ErrBusy = errors.New("too many concurrent git sessions")

// ErrPath is returned for a path that is not owner/name.
var ErrPath = errors.New("invalid repository path")

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// Name identifies a repository.
type Name struct{ Owner, Repo string }

func (n Name) String() string { return n.Owner + "/" + n.Repo }

// ParsePath reads "owner/name", "owner/name.git" or either with one leading
// "/". Anything else is refused: no ".." and no other separator, no empty
// segment, no byte outside printable ASCII, and only the lowercase letters,
// digits, ".", "_" and "-" that logins and names are made of.
func ParsePath(p string) (Name, error) {
	// The two anchored patterns below are the whole check: they bound the
	// owner to 39 and the name to 100 bytes and allow nothing outside
	// [a-z0-9._-], so there is no length or byte test of its own to keep in step.
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, ".git")
	owner, repo, _ := strings.Cut(p, "/")
	if store.ValidLogin(owner) != nil {
		return Name{}, fmt.Errorf("%w: owner", ErrPath)
	}
	if !nameRE.MatchString(repo) || strings.Contains(repo, "..") || strings.HasSuffix(repo, ".git") {
		return Name{}, fmt.Errorf("%w: name", ErrPath)
	}
	return Name{Owner: owner, Repo: repo}, nil
}

// Service opens repositories under Root.
type Service struct {
	// Root is the directory holding <owner>/<name>.git.
	Root string
	// Git is the git executable ("" for the one on PATH).
	Git string
	// Limits bound one protocol request (zero fields mean gitproto's defaults).
	Limits gitproto.Limits
	// PackThreads is passed to pack-objects (0: git's default).
	PackThreads int
	// Agent is advertised to clients ("" for gitproto's).
	Agent string
}

// Validate refuses a service that cannot work.
func (s *Service) Validate() error {
	fi, err := os.Stat(s.Root)
	if err != nil {
		return fmt.Errorf("gitrepo: repositories root: %w", err)
	}
	if !fi.IsDir() {
		return errors.New("gitrepo: repositories root is not a directory")
	}
	return s.Limits.Validate()
}

func isDir(p string) bool {
	fi, err := os.Lstat(p) // a symbolic link is not followed: it could leave the root
	return err == nil && fi.IsDir()
}

func isFile(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Dir returns the directory of the bare repository n if login may read it, with
// the rule of Open (the web pages and the protocols read the same repositories).
func (s *Service) Dir(n Name, login string) (string, error) {
	ownerDir := filepath.Join(s.Root, n.Owner)
	dir := filepath.Join(ownerDir, n.Repo+".git")
	if !isDir(ownerDir) || !isDir(dir) || !isFile(filepath.Join(dir, "HEAD")) {
		return "", ErrNotFound
	}
	if login == "" || login != n.Owner {
		if !isFile(filepath.Join(dir, PublicMarker)) {
			return "", ErrNotFound
		}
	}
	return dir, nil
}

// Open returns the protocol server for n, for the account login ("" for an
// anonymous reader). A missing repository, one that is not a plain directory
// inside Root, and one login may not read all return ErrNotFound.
func (s *Service) Open(n Name, login string) (*gitproto.Server, error) {
	dir, err := s.Dir(n, login)
	if err != nil {
		return nil, err
	}
	return &gitproto.Server{
		Repo:   &gitproto.GitRepo{Dir: dir, Git: s.Git, PackThreads: s.PackThreads},
		Limits: s.Limits,
		Agent:  s.Agent,
	}, nil
}

// Limiter caps concurrent sessions in total and per key (an account, or a
// remote host). A session over a cap is refused at once, not queued: waiting
// would let idle sessions hold everyone else out.
type Limiter struct {
	Total, PerKey int

	mu    sync.Mutex
	total int
	keys  map[string]int
}

// Acquire takes a slot for key. The returned function gives it back and may be
// called more than once.
func (l *Limiter) Acquire(key string) (release func(), err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.keys == nil {
		l.keys = map[string]int{}
	}
	if l.total >= l.Total || l.keys[key] >= l.PerKey {
		return nil, ErrBusy
	}
	l.total++
	l.keys[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if l.keys[key]--; l.keys[key] == 0 {
				delete(l.keys, key)
			}
		})
	}, nil
}

// Defaults for the caps and the time one request may take.
const (
	DefaultTotalSessions   = 64
	DefaultSessionsPerKey  = 4
	DefaultRequestDuration = 15 * time.Minute
)

// WithTimeout derives the context a request runs under.
func WithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = DefaultRequestDuration
	}
	return context.WithTimeout(ctx, d)
}
