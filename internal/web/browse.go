// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-vcs/forge/internal/gitrepo"
	"github.com/go-vcs/forge/internal/gitview"
)

// The repository pages are read-only. They show what the protocols would let
// the same reader fetch: the rule is gitrepo.Service.Dir's, and a repository the
// reader may not see is a 404 like one that does not exist.

type crumb struct{ Name, Href string }

type entryView struct {
	Name, Href string
	Dir        bool
	Size       int64
}

type commitView struct {
	Href, Subject, Author, Date string
}

type diffLine struct{ Class, Text string }

// view is the data of every page.
type view struct {
	Login, CSRF string
	Title       string
	Owner, Repo string
	Ref         string
	Crumbs      []crumb
	Base        string // /owner/repo
	Entries     []entryView
	Truncated   bool
	Empty       bool
	Text        string
	Notice      string
	RawHref     string
	Commits     []commitView
	Newer       string
	Older       string
	Commit      commitView
	ID          string
	Parents     []crumb
	Message     string
	Diff        []diffLine
}

// call is one request to a repository page.
type call struct {
	s    *Server
	w    http.ResponseWriter
	r    *http.Request
	repo *gitview.Repo
	v    view
}

func (s *Server) browse(h func(c *call)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Repos == nil {
			s.fail(w, http.StatusNotFound, "Not found")
			return
		}
		sess, _, signed := s.sessionFor(r)
		login := ""
		v := view{}
		if signed {
			login, v.Login, v.CSRF = sess.Login, sess.Login, sess.CSRF
		}
		n, err := gitrepo.ParsePath(r.PathValue("owner") + "/" + r.PathValue("repo"))
		// ParsePath also reads "name.git", which git clients use; a page has one
		// address only.
		if err != nil || strings.HasSuffix(r.PathValue("repo"), ".git") {
			s.fail(w, http.StatusNotFound, "Not found")
			return
		}
		dir, err := s.Repos.Dir(n, login)
		if err != nil {
			s.fail(w, http.StatusNotFound, "Not found")
			return
		}
		if s.Limiter != nil {
			key := login
			if key == "" {
				key, _, _ = net.SplitHostPort(r.RemoteAddr)
			}
			release, err := s.Limiter.Acquire(key)
			if err != nil {
				w.Header().Set("Retry-After", "5")
				s.fail(w, http.StatusServiceUnavailable, "Busy, try again shortly")
				return
			}
			defer release()
		}
		v.Owner, v.Repo, v.Base = n.Owner, n.Repo, "/"+n.Owner+"/"+n.Repo
		v.Title = n.String()
		h(&call{s: s, w: w, r: r, repo: &gitview.Repo{Dir: dir, Git: s.Repos.Git, Timeout: s.GitTimeout}, v: v})
	}
}

func (s *Server) fail(w http.ResponseWriter, code int, msg string) {
	s.page(w, code, "error.html", struct{ Title, Message string }{http.StatusText(code), msg})
}

// err maps an error of gitview to a page.
func (c *call) err(err error) {
	switch {
	case errors.Is(err, gitview.ErrNotFound), errors.Is(err, gitview.ErrBadPath):
		c.s.fail(c.w, http.StatusNotFound, "Not found")
	case errors.Is(err, context.DeadlineExceeded):
		c.s.fail(c.w, http.StatusGatewayTimeout, "That took too long")
	default:
		c.s.Log.Error("browse", "repo", c.v.Title, "err", err)
		c.s.fail(c.w, http.StatusInternalServerError, "Internal error")
	}
}

func escPath(parts ...string) string {
	return (&url.URL{Path: strings.Join(parts, "/")}).EscapedPath()
}

func (c *call) href(kind, ref, p string) string {
	if p == "" {
		return escPath(c.v.Base, kind, ref)
	}
	return escPath(c.v.Base, kind, ref, p)
}

// target reads {ref} and {path...}.
func (c *call) target() (oid, p string, ok bool) {
	p, err := gitview.CleanPath(c.r.PathValue("path"))
	if err != nil {
		c.err(err)
		return "", "", false
	}
	oid, err = c.repo.Resolve(c.r.Context(), c.r.PathValue("ref"))
	if err != nil {
		c.err(err)
		return "", "", false
	}
	c.v.Ref = c.r.PathValue("ref")
	return oid, p, true
}

func (c *call) crumbs(kind, p string) {
	c.v.Crumbs = []crumb{{c.v.Repo, c.href("tree", c.v.Ref, "")}}
	if p == "" {
		return
	}
	acc := ""
	for _, seg := range strings.Split(p, "/") {
		if acc != "" {
			acc += "/"
		}
		acc += seg
		k := "tree"
		if acc == p {
			k = kind
		}
		c.v.Crumbs = append(c.v.Crumbs, crumb{seg, c.href(k, c.v.Ref, acc)})
	}
}

func (c *call) tree(oid, p string) {
	es, trunc, err := c.repo.Tree(c.r.Context(), oid, p)
	if err != nil {
		c.err(err)
		return
	}
	c.v.Truncated = trunc
	for _, e := range es {
		ep := e.Name
		if p != "" {
			ep = p + "/" + e.Name
		}
		ev := entryView{Name: e.Name, Dir: e.IsDir(), Size: e.Size}
		switch e.Type {
		case "tree":
			ev.Href = c.href("tree", c.v.Ref, ep)
		case "blob":
			ev.Href = c.href("blob", c.v.Ref, ep)
		}
		c.v.Entries = append(c.v.Entries, ev)
	}
	c.crumbs("tree", p)
	c.s.page(c.w, http.StatusOK, "tree.html", c.v)
}

func (s *Server) treePage(c *call) {
	oid, p, ok := c.target()
	if !ok {
		return
	}
	if p != "" {
		k, err := c.repo.Kind(c.r.Context(), oid, p)
		if err != nil {
			c.err(err)
			return
		}
		if k == "blob" {
			http.Redirect(c.w, c.r, c.href("blob", c.v.Ref, p), http.StatusFound)
			return
		}
	}
	c.tree(oid, p)
}

func (s *Server) homePage(c *call) {
	c.v.Ref = "HEAD"
	oid, err := c.repo.Resolve(c.r.Context(), "HEAD")
	if errors.Is(err, gitview.ErrNotFound) {
		c.v.Empty = true
		c.s.page(c.w, http.StatusOK, "tree.html", c.v)
		return
	}
	if err != nil {
		c.err(err)
		return
	}
	c.tree(oid, "")
}

func (s *Server) blobPage(c *call) {
	oid, p, ok := c.target()
	if !ok {
		return
	}
	if p == "" {
		c.err(gitview.ErrNotFound)
		return
	}
	ctx := c.r.Context()
	k, err := c.repo.Kind(ctx, oid, p)
	if err != nil {
		c.err(err)
		return
	}
	if k == "tree" {
		http.Redirect(c.w, c.r, c.href("tree", c.v.Ref, p), http.StatusFound)
		return
	}
	c.crumbs("blob", p)
	c.v.Title = c.v.Title + " " + p
	c.v.RawHref = c.href("raw", c.v.Ref, p)
	size, err := c.repo.BlobSize(ctx, oid, p)
	if err != nil {
		c.err(err)
		return
	}
	if size > gitview.MaxBlobView {
		c.v.Notice = "This file is too large to show (" + strconv.FormatInt(size, 10) + " bytes)."
		c.s.page(c.w, http.StatusOK, "blob.html", c.v)
		return
	}
	b, _, err := c.repo.Blob(ctx, oid, p, gitview.MaxBlobView)
	if err != nil {
		c.err(err)
		return
	}
	if !gitview.IsText(b) {
		c.v.Notice = "This file is binary (" + strconv.Itoa(len(b)) + " bytes)."
	} else {
		c.v.Text = string(b)
	}
	c.s.page(c.w, http.StatusOK, "blob.html", c.v)
}

// rawPage serves a blob's bytes. Text is plain text; anything else is a
// download. Nothing is ever served with a type a browser would render.
func (s *Server) rawPage(c *call) {
	oid, p, ok := c.target()
	if !ok {
		return
	}
	ctx := c.r.Context()
	// An empty path is the commit's own tree: not a blob.
	k, err := c.repo.Kind(ctx, oid, p)
	if err != nil {
		c.err(err)
		return
	}
	if k != "blob" {
		c.err(gitview.ErrNotFound)
		return
	}
	size, err := c.repo.BlobSize(ctx, oid, p)
	if err != nil {
		c.err(err)
		return
	}
	if size > gitview.MaxRaw {
		c.s.fail(c.w, http.StatusRequestEntityTooLarge, "This file is too large to serve")
		return
	}
	b, trunc, err := c.repo.Blob(ctx, oid, p, gitview.MaxRaw)
	if err != nil {
		c.err(err)
		return
	}
	if trunc {
		c.s.fail(c.w, http.StatusRequestEntityTooLarge, "This file is too large to serve")
		return
	}
	h := c.w.Header()
	if gitview.IsText(b) {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Disposition", "attachment")
	}
	h.Set("Content-Length", strconv.Itoa(len(b)))
	h.Set("Cache-Control", "no-store")
	_, _ = c.w.Write(b)
}

func commitLine(c *call, cm gitview.Commit) commitView {
	return commitView{Href: escPath(c.v.Base, "commit", cm.ID), Subject: cm.Subject, Author: cm.Author,
		Date: cm.Time.Format("2006-01-02 15:04 UTC")}
}

func (s *Server) logPage(c *call) {
	oid, err := c.repo.Resolve(c.r.Context(), c.r.PathValue("ref"))
	if err != nil {
		c.err(err)
		return
	}
	c.v.Ref = c.r.PathValue("ref")
	skip := 0
	if q := c.r.URL.Query().Get("skip"); q != "" {
		skip, err = strconv.Atoi(q)
		if err != nil || skip < 0 || skip > gitview.MaxSkip {
			c.err(gitview.ErrBadPath)
			return
		}
	}
	cs, more, err := c.repo.Log(c.r.Context(), oid, skip)
	if err != nil {
		c.err(err)
		return
	}
	for _, cm := range cs {
		c.v.Commits = append(c.v.Commits, commitLine(c, cm))
	}
	base := c.href("commits", c.v.Ref, "")
	if more && skip+gitview.LogPage <= gitview.MaxSkip {
		c.v.Older = base + "?skip=" + strconv.Itoa(skip+gitview.LogPage)
	}
	if skip > 0 {
		c.v.Newer = base + "?skip=" + strconv.Itoa(max(0, skip-gitview.LogPage))
	}
	c.v.Crumbs = []crumb{{c.v.Repo, c.href("tree", c.v.Ref, "")}}
	c.s.page(c.w, http.StatusOK, "log.html", c.v)
}

func (s *Server) commitPage(c *call) {
	sha := c.r.PathValue("sha")
	oid, err := c.repo.Resolve(c.r.Context(), sha)
	if err != nil || oid != sha {
		c.err(gitview.ErrNotFound)
		return
	}
	d, err := c.repo.Show(c.r.Context(), oid)
	if err != nil {
		c.err(err)
		return
	}
	c.v.Ref = oid
	c.v.ID, c.v.Message, c.v.Commit = oid, d.Message, commitLine(c, d.Commit)
	for _, p := range d.Parents {
		c.v.Parents = append(c.v.Parents, crumb{p, escPath(c.v.Base, "commit", p)})
	}
	c.v.Diff = classify(d.Diff)
	c.v.Truncated = d.DiffTruncated
	c.v.Crumbs = []crumb{{c.v.Repo, c.href("tree", c.v.Ref, "")}}
	c.s.page(c.w, http.StatusOK, "commit.html", c.v)
}

// classify gives each line of a diff one of a fixed set of CSS classes. The
// class is never derived from the text, only chosen among these names.
func classify(d string) []diffLine {
	var out []diffLine
	inHunk := false
	for _, l := range strings.Split(d, "\n") {
		cl := "ctx"
		switch {
		case strings.HasPrefix(l, "diff --git "):
			inHunk, cl = false, "meta"
		case strings.HasPrefix(l, "@@"):
			inHunk, cl = true, "hunk"
		case !inHunk:
			cl = "meta"
		case strings.HasPrefix(l, "+"):
			cl = "add"
		case strings.HasPrefix(l, "-"):
			cl = "del"
		}
		out = append(out, diffLine{cl, l})
	}
	if n := len(out); n > 0 && out[n-1].Text == "" {
		out = out[:n-1]
	}
	return out
}

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{owner}/{repo}", s.browse(s.homePage))
	for _, k := range []struct {
		kind string
		h    func(*call)
	}{{"tree", s.treePage}, {"blob", s.blobPage}, {"raw", s.rawPage}} {
		mux.HandleFunc("GET /{owner}/{repo}/"+k.kind+"/{ref}", s.browse(k.h))
		mux.HandleFunc("GET /{owner}/{repo}/"+k.kind+"/{ref}/{path...}", s.browse(k.h))
	}
	mux.HandleFunc("GET /{owner}/{repo}/commits/{ref}", s.browse(s.logPage))
	mux.HandleFunc("GET /{owner}/{repo}/commit/{sha}", s.browse(s.commitPage))
}
