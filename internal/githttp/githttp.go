// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package githttp serves git clone and fetch over smart HTTP, protocol
// version 2 only, anonymously and for public repositories only
// (gitprotocol-http, gitprotocol-v2).
//
// Two requests exist: GET <repo>/info/refs?service=git-upload-pack, which
// answers the capability advertisement, and POST <repo>/git-upload-pack, which
// answers one command request (stateless-rpc). Push, the dumb protocol and
// protocol versions 0 and 1 are refused with a message that says so.
//
// A repository that does not exist and one the caller may not read both answer
// 404, so a name cannot be probed. gitprotocol-http asks for 403 when the
// repository exists and is not permitted; that is a deliberate departure.
package githttp

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-vcs/gitproto"

	"github.com/go-vcs/forge/internal/gitrepo"
)

// Media types (gitprotocol-http).
const (
	typeAdvertisement = "application/x-git-upload-pack-advertisement"
	typeRequest       = "application/x-git-upload-pack-request"
	typeResult        = "application/x-git-upload-pack-result"
)

// Bounds that are not configurable.
const (
	// MaxPathLen is the longest request path read at all.
	MaxPathLen = 512
	// DefaultMaxBody bounds a request body as it travels (compressed or not).
	DefaultMaxBody = 8 << 20
	// errorGrace is how long past the request deadline a reply may still be written.
	errorGrace = time.Second
)

// Endpoint is the part of a request path after the repository.
type Endpoint int

// The endpoints a request path may end in.
const (
	InfoRefs Endpoint = iota + 1
	UploadPack
	ReceivePack
)

// ErrRoute is returned for a path that is none of the endpoints.
var ErrRoute = errors.New("no such resource")

var routes = []struct {
	suffix string
	ep     Endpoint
}{
	{"/info/refs", InfoRefs},
	{"/git-upload-pack", UploadPack},
	{"/git-receive-pack", ReceivePack},
}

// ParsePath splits a request path into the repository and the endpoint. It is
// strict: a path longer than MaxPathLen, with a byte outside printable ASCII,
// or whose repository part is not owner/name[.git] is refused.
func ParsePath(p string) (gitrepo.Name, Endpoint, error) {
	if len(p) > MaxPathLen || !strings.HasPrefix(p, "/") {
		return gitrepo.Name{}, 0, ErrRoute
	}
	for _, r := range routes {
		if rest, ok := strings.CutSuffix(p, r.suffix); ok {
			n, err := gitrepo.ParsePath(rest)
			if err != nil {
				return gitrepo.Name{}, 0, ErrRoute
			}
			return n, r.ep, nil
		}
	}
	return gitrepo.Name{}, 0, ErrRoute
}

// Handler is the smart HTTP git server.
type Handler struct {
	Repos    *gitrepo.Service
	Sessions *gitrepo.Limiter // keyed by client address
	Log      *slog.Logger

	// RequestTimeout bounds one request (0: gitrepo's default).
	RequestTimeout time.Duration
	// MaxBody bounds a request body as sent (0: DefaultMaxBody).
	MaxBody int64
}

const (
	msgPush  = "forge: push is not available over HTTP (milestone 4)"
	msgDumb  = "forge: only smart HTTP with git protocol version 2 is served (git 2.26 or later)"
	msgProto = "forge: git protocol version 2 is required: send \"Git-Protocol: version=2\" (git 2.26 or later)"
)

func wantsV2(h string) bool {
	for _, v := range strings.Split(h, ":") {
		if v == "version=2" {
			return true
		}
	}
	return false
}

func (h *Handler) maxBody() int64 {
	if h.MaxBody > 0 {
		return h.MaxBody
	}
	return DefaultMaxBody
}

// maxDecoded is the most a request may hold once decompressed.
func (h *Handler) maxDecoded() int64 {
	n := h.Repos.Limits.MaxRequestBytes
	if n == 0 {
		n = gitproto.DefaultLimits.MaxRequestBytes
	}
	return n + 1<<16 // one more pkt-line than the bound, so gitproto is the one to refuse
}

func refuse(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintln(w, msg)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	if r.URL.RawPath != "" { // an encoding that is not the canonical one
		refuse(w, http.StatusNotFound, "forge: not found")
		return
	}
	name, ep, err := ParsePath(r.URL.Path)
	if err != nil {
		refuse(w, http.StatusNotFound, "forge: not found")
		return
	}
	switch ep {
	case InfoRefs:
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			refuse(w, http.StatusMethodNotAllowed, "forge: use GET")
			return
		}
		switch r.URL.RawQuery {
		case "service=git-upload-pack":
		case "service=git-receive-pack":
			refuse(w, http.StatusForbidden, msgPush)
			return
		default:
			refuse(w, http.StatusForbidden, msgDumb)
			return
		}
	case UploadPack:
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			refuse(w, http.StatusMethodNotAllowed, "forge: use POST")
			return
		}
		if r.Header.Get("Content-Type") != typeRequest {
			refuse(w, http.StatusUnsupportedMediaType, "forge: Content-Type must be "+typeRequest)
			return
		}
	case ReceivePack:
		refuse(w, http.StatusForbidden, msgPush)
		return
	}
	if !wantsV2(r.Header.Get("Git-Protocol")) {
		refuse(w, http.StatusBadRequest, msgProto)
		return
	}

	// Anonymous: only a public repository is opened.
	srv, err := h.Repos.Open(name, "")
	if err != nil {
		refuse(w, http.StatusNotFound, "forge: not found")
		return
	}
	host, _, splitErr := net.SplitHostPort(r.RemoteAddr)
	if splitErr != nil {
		host = r.RemoteAddr
	}
	release, err := h.Sessions.Acquire(host)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		refuse(w, http.StatusServiceUnavailable, "forge: busy, try again later")
		return
	}
	defer release()
	ctx, cancel := gitrepo.WithTimeout(r.Context(), h.RequestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	// A client that stalls on the body or the reply is cut off at the deadline.
	deadline, _ := ctx.Deadline()
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline.Add(errorGrace)) // room to say why the read was cut

	if ep == InfoRefs {
		w.Header().Set("Content-Type", typeAdvertisement)
		if err := srv.Advertise(w); err != nil {
			h.Log.Info("advertise ended", "remote", host, "repo", name.String(), "err", err)
		}
		return
	}

	body := io.Reader(http.MaxBytesReader(w, r.Body, h.maxBody()))
	switch r.Header.Get("Content-Encoding") {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			refuse(w, http.StatusBadRequest, "forge: bad gzip body")
			return
		}
		defer zr.Close()
		body = zr
	default:
		refuse(w, http.StatusUnsupportedMediaType, "forge: Content-Encoding must be gzip or absent")
		return
	}
	body = io.LimitReader(body, h.maxDecoded())

	w.Header().Set("Content-Type", typeResult)
	err = srv.ServeRequest(ctx, body, w)
	switch {
	case err == nil:
	case errors.Is(err, io.EOF): // nothing was written: say so with a status
		w.Header().Del("Content-Type")
		refuse(w, http.StatusBadRequest, "forge: empty request")
	default:
		// gitproto has already answered with an ERR line, which is the only
		// error channel once the reply is a pkt-line stream (this includes a
		// body over the bounds and a read cut at the deadline).
		h.Log.Info("request ended", "remote", host, "repo", name.String(), "err", err)
	}
}
