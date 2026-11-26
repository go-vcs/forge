// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package gitssh

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-vcs/forge/internal/gitrepo"
)

// MaxCommandLen bounds an exec request's command line.
const MaxCommandLen = 512

// ErrPush is returned for git-receive-pack: push arrives with milestone 4.
var ErrPush = errors.New("push over SSH is not supported yet (milestone 4); this forge serves clone and fetch only")

// ErrCommand is returned for any command that is not git-upload-pack.
var ErrCommand = errors.New("only git-upload-pack is available: no shell, no other command")

// ParseExec reads the command line git sends: git-upload-pack '<path>' (the
// path always single-quoted, gitprotocol-pack). The command name is compared
// whole; the path must be owner/name and holds no quote, backslash or "!"
// (what git's own quoting would have to escape), so nothing is ever unquoted
// or interpreted: there is no shell.
func ParseExec(cmd string) (gitrepo.Name, error) {
	if len(cmd) > MaxCommandLen {
		return gitrepo.Name{}, fmt.Errorf("%w: command too long", ErrCommand)
	}
	name, arg, ok := strings.Cut(cmd, " ")
	switch name {
	case "git-upload-pack":
	case "git-receive-pack":
		return gitrepo.Name{}, ErrPush
	default:
		return gitrepo.Name{}, ErrCommand
	}
	if !ok || len(arg) < 3 || arg[0] != '\'' || arg[len(arg)-1] != '\'' {
		return gitrepo.Name{}, fmt.Errorf("%w: usage: git-upload-pack '<owner>/<name>'", ErrCommand)
	}
	path := arg[1 : len(arg)-1]
	return gitrepo.ParsePath(path)
}

// wantsV2 reports whether a GIT_PROTOCOL value (colon-separated extra
// parameters) asks for protocol version 2.
func wantsV2(v string) bool {
	return slices.Contains(strings.Split(v, ":"), "version=2")
}
