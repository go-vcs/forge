// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv

import "io/fs"

// OwnedBy exposes ownedBy to the tests.
func OwnedBy(fi fs.FileInfo, uid int) bool { return ownedBy(fi, uid) }

// UseEuid makes ListenUnix believe it runs as uid and returns the restore.
func UseEuid(uid int) (restore func()) {
	old := geteuid
	geteuid = func() int { return uid }
	return func() { geteuid = old }
}

// UseChmod swaps the chmod ListenUnix applies to its socket and returns the
// restore.
func UseChmod(f func(string, fs.FileMode) error) (restore func()) {
	old := chmod
	chmod = f
	return func() { chmod = old }
}
