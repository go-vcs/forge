// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv

import (
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// ListenUnix listens on a Unix socket whose access is controlled by file
// permissions: the directory must be owned by this user and closed to group
// and others (0700), and the socket is made 0600. An existing socket at the
// path is replaced; anything else there is refused.
func ListenUnix(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("adminsrv: socket directory %s must be a directory with mode 0700 (is %v)", dir, fi.Mode())
	}
	if !ownedBy(fi, geteuid()) {
		return nil, fmt.Errorf("adminsrv: socket directory %s is not owned by this user", dir)
	}
	if li, err := os.Lstat(path); err == nil {
		if li.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("adminsrv: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// chmod and geteuid are variables so that a test can make the step after
// Listen fail and can pose as another user.
var (
	chmod   = os.Chmod
	geteuid = os.Geteuid
	readAll = io.ReadAll
)

// ownedBy says whether fi is owned by uid. A file whose owner cannot be read
// is not owned by anyone.
func ownedBy(fi fs.FileInfo, uid int) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid
}

// maxSecretLen bounds what readSecretFile reads.
const maxSecretLen = 1 << 20

// readSecretFile reads a secret file that must be a regular file (not a
// symbolic link, which is refused at open, nor a device or FIFO), owned by this
// process's effective user, and closed to group and others. The checks are made
// on the opened descriptor, so the file checked is the file read.
func readSecretFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("adminsrv: key file %s: %w (symbolic links are refused)", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("adminsrv: key file %s is not a regular file", path)
	}
	if !ownedBy(fi, geteuid()) {
		return nil, fmt.Errorf("adminsrv: key file %s is not owned by this user", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("adminsrv: key file %s is accessible to group or others (mode %v); use 0600", path, fi.Mode().Perm())
	}
	b, err := readAll(io.LimitReader(f, maxSecretLen+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSecretLen {
		return nil, fmt.Errorf("adminsrv: key file %s is larger than %d bytes", path, maxSecretLen)
	}
	return b, nil
}
