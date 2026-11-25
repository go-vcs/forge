// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package adminsrv

import (
	"fmt"
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
)

// ownedBy says whether fi is owned by uid. A file whose owner cannot be read
// is not owned by anyone.
func ownedBy(fi fs.FileInfo, uid int) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid
}

func checkSecretFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("adminsrv: key file %s is accessible to group or others (mode %v); use 0600", path, fi.Mode().Perm())
	}
	return nil
}
