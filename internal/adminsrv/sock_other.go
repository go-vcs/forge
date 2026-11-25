// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package adminsrv

import (
	"errors"
	"net"
)

// ListenUnix is not supported here: the file-permission guarantee of the
// enrolment socket cannot be checked on this platform.
func ListenUnix(string) (net.Listener, error) {
	return nil, errors.New("adminsrv: the enrolment socket requires a Unix system")
}

func checkSecretFile(string) error { return nil }
