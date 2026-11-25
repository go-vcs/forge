// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package adminsrv_test

import (
	"path/filepath"
	"testing"

	"github.com/go-vcs/forge/internal/adminsrv"
)

// Where the socket's file permissions cannot be checked, enrolment is not offered.
func TestListenUnixUnsupported(t *testing.T) {
	if _, err := adminsrv.ListenUnix(filepath.Join(t.TempDir(), "s")); err == nil {
		t.Fatal("a Unix socket was offered on a platform that cannot check its permissions")
	}
}
