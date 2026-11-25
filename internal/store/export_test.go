// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package store

import "io/fs"

// UseMigrations swaps the migration set and returns the function that puts the
// real one back.
func UseMigrations(f fs.FS) (restore func()) {
	old := migrationFS
	migrationFS = f
	return func() { migrationFS = old }
}

// UseDriver swaps the database/sql driver name and returns the restore.
func UseDriver(name string) (restore func()) {
	old := driverName
	driverName = name
	return func() { driverName = old }
}
