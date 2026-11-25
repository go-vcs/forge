// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminclient

import "crypto/tls"

// SetExport replaces the TLS exporter and returns the function that puts the
// real one back.
func SetExport(f func(*tls.ConnectionState, string, []byte, int) ([]byte, error)) (restore func()) {
	old := exportKeyingMaterial
	exportKeyingMaterial = f
	return func() { exportKeyingMaterial = old }
}
