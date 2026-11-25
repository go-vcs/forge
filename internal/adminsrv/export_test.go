// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminsrv

import "crypto/tls"

// UseExporter swaps the keying-material export Exporter calls and returns the
// restore.
func UseExporter(f func(*tls.ConnectionState, string, []byte, int) ([]byte, error)) (restore func()) {
	old := exportKeyingMaterial
	exportKeyingMaterial = f
	return func() { exportKeyingMaterial = old }
}
