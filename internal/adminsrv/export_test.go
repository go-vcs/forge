// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminsrv

import (
	"context"
	"crypto/tls"
)

// Finish and SealStatus expose the unexported helpers to the tests.
func (a *Admin) Finish(ctx context.Context, err error) { a.finish(ctx, nil, err) }

func SealStatus(err error) error { return sealStatus(err) }

// UseExporter swaps the keying-material export Exporter calls and returns the
// restore.
func UseExporter(f func(*tls.ConnectionState, string, []byte, int) ([]byte, error)) (restore func()) {
	old := exportKeyingMaterial
	exportKeyingMaterial = f
	return func() { exportKeyingMaterial = old }
}
