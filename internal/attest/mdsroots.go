// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/go-authn/fido/mds"
)

// ErrModelRevoked is returned when the metadata service reports a compromise
// or revocation for the model.
var ErrModelRevoked = errors.New("the FIDO metadata service reports this model as compromised or revoked")

// badStatus are the MDS3 authenticator statuses (3.1.3) that end trust in a
// model for good.
var badStatus = map[string]bool{
	"REVOKED":                      true,
	"ATTESTATION_KEY_COMPROMISE":   true,
	"USER_VERIFICATION_BYPASS":     true,
	"USER_KEY_REMOTE_COMPROMISE":   true,
	"USER_KEY_PHYSICAL_COMPROMISE": true,
}

// ErrStaleMetadata is returned when the blob's nextUpdate has passed. The blob
// was current when it was verified; what the metadata service has said since
// (a revocation, a compromise) is not in it.
var ErrStaleMetadata = errors.New("the FIDO metadata blob is past its nextUpdate")

// MDSRoots serves attestation roots from a verified MDS3 blob, for as long as
// that blob is current.
type MDSRoots struct {
	// Blob is the result of mds.Verify. A Blob built any other way has no
	// nextUpdate instant and serves nothing.
	Blob *mds.Blob
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Roots implements [Roots].
func (m MDSRoots) Roots(aaguid string) ([]*x509.Certificate, error) {
	if m.Blob == nil {
		return nil, fmt.Errorf("%w: no blob loaded", ErrUnknownModel)
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	// Checked on every lookup, not once: the process outlives the blob.
	if next := m.Blob.NextUpdate(); !now().Before(next) {
		return nil, fmt.Errorf("%w: %s", ErrStaleMetadata, next.Format(time.DateOnly))
	}
	e := m.Blob.Lookup(aaguid)
	if e == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownModel, aaguid)
	}
	for _, r := range e.StatusReports {
		if badStatus[r.Status] {
			return nil, fmt.Errorf("%w: %s %s", ErrModelRevoked, aaguid, r.Status)
		}
	}
	return e.RootCertificates()
}
