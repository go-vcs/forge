// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"crypto/x509"
	"errors"
	"fmt"

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

// MDSRoots serves attestation roots from a verified MDS3 blob.
type MDSRoots struct{ Blob *mds.Blob }

// Roots implements [Roots].
func (m MDSRoots) Roots(aaguid string) ([]*x509.Certificate, error) {
	if m.Blob == nil {
		return nil, fmt.Errorf("%w: no blob loaded", ErrUnknownModel)
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
