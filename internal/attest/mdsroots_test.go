// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package attest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/go-authn/fido/mds"
	"github.com/go-vcs/forge/internal/attest"
	"github.com/go-vcs/forge/internal/fidotest"
)

// The test blobs are signed at blobSigned and name blobNextUpdate as their
// nextUpdate; MDS3 dates are whole days, so the blob ends at blobEnd.
const blobNextUpdate = "2026-12-01"

var (
	blobSigned = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	blobEnd    = time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC)
)

func at(ts time.Time) func() time.Time { return func() time.Time { return ts } }

// verifiedBlob returns what mds.Verify returns for a blob holding entries: a
// blob signed by a test authority, checked at blobSigned exactly as a real one
// is (signature, chain, host name, CRL, nextUpdate). MDSRoots is only ever
// given such a blob, so its tests are too.
func verifiedBlob(t *testing.T, entries ...mds.Entry) *mds.Blob {
	t.Helper()
	const host, crlURL = "mds.test", "http://crl.test/root.crl"
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rootKey, leafKey := newKey(), newKey()
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test metadata root"},
		NotBefore:             blobSigned.AddDate(-1, 0, 0),
		NotAfter:              blobSigned.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             blobSigned.AddDate(0, -1, 0),
		NotAfter:              blobSigned.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{crlURL},
	}, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: blobSigned.AddDate(0, 0, -1),
		NextUpdate: blobSigned.AddDate(0, 0, 1),
	}, root, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	b64 := base64.RawURLEncoding.EncodeToString
	header, err := json.Marshal(map[string]any{
		"alg": "ES256", "typ": "JWT",
		"x5c": []string{base64.StdEncoding.EncodeToString(leafDER)},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(mds.Blob{No: 1, NextUpdateDate: blobNextUpdate, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	signed := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	pool := x509.NewCertPool()
	pool.AddCert(root)
	blob, err := mds.Verify([]byte(signed+"."+b64(sig)), mds.Options{
		Roots:    pool,
		Hostname: host,
		Now:      at(blobSigned),
		CRL: func(u string) ([]byte, error) {
			if u != crlURL {
				return nil, errors.New("no such CRL")
			}
			return crl, nil
		},
	})
	if err != nil {
		t.Fatalf("the test blob does not verify: %v", err)
	}
	if !blob.NextUpdate().Equal(blobEnd) {
		t.Fatalf("nextUpdate = %s, want %s", blob.NextUpdate(), blobEnd)
	}
	return blob
}

// A forge process outlives the blob it verified at start. Once nextUpdate has
// passed, the blob no longer says what the metadata service says: a model
// revoked since then would still be enrolled. No roots are served from it.
func TestABlobPastItsNextUpdateServesNoRoots(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	id := attest.FormatAAGUID(a.AAGUID)
	blob := blobFor(t, a, "")

	for _, c := range []struct {
		name  string
		now   time.Time
		stale bool
	}{
		{"when verified", blobSigned, false},
		{"last instant", blobEnd.Add(-time.Nanosecond), false},
		{"at nextUpdate", blobEnd, true},
		{"a month later", blobEnd.AddDate(0, 1, 0), true},
	} {
		rs, err := attest.MDSRoots{Blob: blob, Now: at(c.now)}.Roots(id)
		if c.stale {
			if !errors.Is(err, attest.ErrStaleMetadata) || rs != nil {
				t.Errorf("%s: roots %v, err %v; want ErrStaleMetadata and no roots", c.name, rs, err)
			}
			continue
		}
		if err != nil || len(rs) != 1 {
			t.Errorf("%s: roots %v, err %v; want the model's root", c.name, rs, err)
		}
	}

	// Through a policy: the enrolment is refused, for that reason.
	f, ad, st := make1(t, a)
	p, err := attest.NewPolicy(rp, [][16]byte{a.AAGUID}, attest.MDSRoots{Blob: blob, Now: at(blobEnd)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(f, ad, st, cdh); !errors.Is(err, attest.ErrStaleMetadata) {
		t.Fatalf("enrolment against a stale blob: %v, want ErrStaleMetadata", err)
	}
}

// A blob that did not come out of mds.Verify has no nextUpdate instant. It is
// refused whatever the clock says, the wall clock included: nothing vouches
// for it.
func TestABlobThatWasNotVerifiedServesNoRoots(t *testing.T) {
	a := fidotest.New(fidotest.YubiKeyBioAAGUID)
	id := attest.FormatAAGUID(a.AAGUID)
	handBuilt := &mds.Blob{NextUpdateDate: "2999-01-01", Entries: []mds.Entry{entryFor(a, "")}}
	for name, m := range map[string]attest.MDSRoots{
		"wall clock": {Blob: handBuilt},
		"year 1":     {Blob: handBuilt, Now: at(time.Time{}.AddDate(0, 0, 1))},
	} {
		if rs, err := m.Roots(id); err == nil {
			t.Errorf("%s: an unverified blob served %d root(s)", name, len(rs))
		}
	}
}
