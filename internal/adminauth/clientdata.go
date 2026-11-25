// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package adminauth authenticates admin API calls with FIDO2 assertions.
//
// An assertion is valid for exactly one request on exactly one TLS connection:
// the challenge the authenticator signs commits to a single-use server nonce,
// the full method name, the bytes of the request as received and a TLS exporter
// value of the connection. See docs/admin-api.md.
package adminauth

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

const (
	// Domain separates the signed calls of this API from every other use of the
	// key, and versions the encoding.
	Domain = "go-vcs admin v1"
	// EnrolDomain does the same for enrolment challenges.
	EnrolDomain = "go-vcs enrol v1"
	// ExporterLabel is the RFC 9266 label for TLS 1.3 channel binding.
	ExporterLabel = "EXPORTER-Channel-Binding"
	// ExporterLen is the number of exporter bytes used (RFC 9266: 32).
	ExporterLen = 32
	// NonceLen is the length of a server nonce.
	NonceLen = 32
)

// field writes b with a 4-byte big-endian length prefix, so that no two
// different field lists encode to the same bytes.
func field(h hash.Hash, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	h.Write(n[:])
	h.Write(b)
}

// ClientDataHash is the 32-byte challenge an authenticator signs for one call:
//
//	SHA-256( lp(Domain) || lp(method) || lp(nonce) || lp(SHA-256(request)) || lp(exporter) )
//
// where lp prefixes a 4-byte big-endian length. request is hashed exactly as it
// was received; nothing is re-encoded.
func ClientDataHash(method string, nonce, request, exporter []byte) [32]byte {
	h := sha256.New()
	field(h, []byte(Domain))
	field(h, []byte(method))
	field(h, nonce)
	rh := sha256.Sum256(request)
	field(h, rh[:])
	field(h, exporter)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// EnrolClientDataHash is the challenge signed (as an attestation) at
// enrolment: SHA-256( lp(EnrolDomain) || lp(challenge) || lp(name) ).
func EnrolClientDataHash(challenge []byte, name string) [32]byte {
	h := sha256.New()
	field(h, []byte(EnrolDomain))
	field(h, challenge)
	field(h, []byte(name))
	var out [32]byte
	h.Sum(out[:0])
	return out
}
