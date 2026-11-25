# forge

<img src="https://raw.githubusercontent.com/go-vcs/brand/main/avatar/go-vcs-forge.png" width="96" alt="go-vcs forge" align="right">

[![Go Reference](https://pkg.go.dev/badge/github.com/go-vcs/forge.svg)](https://pkg.go.dev/github.com/go-vcs/forge)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![CI](https://github.com/go-vcs/forge/actions/workflows/ci.yml/badge.svg)](https://github.com/go-vcs/forge/actions/workflows/ci.yml)
[![Landing](https://img.shields.io/badge/landing-go--vcs.github.io-0079A8.svg)](https://go-vcs.github.io) [![Docs](https://img.shields.io/badge/docs-go--vcs.github.io%2Fdocs-0079A8.svg)](https://go-vcs.github.io/docs/main/)

Light, secure Git forge: hosting, web UI, admin gRPC, Actions runners via GARM.

Status: milestone 2a. The admin gRPC API and its CLI are implemented; hosting,
sign-in and the web UI are still design only. Read [docs/design.md](docs/design.md)
for the goals, the security invariants, how the work is split between
`go-vcs/forge`, `go-vcs/gitproto` and `go-vcs/actions`, and the milestones.

## Administration with a FIDO2 key

Two binaries, both pure Go (`CGO_ENABLED=0`):

- `forge serve` runs the admin API (gRPC over TLS 1.3) and the local
  enrolment socket.
- `forgectl` administers it: `enrol`, `credentials list|revoke`,
  `users create|list|disable`, `identities bind|list|unbind`.

Every change is signed by the administrator's hardware key, one touch and one
user verification per call, bound to the TLS connection and to a single-use
server nonce. Reads open a short session with one touch. The byte layout and the
list of refusals are in [docs/admin-api.md](docs/admin-api.md).

```sh
forge serve --db forge.db --tls-cert cert.pem --enrol-socket /run/forge/enrol.sock \
    --rp-id forge.example --aaguid <model AAGUID> --mds-blob blob.jwt
forgectl enrol --socket /run/forge/enrol.sock --rp-id forge.example --name laptop-key
forgectl --server forge.example:8443 --rp-id forge.example --credential-id <hex> users create alice
```

The TLS key is read from `--tls-key` or the systemd credential `tls.key`; no
secret is accepted on the command line, in the environment or in a URL.
Enrolment is possible only over the Unix socket, and only for a key whose
attestation chains to the FIDO MDS3 blob (verified at start) and whose AAGUID is
on the allowlist; there is no switch to relax either.
