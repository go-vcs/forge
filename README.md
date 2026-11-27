# forge

<img src="https://raw.githubusercontent.com/go-vcs/brand/main/avatar/go-vcs-forge.png" width="96" alt="go-vcs forge" align="right">

[![Go Reference](https://pkg.go.dev/badge/github.com/go-vcs/forge.svg)](https://pkg.go.dev/github.com/go-vcs/forge)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![CI](https://github.com/go-vcs/forge/actions/workflows/ci.yml/badge.svg)](https://github.com/go-vcs/forge/actions/workflows/ci.yml)
[![Landing](https://img.shields.io/badge/landing-go--vcs.github.io-0079A8.svg)](https://go-vcs.github.io) [![Docs](https://img.shields.io/badge/docs-go--vcs.github.io%2Fdocs-0079A8.svg)](https://go-vcs.github.io/docs/main/)

Light, secure Git forge: hosting, web UI, admin gRPC, Actions runners via GARM.

Status: milestone 3. The admin gRPC API and its CLI, read-only `git clone`
and `git fetch` over SSH and smart HTTP (protocol v2), OIDC sign-in through the
go-authn bridge, and a read-only web UI are implemented. With `--web-listen`
and `--repos-root` the web listener serves, for each repository the viewer may
read (owner, or exported with `git-daemon-export-ok`; anything else is a 404),
the tree, blob, raw file, commit log and commit diff pages; every git command
runs with a deadline, a bounded output and a bounded concurrency. Push and
pull requests are still design only. Read [docs/design.md](docs/design.md)
for the goals, the security invariants, how the work is split between
`go-vcs/forge`, `go-vcs/gitproto` and `go-vcs/actions`, and the milestones.

[docs/agent-vcs.md](docs/agent-vcs.md) designs (not yet implemented) an
agent-oriented layer on top of git: writes and reads without a clone, change
ids stable across rebase, merges only on a CI verdict for the exact merged
commit, path-scoped leases, one local daemon per machine, and atomic changes
across repositories. Git stays the storage and interchange format. The first
milestone is the local daemon against GitHub, before the forge hosts anything.

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

## Clone and fetch over SSH

```sh
ssh-keygen -t ed25519 -N '' -f ssh_host_key        # the host key is never generated
forge serve ... --ssh-listen :2222 --ssh-host-key ssh_host_key --repos-root /srv/repos
git clone ssh://git@forge.example:2222/alice/project.git
```

Repositories are bare, at `<repos-root>/<owner>/<name>.git`. A user
authenticates with a public key registered through the admin API; only
`git-upload-pack` runs (no shell, pty, forwarding or agent), and only with
protocol v2. Push is refused with a message naming milestone 4. A reader must
own the repository, or the repository must contain a `git-daemon-export-ok`
file; a missing and a forbidden repository answer alike. There is no ACL yet.
The host key is read from `--ssh-host-key` or the systemd credential
`ssh_host_key` (ed25519, no passphrase, owner-only permissions). Bounds:
`--git-timeout` per request, `--git-sessions` in total and
`--git-sessions-per-account`, plus fixed caps on authentication tries,
connections per host, request bytes and pkt-line count.

## Clone and fetch over HTTPS

```sh
forge serve ... --http-listen :8444 --repos-root /srv/repos
git clone https://forge.example:8444/alice/project.git
```

Anonymous and read-only: only repositories holding a `git-daemon-export-ok`
file are served, over TLS 1.3 with the admin certificate. A request needs
`Git-Protocol: version=2` (git 2.26 or later does that by default); protocol
versions 0 and 1, the dumb protocol and push (`git-receive-pack`, milestone 4)
are refused with a message that says so. A private and a missing repository
both answer 404. Bounds: `--git-timeout` per request, `--git-sessions` in
total and `--git-sessions-per-account` (per client address here), plus fixed
caps on header size, body size (as sent and once decompressed), request
bytes and pkt-line count. No credential is accepted in a URL.
