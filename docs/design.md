# go-vcs design

Status: draft, 2026-11-25. Nothing described here is implemented yet.

## Why

go-vcs is a light Git forge (hosting, a GitHub-like web UI, CI) written to
replace a Forgejo install whose security design conflicts with ours. The
conflicts, each read in Forgejo v17.0.2's source:

- an OAuth2 client secret can only be given on a command line
  (`forgejo admin auth add-oauth --secret`, `cmd/admin_auth_oauth.go:36`) or a
  web form, and is stored in clear (`services/auth/source/oauth2/source.go:17`);
- `app.ini` holds every server secret inline, and git hooks run outside the
  service with `INTERNAL_TOKEN`, so per-service secret isolation cannot cover it;
- OAuth2 auto-registration ignores `DISABLE_REGISTRATION`
  (`routers/web/auth/oauth.go:1110`), and an already signed-in user gets an
  external identity linked silently (`routers/web/auth/oauth.go:1100`).

go-vcs is designed from its own stated semantics, not for compatibility with
Gitea/Forgejo. The one deliberate compatibility is with existing runners and
runner managers (see Actions), because that saves building them.

## Invariants

These hold for every component and are tested, not documented only.

1. **No secret in argv, environment or URL.** Secrets come from systemd
   credentials, a file descriptor or a no-echo prompt, and travel only in
   request bodies.
2. **Nobody gets an account by signing in.** Accounts exist only through the
   admin API, against an allowlist; there is no switch to accept every account.
3. **Identities are never linked by e-mail.** An external identity is bound to
   an account by an explicit admin act, keyed on the issuer and subject.
4. **Every parser of untrusted input is fuzzed** (git protocol, pack files,
   protobuf, workflow YAML, webhooks), with its corpus committed, and every
   input has a size, depth and time bound that a test proves is refused.
5. **No component trusts another through a shared static token.** In
   particular there are no git hooks calling back into the server.
6. **Performance is measured against git itself**, single core; slower is a
   defect.

## Repositories

| Repository | Holds |
|---|---|
| `go-vcs/gitproto` | Git wire protocol v2 (upload-pack, receive-pack), pkt-line, pack files and indexes. A library with no forge knowledge, fuzzed and benchmarked against `git`. |
| `go-vcs/actions` | Workflow parsing and planning (matrix, `needs`, expressions) and the server side of the gitea-runner protocol. Reusable without the forge. |
| `go-vcs/forge` | The server: storage, accounts, permissions, SSH and smart HTTP transports, web UI, admin gRPC API and its CLI, webhooks, the GARM-facing API. |

## Identity and sign-in

- Web sign-in goes only through the go-authn bridge (OIDC,
  `https://login.mesocentre.plateau-de-saclay.net`), with a client restricted to
  bridge local accounts (passkeys). The forge does not implement passwords.
- A sign-in whose `(iss, sub)` is not bound to an existing account is refused.
  It never creates an account and never links to a signed-in session.
- SSH push and pull use per-user SSH keys, preferably `sk-` keys
  (FIDO-backed), with a policy setting to require them.

## Administration: gRPC API and CLI

Everything administrative (users, identity bindings, repositories,
organisations, settings, OAuth clients, runners) goes through one gRPC API.
The web UI has no admin pages that the API lacks.

Authentication is a FIDO2 credential on a hardware key with user verification
(the target is a YubiKey Bio, AAGUID `9dd8d593-2213-438a-97f8-d6b813d51c27`,
which has no PIV applet, so there is no X.509 client-certificate path):

- **Enrolment:** the attestation is verified against FIDO MDS3 with
  go-authn/fido; only allowlisted AAGUIDs are accepted, with no opt-out.
- **Each mutating call** carries a fresh assertion with UV set, over a challenge
  that combines a server nonce, the hash of the exact request message, and a
  TLS exporter value of the connection (RFC 9266-style channel binding). An
  assertion is therefore valid for one request on one connection: it cannot be
  replayed, reordered or relayed.
- Read-only calls may use a short session established by one assertion.
- Secrets given to the API (an OAuth client secret, a webhook secret) are read
  by the CLI from a no-echo prompt or an inherited file descriptor, are sent in
  the request body only, and are stored encrypted at rest.

## Git transport

- SSH (in-process, `x/crypto/ssh`) and smart HTTP, protocol v2 only for fetch.
- Push policy (branch protection, permission, size limits) is decided in-process
  by parsing the receive-pack command list and pack with `gitproto` before any
  ref moves. There are no server-side hooks and no internal callback token.
- Whether objects are stored by `gitproto` itself or by invoking `git` behind a
  narrow interface is decided by measurement in `gitproto`, not up front.

## Actions

### Runner protocol

The forge serves the gitea-runner protocol so that the existing runner
(gitea-runner, built on nektos/act) runs our jobs unchanged: connect-rpc under
`<forge>/api/actions`, `RunnerService` with `Register`, `Declare`,
`FetchTask`, `UpdateTask` and `UpdateLog`, plus `PingService`
(gitea `actions-proto-def`, `proto/runner/v1/services.proto`). After
registration the runner authenticates each call with its UUID and token headers.

What the forge does differently from Gitea:

- a registration token is **single-use**, short-lived and bound to one runner
  name;
- a job's token (task context `token`) is scoped to its repository and job and
  revoked when the job ends;
- secrets are never sent to runs triggered from forks;
- log rows and outputs are bounded in size and count.

### Runner orchestration: GARM

Runners are created by GARM, which already serves our GitHub organisations.

- **Phase 1:** the forge implements what GARM's `gitea` forge type calls:
  org/repo webhooks, runner list and removal, registration tokens, and
  `workflow_job` webhooks signed with `X-Hub-Signature-256` (GARM v0.2.1
  `util/github/client.go`, `util/github/gitea.go`). GARM's gitea userdata
  template is replaced by a hardened one: the runner binary is pinned and its
  checksum verified (the stock template downloads without verification,
  `internal/templates/userdata/gitea_linux_userdata.tmpl:122`, and may fall back
  to an unpinned nightly, `workers/cache/gitea_tools.go:198`), and the
  registration token is not passed on the command line.
- **Phase 2:** a `govcs` forge type contributed to GARM, to get what the
  `gitea` type lacks: just-in-time runner configuration
  (`runner/pool/pool.go:953`) and a pull-based job queue instead of inbound
  webhooks (`runner/pool/util.go:274`).

### Artifacts and cache

The cache is served by the runner itself. Artifacts (`ACTIONS_RUNTIME_URL` =
`<forge>/api/actions_pipeline/`, `ACTIONS_RESULTS_URL` = `<forge>`) are a later
milestone.

## Milestones

1. `gitproto`: pkt-line, protocol v2 capability advertisement and `ls-refs`,
   `fetch` serving from an existing repository; fuzzers; benchmark vs
   `git upload-pack`.
2. `forge`: storage layout, accounts, admin gRPC API with FIDO2 assertions and
   its CLI; SSH and HTTP clone.
3. `forge`: OIDC sign-in through the bridge, read-only web UI (tree, blob,
   commits, diff).
4. `gitproto` + `forge`: receive-pack with in-process push policy.
5. `actions`: workflow planning; runner protocol server; GARM `gitea` type.
6. Pull requests and reviews in the web UI.
7. GARM `govcs` forge type; artifacts.

## Sources read for this document

- Forgejo v17.0.2 source, as cited above (read by the go-authn session).
- GARM v0.2.1 source (`github.com/cloudbase/garm`), files cited above.
- `gitea.com/gitea/actions-proto-def`, `proto/runner/v1/*.proto`.
- `gitea.com/gitea/runner` v6.0.1, `internal/pkg/client/http.go`,
  `internal/app/run/runner.go`, `internal/app/cmd/cmd.go`.

To be read before the matching milestone: `gitprotocol-v2`,
`gitprotocol-pack`, `gitformat-pack` (Git documentation); WebAuthn Level 3 and
CTAP 2.2; RFC 9266 and RFC 5705 (TLS exporters); the Connect protocol
specification.
