# Admin API

Source of truth: `proto/govcs/forge/admin/v1/admin.proto`. Transport: gRPC over
TLS 1.3 only (TLS 1.2 and cleartext are refused). Messages above 64 KiB are
refused, the serialized parameters inside an envelope above 16 KiB.

## Signed calls

A mutating call carries an `Envelope`: `nonce`, `request` (the serialized
`...Params` message), `credential_id`, `authenticator_data`, `signature`.

1. The client calls `GetNonce` (unauthenticated); the server returns a 56-byte
   stateless nonce: issue time (8 bytes) || 16 random bytes || HMAC-SHA-256 over
   (label, issue time, random, the connection's exporter value), keyed with a
   random key made when the server starts. Nothing is stored at issue time, so
   no number of connections or nonces can fill anything or lock an
   administrator out. It is valid for one minute, on that connection only. The
   key is per process: a restart invalidates outstanding nonces (an in-flight
   call is retried with a new one).
2. The client computes the WebAuthn client data hash

   ```
   clientDataHash = SHA-256( lp("go-vcs admin v1") || lp(method) || lp(nonce)
                             || lp(SHA-256(request)) || lp(exporter) )
   ```

   `lp(x)` is a 4-byte big-endian length followed by `x`, so no two field lists
   encode alike. `request` is hashed exactly as received.

   `method` is the full gRPC method name; `exporter` is the 32-byte RFC 9266
   channel-binding value of the connection (`ExportKeyingMaterial` with label
   `EXPORTER-Channel-Binding`, empty context).
3. The key signs `authenticatorData || clientDataHash` (ES256), with user
   presence and user verification.
4. The server recomputes the hash from what it received and from its own view of
   the connection, then checks, in this order: the nonce was issued on this
   connection (MAC and exporter), is unexpired and unused; the credential is
   active; `rpIdHash` is SHA-256 of the relying party id; UP and UV are set; the
   signature verifies; the signature counter is strictly greater than the
   stored one (when either side is non-zero; WebAuthn L3 7.2 treats "less than
   or equal" as a clone signal, and we refuse, equal included). Only then is
   the nonce marked used.

   **Single use.** A nonce is spent by the first ACCEPTED assertion; it is
   remembered until it would have expired, so that set holds at most the
   accepted calls of one minute (capped at 4096). A call REFUSED for any other
   reason no longer consumes its nonce (it used to): there is nothing stored to
   burn, and burning on refusal would require storing every nonce at issue
   time, which is what let an unauthenticated peer fill the table. A refused
   nonce stays useless to anyone else: it is bound to the connection by the MAC
   and to the request by the signature, and it expires in a minute.

   The listener refuses (closes unserved) connections beyond 256 in total or 16
   per remote host; idle connections are closed after one minute.

Each refusal is `Unauthenticated`, with a reason, and changes nothing. A failure
of the server's own storage during these checks is not a refusal: it is
`Internal`, without detail (the cause is in the server log), since the caller
has not been authenticated yet.

`RevokeAdminCredential` refuses (`FailedPrecondition`) to revoke the last active
credential, which would lock every administrator out. The TLS key file must be
a regular file (no symbolic link) owned by the server's user, mode 0600 or
stricter.

## Sessions

Read calls (`List*`) take a session token from `OpenSession`, itself a signed
call. A token is bound to the connection it was issued on and expires.
A session records the credential that opened it, and every read call checks
that credential is still active: revoking it ends its sessions at once.

## Enrolment

`EnrolService` is registered only on a Unix socket (mode 0600, in a private
directory) and refuses any other peer. `BeginEnrol` returns a challenge (single
use, five minutes, at most eight open). The challenge the key signs is
`SHA-256( lp("go-vcs enrol v1") || lp(challenge) || lp(name) )`. `FinishEnrol`
verifies the `packed` attestation: signature, chain to the roots of the MDS3 blob for that AAGUID,
leaf AAGUID extension and certificate subject, UP, UV, no backup flags, relying
party, and the AAGUID allowlist. Self and `none` attestation are refused.

The blob is verified when the server starts, and its `nextUpdate` is checked
again at every enrolment: once it has passed, enrolment is refused until the
server is restarted with a current blob, because a revocation published since
is not in the one it holds. Signed calls and sessions do not depend on the blob
and keep working.

## SSH keys and policy

| Call | Kind | What it does |
|---|---|---|
| `AddSSHKey(login, public_key)` | signed | Registers one `authorized_keys` line, **without options**, for an enabled user. |
| `RemoveSSHKey(fingerprint)` | signed | Removes the key with that `SHA256:` fingerprint. |
| `ListSSHKeys(login?)` | session | Lists keys (fingerprint, login, type, whether FIDO-backed, comment). |
| `SetPolicy(policy)` | signed | Replaces the forge-wide settings. A message field left out is its zero value. |
| `GetPolicy()` | session | Reads them. |

Accepted key types: `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `ssh-rsa`
with a modulus of at least 3072 bits, and the FIDO-backed `sk-ssh-ed25519@openssh.com`
and `sk-ecdsa-sha2-nistp256@openssh.com`. DSA, certificates, options in front of
the key (`command=`, `from=`...), a line over 8 KiB and a comment over 128 bytes
are `InvalidArgument`. A key belongs to one account: registering it again, for
anyone, is `AlreadyExists`.

`Policy.require_sk_ssh_keys` makes `AddSSHKey` refuse any key that is not an
`sk-` type, **and** makes the SSH transport refuse to authenticate with one
already stored (the keys stay in the database, so relaxing the policy brings
them back). The CLI is `forgectl ssh-keys add|list|remove` (the key is read from
a file or `-`, never from argv) and `forgectl policy show|set`.

## Audit

A signed call leaves two rows in `admin_audit`: an `attempt` row when it is
authorized, before the action runs, then a `success` or `failure` row once the
action has ended. A call whose assertion is refused leaves none. A crash between
the two leaves an attempt with no outcome, which is itself the evidence. If the
outcome row cannot be written it is logged and the caller still gets the
action's own result.
