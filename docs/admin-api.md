# Admin API

Source of truth: `proto/govcs/forge/admin/v1/admin.proto`. Transport: gRPC over
TLS 1.3 only (TLS 1.2 and cleartext are refused). Messages above 64 KiB are
refused, the serialized parameters inside an envelope above 16 KiB.

## Signed calls

A mutating call carries an `Envelope`: `nonce`, `request` (the serialized
`...Params` message), `credential_id`, `authenticator_data`, `signature`.

1. The client calls `GetNonce`; the server returns 32 random bytes, valid for one
   minute, remembered against that TLS connection.
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
   connection, is unexpired and unused (it is consumed even if the call is then
   refused); the credential is active; `rpIdHash` is SHA-256 of the relying
   party id; UP and UV are set; the signature verifies; the signature counter
   did not go backwards (when either side is non-zero).

Each refusal is `Unauthenticated`, with a reason, and changes nothing.

## Sessions

Read calls (`List*`) take a session token from `OpenSession`, itself a signed
call. A token is bound to the connection it was issued on and expires.
Known limit: revoking a credential does not end sessions it already opened; they
expire by themselves.

## Enrolment

`EnrolService` is registered only on a Unix socket (mode 0600, in a private
directory) and refuses any other peer. `BeginEnrol` returns a challenge (single
use, five minutes, at most eight open). The challenge the key signs is
`SHA-256( lp("go-vcs enrol v1") || lp(challenge) || lp(name) )`. `FinishEnrol`
verifies the `packed` attestation: signature, chain to the roots of the MDS3 blob for that AAGUID,
leaf AAGUID extension and certificate subject, UP, UV, no backup flags, relying
party, and the AAGUID allowlist. Self and `none` attestation are refused.

## Known limit

The audit row of a signed call is written when the call is authorized, before
the action runs; a call refused later still leaves its row. The row is evidence
of an authorized attempt, not of success.
