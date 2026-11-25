# Agent-oriented version control on top of git

Status: design, 2026-11-25. Nothing here is implemented. It extends
[design.md](design.md) and inherits all of its invariants; where this document
and design.md disagree, design.md wins until this one is amended.

## Why

The forge's first users are not only people: on one build machine about 25
coding-agent sessions run at once, each against many repositories, through
plain `git` and the GitHub API. The frictions below were measured there, each
on more than one occasion:

| # | Friction | What it cost |
|---|---|---|
| F1 | Per-agent worktrees deleted mid-work by cleanup; duplicate clones of the same repository; a repository path guessed instead of resolved. | Lost uncommitted work, gigabytes of duplicate objects, edits made in the wrong clone. |
| F2 | A full commit id reconstructed from the 7-character prefix a tool printed; `git commit --amend` after a push, leaving the CI verdict on the old commit. | A well-formed "this commit has no runs" answer taken as a measurement; a green verdict on a tree that was not the one published. |
| F3 | Concurrent merges into one branch; "update branch" done by hand; a merge retried after a 5xx answered "merge already in progress". | Serialised human-style choreography for every merge, ambiguous retries. |
| F4 | Coordination by a local lease tool whose leases are whole-repository, exclusive about the *name* only, and lapse silently. | Two sessions editing the same files; a waiter dropped without notice. |
| F5 | 13 concurrent CI pollers sharing one REST budget with Renovate. | Rate-limit starvation of unrelated automation. |
| F6 | `go.mod` bumps and lock-step package sets spread over ~300 organisations, merged one repository at a time. | Hours in which `main` of one repository depends on an unmerged change of another. |
| F7 | Errors as prose, writes that cannot be retried safely, a verdict printed without the revision it judged, agents acting with a human's token. | Wrong conclusions drawn from well-formed output; no attribution. |

Anthropic's Scion ([Redesigning source control at Anthropic][scion], sections
"Principles for agent-scale source control" and "How Scion works") answers
similar pressure inside one monorepo by replacing git: server-side commit,
merge and rebase so that there is "nothing to push"; changesets in a
write-ahead log; refs moved by compare-and-swap on one Spanner row; per-directory
access control; a three-tier cache (per-node daemon, regional cache,
authoritative server). We take the *shape* of several of these ideas and keep
git as the storage and interchange format, and we reject one of its decisions
outright (see [Not taken](#not-taken)).

## Constraints

1. **git stays the storage and the interchange format.** Every object is a git
   object in a git repository; every durable name of a commit is a git ref.
   `git clone`, `git fetch`, and mirroring to GitHub keep working unchanged and
   see ordinary repositories.
2. **design.md's invariants hold**: no secret in argv, environment or URL; no
   account by sign-in; every untrusted parser fuzzed with a committed corpus;
   every input bounded and the refusal tested; no hooks and no shared internal
   token; performance measured against git, single core, slower is a defect.
3. **A branch moves only to a commit that CI judged green, that exact commit.**
   No "merge, then let an agent fix it". A verdict always names the full object
   id it judged; a merge names the revision it intends to merge.
4. **Every write is idempotent under retry** with the same request id.

## Overview

```
 agent sessions (same uid)                      forge server
 ┌────────┐ ┌────────┐                          ┌────────────────────────────┐
 │session1│ │session2│ … gRPC on a Unix socket  │ agent API (gRPC, TLS 1.3)  │
 └───┬────┘ └───┬────┘                          │  RepoService  ChangeService│
     └────┬─────┘                               │  LeaseService EventService │
   ┌──────▼──────────────┐  one TLS connection  │  ChangeSetService …        │
   │ forge-agentd        │◄────────────────────►│ per-repo writer ──► git    │
   │ object cache (CAS)  │  one event stream    │ SQLite: leases, verdicts,  │
   │ event fan-out       │                      │  intents, idempotency      │
   └─────────────────────┘                      └──────────┬─────────────────┘
                                                           │ push heads/tags
                                                           ▼
                                                    GitHub mirror (unchanged)
```

## Data model

All object ids on this API are **full** hexadecimal ids (40 digits for SHA-1;
64 for SHA-256 when the repository uses it). An abbreviated id is refused
everywhere with `InvalidArgument`; there is no endpoint that expands a prefix.
This removes F2's first half by construction: a client has nothing to
reconstruct, because nothing the API prints is shorter than what it accepts.

### Change

A unit of work against one target branch of one repository, stable across
every rewrite of its content.

| Field | Meaning |
|---|---|
| `change_id` | `I` + 40 lowercase hex digits, 160 random bits drawn by the server. Gerrit's spelling ([Change-Id][gerrit]), so existing tooling reads it. |
| `repo`, `target_ref` | Full ref name, e.g. `refs/heads/main`. Immutable for the life of the change. |
| `owner` | The principal that created it (an agent session or a user). |
| `state` | `OPEN`, `MERGED`, `ABANDONED`. |
| `latest_revision` | Highest revision number. |
| `change_set_id` | Optional, see [Multi-repository changes](#multi-repository-change-sets). |

Like a jj change ("a commit as it evolves over time"; rewriting gives "a new
commit ID, but the change ID generally remains the same", [jj glossary][jj]),
the change is the thing an agent names; the commit is what it is at one moment.

### Revision

An immutable pair `(change_id, n)` → one commit id, `n` = 1, 2, 3, … ; a
change is one commit at a time (a series of dependent commits is a series of
changes, each based on the previous one's latest revision). A revision is
never rewritten: amending, rebasing or editing a change creates revision
`n + 1`. Every revision's commit carries the trailer `Change-Id: <change_id>`
in its message, which is how the identity survives a rebase made outside the
forge with plain git.

### Verdict

The CI result for one commit, as recorded by the forge's own Actions subsystem
(milestone 5 of design.md):

| Field | Meaning |
|---|---|
| `repo`, `commit` | Full commit id. The key. A verdict cannot exist without it. |
| `check` | Workflow and job name. |
| `conclusion` | `SUCCESS`, `FAILURE`, `CANCELLED`, `ERROR`. |
| `jobs` | Number of jobs that ran. A run with zero jobs never started and is `ERROR`, never `SUCCESS`. |
| `run_id`, `finished_after` | The run, and a server-side monotonic duration since it was queued. |

A **gate verdict** for `(repo, commit, target_ref)` is `GREEN` iff every check
required by the target ref's policy has a `SUCCESS` verdict on *that commit*
with at least one job; `RED` if any required check has another conclusion;
`PENDING` otherwise. A missing check is `PENDING`, never `GREEN`.

Verdicts are keyed by commit, not by tree. Two commits with the same tree
usually deserve the same verdict, but CI can read commit metadata (version
stamping from `git describe`, for instance); reusing verdicts across commits
with equal trees is an optimisation left as an open question.

Agents cannot write verdicts. Only the Actions subsystem does, from the run it
scheduled on that exact commit.

### Lease

A claim by one principal on a set of paths of one ref, for a bounded time.

| Field | Meaning |
|---|---|
| `lease_id`, `epoch` | `epoch` is a per-repository counter, strictly increasing at each grant; it is the fencing token. |
| `repo`, `ref` | The ref whose content is claimed (usually the target branch). |
| `paths` | 1 to 64 path prefixes (`internal/store/`, `go.mod`). `""` means the whole tree. |
| `holder` | Principal. |
| `note` | Free text, at most 256 bytes, shown to others. |
| `ttl_remaining` | Duration, computed by the server's monotonic clock. The API never exchanges absolute expiry times: a client whose clock drifted (a resumed virtual machine) cannot misjudge it. |

Two leases **overlap** iff some prefix of one is a path-component prefix of a
prefix of the other (`a/b/` overlaps `a/` and `a/b/c.go`; it does not overlap
`a/bc/`). Overlapping leases on the same ref are never granted to two holders.

### Change set

A group of changes in up to 64 repositories that merge all together or not at
all. See [Multi-repository change sets](#multi-repository-change-sets).

## How it maps onto git

The choice is: **names of commits are refs; everything that judges or
coordinates is forge state in SQLite**, rebuilt or exported to git where that is
sound.

| Concept | Representation | Why |
|---|---|---|
| Revision | `refs/changes/<last 2 hex of id>/<change_id>/<n>` → commit, created with `create` (must not exist) and never updated. | A ref keeps the objects alive against `git gc`, can be fetched by any git client (`git fetch origin refs/changes/…`), and makes revision → commit reconstructible from the repository alone. Sharding by two hex digits bounds the fan-out of a "files" ref directory. |
| Change identity | Trailer `Change-Id: I<40 hex>` in the last paragraph of every revision's message; `Change-Set: S<40 hex>` when the change belongs to a set. | Survives rebase and cherry-pick done with plain git, as Gerrit relies on ([Change-Id][gerrit]). A trailer is part of the commit, so it is covered by the commit id; no side table can disagree with it. |
| Merge candidate | `refs/forge/candidates/<target-hash>/<seq>` → the commit CI runs on before it may become the target. Deleted after merge or failure. | CI needs a fetchable name for a commit that is not yet on any branch. |
| Change state, leases, verdicts, idempotency records, intents | SQLite (the store of `internal/store`), never git. | They need transactional compare-and-set and frequent writes. Git notes were considered for verdicts: a notes ref is one ref with a commit chain, so every verdict would be a compare-and-swap on the same ref, the exact contention the design removes. Verdicts are *exported* read-only as `refs/notes/forge/verdicts` by one batched writer, for offline audit; the gate never reads the export. |
| Mirroring | Only `refs/heads/*` and `refs/tags/*` are pushed to GitHub. | A mirror shows ordinary history; `refs/changes` and `refs/forge` are forge-private names, still fetchable from the forge by permitted readers. |

A plain `git clone` from the forge fetches `refs/heads/*` and tags (the default
refspec); `refs/changes/*` are advertised through `ls-refs` only to a reader of
the repository, and fetched only on request.

**Rebuild.** Revisions are rebuilt from refs: at start, any
`refs/changes/**/<n>` absent from SQLite is inserted (the ref is the truth for
revision → commit). Leases and verdicts are not rebuilt: a lost lease is
re-requested, a lost verdict is re-run, both safely.

**Pushing with plain git** (needs receive-pack, design.md milestone 4):
`git push forge HEAD:refs/changes/new/<branch>` creates a change, or adds a
revision to the change named by the commit's `Change-Id` trailer. A commit with
no trailer is refused with the exact line to add (the server cannot add it: it
would change the commit id the client holds). Pushes to `refs/changes/<…>/<n>`
directly are refused.

## API

Package `govcs.forge.agent.v1`, gRPC over TLS 1.3 only, same listener rules as
the admin API ([admin-api.md](admin-api.md)). Messages are bounded (below).

### Common fields

Every mutating request has:

```proto
message WriteHeader {
  bytes request_id = 1;      // 16 bytes, client-chosen, random
  uint64 lease_epoch = 2;    // 0 = no lease; else the fencing token held
}
```

Every response and every error carries `server_request_id` (for logs) and,
when it concerns a commit, the full commit id and `(change_id, revision)`.

### Idempotency

The server keeps `(principal, method, request_id) → (SHA-256 of the request,
response or error)` for 24 hours, at most 100 000 rows per principal.

- Same id, same request hash: the stored response is returned, nothing runs
  again. A retry after a timeout or a 5xx is always safe.
- Same id, different hash: `InvalidArgument`, reason `REQUEST_ID_REUSED`.
- A request whose first execution is still running returns the same
  operation handle (long operations) or waits for it (short ones).

Writes that create git objects use a **write-ahead intent**: the request is
recorded with everything that determines its result (planned change id,
author, committer time, parents) *before* any object or ref is written, so that
a crash between the ref update and the SQLite commit is completed on retry or
at restart by recomputing the same commit id and finding the ref already there.
Commit ids are deterministic given the intent.

### RepoService (reads, no clone)

| RPC | Semantics |
|---|---|
| `ListRefs(repo, prefixes)` | Full names and full ids, paged. |
| `ResolveRevision(repo, change_id, revision)` | → commit id. No name resolution from abbreviated ids. |
| `ReadTree(repo, commit, path, recursive, page)` | Entries (mode, type, id, name), paged; recursion bounded. |
| `ReadBlob(repo, commit, path)` / `ReadObject(repo, id)` | Server-streamed content in 1 MiB chunks, with its size up front. |
| `Diff(repo, from, to, paths, rename_detection)` | Structured per-file hunks, paged; rename detection bounded (below). |
| `Log(repo, commit, path, page)` | First-parent or full, paged. |

### ChangeService (writes)

```proto
message FileEdit {
  string path = 1;
  oneof op {
    bytes content = 2;        // inline, up to 1 MiB
    string blob_id = 3;       // a blob uploaded with UploadBlob
    bool delete = 4;
    string rename_from = 5;   // with content or blob_id, or alone
  }
  Mode mode = 6;              // REGULAR, EXECUTABLE, SYMLINK; no gitlink
}

message CreateChangeRequest {
  WriteHeader header = 1;
  string repo = 2;
  string target_ref = 3;
  string base_commit = 4;     // full id; the parent of revision 1
  repeated FileEdit edits = 5;
  string message = 6;         // the server appends the Change-Id trailer
}

message UpdateChangeRequest {
  WriteHeader header = 1;
  string change_id = 2;
  uint32 expected_latest_revision = 3; // optimistic: refused if not latest
  optional string new_base_commit = 4; // rebase onto it (server-side)
  repeated FileEdit edits = 5;         // applied on top of latest (or rebased)
  optional string message = 6;
}
```

| RPC | Semantics |
|---|---|
| `UploadBlob(stream)` | Content-addressed; returns the blob id; idempotent by content. |
| `CreateChange` | Builds the tree from `base_commit`'s tree and the edits, writes commit and revision 1 ref. The server is the committer; the author is the principal. Returns change id, revision, full commit id, and the list of open changes and leases that overlap the touched paths (advisory, see Concurrency). |
| `UpdateChange` | Creates revision `n + 1`; refused with `STALE_REVISION` if `expected_latest_revision` is not the latest, which closes the lost-update between two writers of one change. A rebase is `git merge-tree --write-tree` semantics (below); a conflicting rebase is refused with the conflict, never committed with markers. |
| `AbandonChange` | State `ABANDONED`; revision refs kept for the retention period (default 30 days), then deleted. |
| `Merge` | Long operation, see Merge. |
| `GetChange`, `ListChanges` | Includes each revision's commit and gate verdict. |
| `UpdateRef(repo, ref, new, expected_old)` | Compare-and-swap on a ref that the target policy marks *unprotected* (scratch branches). Protected refs move only through `Merge`. |

Worktrees stay optional: `forge-agentd` can materialise a revision into a
directory the caller names (below), and plain `git` still works.

### Merge

```proto
message MergeRequest {
  WriteHeader header = 1;
  string change_id = 2;
  uint32 revision = 3;        // required: what the caller means to merge
  string revision_commit = 4; // required, full id: must match revision
  Strategy strategy = 5;      // FAST_FORWARD_ONLY, REBASE, MERGE_COMMIT
}
```

`Merge` returns an `Operation` (`GetOperation`, `WatchOperation`). A second
`Merge` for the same `(change_id, revision)` returns the existing operation,
whatever its request id: "merge already in progress" is a handle, not an
error. A `Merge` naming a revision other than the latest is refused
(`STALE_REVISION`): this closes F2's second half, since an agent that amended
must name the new revision and that revision must itself pass CI.

The operation, run by the repository's writer (see Concurrency):

1. Let `T` be the target's current commit. If the revision's parent is `T`, the
   candidate `C` is the revision commit itself (its verdict may already exist).
   Otherwise `C` is built server-side: `REBASE` re-creates the revision's commit on
   `T` from the merge-tree result (same message and trailers, parent `T`); `MERGE_COMMIT` runs the equivalent of
   `git merge-tree --write-tree T <revision>` and commits the tree with parents
   `T, revision`. merge-tree "does not read from or write to either the
   working tree or index" ([git-merge-tree(1)][mergetree], DESCRIPTION).
   Conflicts are decided by its exit status, never by an empty conflict list
   (its "MISTAKES TO AVOID" section), and reported from `-z` output.
2. A conflict ends the operation with `CONFLICT` (paths and git's stable
   conflict types). Nothing is committed with conflict markers; the agent
   resolves with `UpdateChange` and merges the new revision.
3. `C` gets a candidate ref; the Actions subsystem runs the target's required
   checks on `C`.
4. When the gate verdict for `C` is `GREEN`, the writer moves the target from
   `T` to `C` with a compare-and-swap. If the target is no longer `T`, go back
   to 1 with the new `T` (at most 5 rebuilds, then `TARGET_CHURN`). If `RED`,
   the operation ends `VERDICT_RED` naming `C` and the failing checks.

**Queue.** Merges into one target are ordered by arrival. Candidates are
built speculatively on top of the candidates ahead of them, so their CI runs in
parallel; when a candidate ahead fails, the ones built on it are rebuilt. The
order and each candidate's base are visible in `ListOperations`. This is the
price of constraint 3: CI throughput, not git, bounds the merge rate.

### LeaseService

| RPC | Semantics |
|---|---|
| `Acquire(repo, ref, paths, ttl, note, wait)` | Grants a lease with a new `epoch`, or refuses `LEASE_HELD` naming each overlapping holder, its note and remaining TTL. `wait = true` queues server-side; the queue position survives the client's silence until its own deadline. |
| `Renew(lease_id, ttl)` | Extends; refused once lapsed (a lapsed lease is never revived: acquire again, getting a new epoch). |
| `Release(lease_id)` | Idempotent. |
| `List(repo, ref, paths)` | Visible to every principal that can read the repository. |

TTL: 1 to 60 minutes. A lease that lapses emits `LEASE_EXPIRED` to its holder
and to every watcher of the repository: lapse is an event, never silence.

**Enforcement.** A write (`CreateChange`, `UpdateChange`, `Merge`) touching a
path covered by another holder's live lease is refused `LEASE_HELD`. A write
that carries `lease_epoch` is refused `LEASE_LAPSED` if that lease is no longer
live, even when nobody else holds the paths: the holder learns it lost the
lease before, not after, the write. Writes without a lease are allowed on paths
nobody leased; leases are opt-in coordination, not a permission.

### EventService

`Watch(repos, kinds, cursor)` is a server-streaming call. Events: ref moved,
change created/updated/merged/abandoned, verdict recorded, gate verdict
changed, lease granted/released/expired, operation state changed. Each event
has a server-wide strictly increasing `cursor`; a client resumes from the last
cursor it saw. The server retains 24 hours or 1 000 000 events; an older cursor
is refused `CURSOR_EXPIRED` and the client re-reads state. Events are never
silently dropped: a subscriber that cannot keep up (more than 10 000 events
queued) is disconnected with `SUBSCRIBER_TOO_SLOW` and resumes from its cursor.

`WaitVerdict(repo, commit, target_ref)` blocks until the gate verdict is not
`PENDING` or the deadline passes, and answers with the commit id and each check.

### Error model

Errors are a gRPC status plus one detail message:

```proto
message Error {
  Reason reason = 1;              // stable enum, never prose
  bool retryable = 2;             // same request, same request_id
  google.protobuf.Duration retry_after = 3;
  string ref = 4; string current_commit = 5;   // full id
  repeated string paths = 6;
  repeated LeaseInfo holders = 7;
  string change_id = 8; uint32 revision = 9;
  repeated CheckResult checks = 10;
}
```

| gRPC code | Reasons |
|---|---|
| `InvalidArgument` | `MALFORMED`, `ABBREVIATED_ID`, `BAD_PATH`, `REQUEST_ID_REUSED` |
| `ResourceExhausted` | `BOUND_EXCEEDED` (which bound, which value), `RATE_LIMITED` |
| `Aborted` (re-read, then retry with a new request id) | `REF_MOVED`, `STALE_REVISION`, `STALE_BASE` |
| `FailedPrecondition` | `LEASE_HELD`, `LEASE_LAPSED`, `CONFLICT`, `VERDICT_RED`, `TARGET_CHURN`, `PROTECTED_REF`, `CURSOR_EXPIRED` |
| `PermissionDenied` / `Unauthenticated` | `NOT_PERMITTED` (which path or ref), `TOKEN_EXPIRED`, `SCOPE` |
| `Unavailable` | retryable with the same request id |
| `Internal` | no detail (the cause is in the server log, as in the admin API) |

## Concurrency and consistency

- **One writer per repository.** Every ref update of a repository, whether from
  this API, receive-pack, or a merge, goes through one in-process writer for
  that repository. It applies updates with `git update-ref --stdin` with
  `start`, `update <ref> <new> <old>`, `prepare`, `commit`: "If all <ref>s can
  be locked with matching <old-oid>s simultaneously, all modifications are
  performed. Otherwise, no modifications are performed" ([git-update-ref(1)][updateref]).
  The old-id check is a second guard against anything outside the forge.
- **Gate check and ref move are one step.** Inside the writer: read the gate
  verdict of `C` from SQLite, verify the target is `T`, update. No other writer
  can move the target in between, so "green on exactly the merged commit" holds
  at the instant of the update.
- **Ref writes are linearizable per repository**; reads are snapshot reads of
  one commit (an object id names immutable content), so `ReadTree` at a commit
  is consistent regardless of concurrent writes. Reads of a *ref* are
  read-committed: git warns that "a concurrent reader may still see a subset of
  the modifications" of a multi-ref transaction ([git-update-ref(1)][updateref]).
- **Leases** live in SQLite on the single server, checked inside the same
  writer as the write they guard, against the server's monotonic clock. The
  fencing epoch makes a holder that was paused past its TTL harmless.
- **Optimistic conflict detection.** Leases are optional; without them, the
  server still reports at each write the open changes of other principals whose
  latest revisions touch the same paths, and refuses only at merge, where the
  three-way merge is the authority.
- **Crash.** SQLite and refs are two stores; the intent record orders them
  (intent → objects → ref → SQLite state) and restart completes or discards
  each pending intent before the listener opens.

## Multi-repository change sets

A change set holds one change per repository (at most 64 repositories), all on
the same forge server. `CreateChangeSet`, `AddChange`, `MergeChangeSet`.

**Joint CI.** Each repository's candidate `C_i` is built as above. The CI job of
`C_i` receives, in its job context, the list of sibling candidates
`(repo_j, C_j)` and a read token for their candidate refs, so a workflow can
build against them (for Go: a `go.work` over the sibling checkouts). The set's
gate is `GREEN` iff every `C_i`'s gate is `GREEN`, each run with the same
sibling list. If any sibling candidate is rebuilt, every candidate's CI reruns.

**All-or-nothing.** The repositories are independent git repositories, so
there is no single ref to compare-and-swap. The forge runs a two-phase commit
in which it is the coordinator and SQLite the decision log:

1. *Prepare.* For each repository, its writer opens `git update-ref --stdin`,
   queues `update <target> <C_i> <T_i>` and sends `prepare`, which "will create
   lock files for all queued reference updates. If one reference could not be
   locked, the transaction will be aborted" ([git-update-ref(1)][updateref]).
   The writers re-check each gate under the lock. Any failure: `abort` all.
2. *Decide.* One SQLite transaction records `COMMIT` for the set with every
   `(repo, target, T_i, C_i)`. This row is the commit point.
3. *Commit.* Each writer sends `commit`. Then the set is `MERGED`.

What a crash leaves:

- **Before the decision row**: the `update-ref` processes see their stdin close
  and their transactions abort ("a transaction will automatically abort if the
  session ends without an explicit commit"). If a git process was killed
  instead, a `*.lock` file may remain; at restart, before any writer starts and
  therefore while no git process of the forge can be running, recovery removes
  the lock files of the refs listed in un-decided sets and marks them aborted.
  Nothing moved.
- **After the decision row**: restart rolls forward, applying each
  `update <target> <C_i> <T_i>` again; a ref already at `C_i` is done. If a ref
  is at neither (someone moved it outside the forge while it was down), the set
  becomes `PARTIAL`, merges into those repositories are halted, and the state is
  reported to the administrators. This is the honest limit: the forge
  guarantees an all-or-nothing *decision* and its completion, not protection
  against writers that bypass it.
- **Visibility is not atomic.** Between the first and the last `commit`, a
  `git fetch` can see repository A updated and B not; the window is
  milliseconds on one host, but it exists. GitHub mirrors are pushed after the
  set is `MERGED`, one repository after another, so a consumer of the mirrors
  (or of a module proxy that reads them) can observe a partial set for the
  duration of the pushes. Repositories hosted elsewhere cannot be in a set.

## Identity and security

### Principals

| Principal | How it exists | What it may do |
|---|---|---|
| User | Admin API only (design.md); signs in through the bridge. | Per repository role; approves, administers through FIDO2-signed calls. |
| Host | Enrolled by a FIDO2-signed admin call `EnrolHost(name, public key, owner)`. | Open agent sessions for its owner. Nothing else. |
| Agent session | `OpenAgentSession(host-signed, label, repos, ttl)`: owned by the host's owner, at most 12 hours, at most 64 live per host. | Read; create and update changes; acquire leases; request merges of protected refs through the gate; `UpdateRef` on unprotected refs. Never: admin calls, ACL or policy changes, deleting refs, force updates, writing verdicts, approving its own change where a policy requires a human. |
| CI job | Job token (design.md, Actions), scoped to the repository and the job. | Read; write verdicts only through the Actions subsystem. |

An agent session is never created by signing in, and is always attributed to
the user who owns the host: the server is the committer of every commit it
builds, the author is `agent-session <label> (<host>) for <user>`. Agents
never hold a user's credential.

**Host key.** The host signs `OpenAgentSession` with the same envelope shape as
admin calls (nonce, request hash, TLS exporter; [admin-api.md](admin-api.md)),
under the label `go-vcs host v1`. The key is read from a systemd credential or
a file of mode 0600 owned by the daemon's user, never from argv or environment.

**Session tokens** are bound to the daemon's TLS connection (exporter value),
like admin session tokens, and travel in request bodies. They never leave
`forge-agentd`: agent processes talk to the daemon and never see a token, so
a token printed by an agent, or found in its transcript, does not exist.

### Path permissions

A repository's policy may add path rules: `(ref, path prefix) → roles that may
write`. Every write's touched paths are checked; a merge is checked on the
paths the candidate changes relative to `T`. Per-path permissions govern
**writes only**. Read confidentiality stays per repository, because `git clone`
serves whole trees: unlike Scion, which controls the client's fetch, we cannot
hide a directory from a reader who can clone.

### Bounds (each refused with a test)

| Input | Bound |
|---|---|
| gRPC message | 16 MiB; inline content 1 MiB per edit; `UploadBlob` 100 MiB per blob |
| Edits per call | 10 000; total inline bytes 16 MiB |
| Path | 4 096 bytes, 64 components, UTF-8; no empty, `.` or `..` component, no NUL, no leading or trailing `/`, no component that git's own `fsck` refuses (`.git` in any case and its known aliases); the exact list will be taken from git's `fsck.c` when implemented |
| Modes | regular, executable, symlink (target ≤ 4 096 bytes), tree; no gitlink |
| Commit message | 64 KiB; trailers parsed by a fuzzed parser |
| `ReadTree` recursive | 100 000 entries per page, depth 64 |
| `Diff` | 10 000 files, 64 MiB of hunks per page; rename detection on at most 1 000 candidates; 30 s of CPU per call |
| merge-tree, rebase | 60 s per candidate, the git process killed at the deadline |
| Leases | 64 prefixes per lease, 256 live leases per principal |
| Open changes | 10 000 per repository; 1 000 revisions per change |
| Idempotency rows | 100 000 per principal, 24 h |
| Concurrency | 8 concurrent writes and 64 streams per principal |
| Change set | 64 repositories |

Fuzz targets (corpus committed): path validator, trailer parser, change-id and
cursor parsers, `FileEdit` application against a tree, merge-tree `-z` output
parser, every request message's validation.

Untrusted content never reaches a command line: object ids are validated full
hex and written to git's stdin, as gitproto already does; git runs with the
minimal environment gitproto uses (no user or system configuration).

## Local daemon: forge-agentd

One per user per machine. It is the only process that talks to the server.

- **Socket.** gRPC over a Unix socket in a directory of mode 0700, socket 0600;
  every connection's peer uid (`getpeereid` / `SO_PEERCRED`) must equal the
  daemon's. Sessions running under the same uid are one trust domain: the
  daemon attributes calls to the session that declares itself, for leases and
  authorship, but it cannot isolate two processes of one uid from each other.
  Isolation needs distinct uids (one daemon each).
- **Local protocol.** `Hello(label)` opens or reuses an agent session upstream
  for that local label; then the client uses the same services as the server
  (`RepoService`, `ChangeService`, `LeaseService`, `EventService`, …). The
  daemon adds the session token and forwards; reads of objects are served from
  the cache.
- **Object cache.** Content-addressed by object id, shared by every session; an
  object is admitted only after its id is recomputed from its content, so a
  corrupted or malicious response cannot poison it. Bounded (default 10 GiB,
  least recently used evicted). Misses are fetched from the server by id.
  It is **not** offered to clones as `objects/info/alternates`: a clone whose
  objects live in an evicting cache would be corrupted by the eviction.
- **Materialize(repo, commit, paths, dir).** Writes a sparse checkout of a
  commit into a directory the caller names (under the durable root the caller
  owns, never a temporary directory), for tools that need files. It is a plain
  directory, not a git worktree; changes go back through `CreateChange` /
  `UpdateChange` with the edits the daemon computes from it.
- **Events.** One upstream `Watch` for the union of the repositories its
  sessions watch; fan-out to local subscribers with the same cursor semantics.
  `WaitVerdict` is answered from the stream: N local waiters cost one stream,
  not N pollers (F5).
- **Bounds.** 64 local clients, 16 streams per client, the same message bounds
  as the server.

## Measured against git

Each row is a benchmark committed with the code, single core, interleaved
rounds, never under a 1-minute load above 8; allocation counts asserted exactly,
times compared. Repositories: this repository, `golang/go`, and the Linux
kernel (a large tree). Slower than the baseline is an open defect.

| Operation | Baseline with git | Metric |
|---|---|---|
| `CreateChange`, 1 / 100 / 10 000 edits | On a bare repository: `hash-object -w --stdin` per blob, `update-index --index-info` on a temporary index, `write-tree`, `commit-tree`, `update-ref` | server time per call, allocations |
| Agent round-trip: edit 3 files and publish | `git worktree add`, edit, `commit`, `push` to a local bare repository, versus `CreateChange` through the daemon | wall time, bytes written to disk |
| `Merge` candidate build | `git merge-tree --write-tree` + `commit-tree` on the same pair | server time |
| `ReadBlob`, `ReadTree` | `git cat-file --batch` (long-lived) on a local clone; cache hit and cache miss reported separately | latency, throughput |
| `Diff` | `git diff-tree -p -M` between the same commits | time; output equal to git's |
| Waiting for 13 verdicts | 13 independent REST pollers | requests per hour to the server (counted, not timed) |
| Change set of 2 / 16 / 64 repositories | the same number of sequential single-repository merges | time from all-green to all-moved |

Correctness oracle: every commit, tree and merge result the server builds is
compared with the one plain git builds from the same inputs (`git fsck` clean,
identical tree ids), on every benchmark corpus.

## Not taken

- **Merge, then let an agent fix conflicts.** Scion's post says it skipped a
  merge-queue global lock and relies on post-merge testing, since "Claude can
  typically fix those conflicts faster than humans can identify them". We merge
  only commits CI judged green, exactly; the cost is CI throughput, paid with a
  speculative queue.
- **Spanner and cloud blob storage.** A single forge server with SQLite and git
  repositories on disk; the scale of interest is hundreds of repositories and
  tens of agents, not one 100 GB monorepo.
- **Virtual (on-demand, FUSE-style) checkouts.** A kernel filesystem extension
  on every host is a large attack surface (macFUSE on macOS) for a gain that
  `Materialize` with a path list mostly gives.
- **A non-git wire protocol or object format.** Git clients and mirrors keep
  working.

## Milestones

Placed in design.md's list after milestone 4 (receive-pack), as `A1`…`A5`:

- **A1 (after 4).** `RepoService` reads; `CreateChange`, `UpdateChange`,
  `AbandonChange`, revision refs and trailers; `UpdateRef` compare-and-swap on
  unprotected refs; `WriteHeader` idempotency with intents; error model; hosts
  and agent sessions (direct to the server, no daemon yet). Benchmarks rows 1, 4,
  5. Protected refs are not movable through the API before A2.
- **A2 (after 5, Actions).** Verdicts, gate verdicts, `Merge` with candidates and
  the speculative queue, `WaitVerdict`, `EventService`.
- **A3.** Leases with fencing epochs, path permissions.
- **A4.** `forge-agentd`: cache, `Materialize`, event fan-out, session tokens held
  by the daemon only.
- **A5.** Change sets: joint CI, two-phase merge, recovery, the `PARTIAL` state.

## Open questions

1. Until repositories move to the forge, the frictions happen on GitHub. Is a
   GitHub-backed `forge-agentd` (one poller and cache for the whole machine,
   speaking the same local protocol) worth building first?
2. Reuse verdicts across commits with identical trees (saves a CI run after a
   no-op rebase), or keep them per commit?
3. Should protected refs require a FIDO2-signed human approval per merge, or is
   the gate verdict enough for agent changes on some repositories?
4. Should the server sign the commits it builds (SSH signature with a forge
   key)?
5. Is 64 repositories per change set enough for lock-step bumps across the
   organisations, or must large sets be split into ordered waves (giving up
   all-or-nothing between waves)?
6. Reuse Gerrit's `Change-Id` trailer name (tool compatibility) or a forge-own
   name (no confusion with a Gerrit instance's ids)?

## Sources read for this document

- "Redesigning source control at Anthropic" ([scion]), Anthropic Engineering,
  read 2026-11-25 (sections: Principles for agent-scale source control; How
  Scion works — Data structures, Scaling Scion; What we learned building Scion).
- `git-merge-tree(1)` ([mergetree]), Git 2.54.0 manual page (DESCRIPTION,
  OUTPUT, EXIT STATUS, MISTAKES TO AVOID).
- `git-update-ref(1)` ([updateref]), Git 2.54.0 manual page (`--stdin`,
  `start`, `prepare`, `commit`, `abort`; the note on concurrent readers).
- Gerrit, "Change-Id Lines" ([gerrit]), read 2026-11-25.
- Jujutsu glossary ([jj]: change, change ID, commit ID), read 2026-11-25.
- This repository's [design.md](design.md) and [admin-api.md](admin-api.md);
  `go-vcs/gitproto` README (Repository interface, git invocation rules).

To read before the matching milestone: git `fsck.c` and `read-cache.c`
(`verify_path`) for A1's path rules; `gitformat-signature` if open question 4
is answered yes; the GitHub REST conditional-request documentation for open
question 1.

[scion]: https://www.anthropic.com/engineering/redesigning-source-control
[mergetree]: https://git-scm.com/docs/git-merge-tree
[updateref]: https://git-scm.com/docs/git-update-ref
[gerrit]: https://gerrit-review.googlesource.com/Documentation/user-changeid.html
[jj]: https://docs.jj-vcs.dev/latest/glossary/
