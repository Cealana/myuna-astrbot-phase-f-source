# ADR-077: P08 existing-state upgrade v1

Status: source-only candidate; inactive

## Decision

P08 upgrades an already-selected temporal service through a P08-only
transaction. The exact predecessor is release
`9a767797c9e4ee9ac3e417e2e00fdcabb68b6fcafeddcec090b05eb3ef9b103f`.
The transaction may install one immutable P08 release, replace only the P08
selector and the plan-bound P08 service/socket unit bytes, and restart only
`myuna-active-temporal-context-v1.service` and its socket. It does not select,
rewrite, restart, or otherwise mutate P07, generation13, P01, P09, P10, P15,
P16, Owner Profile, session history, Telegram, or QQ.

The existing state directory is authoritative opaque data. The controller
requires exactly the two expected regular files with exact ownership and
modes, records size/digest/mtime without opening a database, copies them into
a non-overwriting plan-addressed backup, verifies the backup byte-for-byte,
and requires the same descriptor after target start. It performs no schema or
content migration. If rollback must restore changed bytes, it first preserves
the changed tree and then atomically selects a verified staged copy of the
original bytes. Type, permission, inventory, size, substitution, or concurrent
drift fails closed.

Before any service mutation, the four public P08 projections are copied and
read back with an exact inventory, bytes, mode, UID, and GID check. The journal
then enters rollback ownership before the first stop command. Because the
service is socket-activated, stop order is socket first and service second;
rollback/recovery restores the predecessor projections before enabling the
socket and starting the service again.

State may legitimately advance between plan preparation and the completed
service stop. Until an exact state backup is journal-owned, such drift is not
controller-owned: the current bytes are never replaced from a missing, partial,
or older backup. The controller restores only public P08 projections, starts
the predecessor, records a typed hard stop, and leaves the advanced state and
failed evidence intact. No target release is selected in that path.

## Compatibility closure

The target release manifest derives compatibility from exact source and
artifacts, not caller-provided allowlists:

- active predecessor client identity
  `798f834102af16efd47d7ddc3fa72904a6ca86d01fd02b354aadf65607594894`
  owns `retrieve`, `propose`, and `confirm`;
- reviewed target client/status-helper identity
  `32e615f8d7a4ce18f2d0e31021b14c984a31640b143b0da7ec7aa779a418f325`
  owns those operations plus `snapshot_active` and `status_content_free`;
- target protocol identity
  `197dc45906628f97e347629c25ef970c39cae9dad13d67665a5836ea86845082`
  must expose exactly those five operations;
- deterministic synthetic authenticated requests from both clients must be
  accepted by the target parser before the release can be built.

The service implementation and service/socket/sysusers/tmpfiles semantics are
also fixed by exact digests. The target selector deliberately retains the
active predecessor P07 gateway client and manifest identities; the reviewed
new client remains a source-bound status-helper artifact. Missing, mixed,
stale, or substituted identities fail closed.

## Journal and rollback

The plan binds predecessor/target releases and source commits, public P08
prestate, opaque state descriptor, active gateway identity, unit state, and an
exact fixed P08-only path set. Recovery also requires the evidence directory's
`PLAN.json` to be byte-identical to the validated plan. A plan-addressed
journal is written and fsynced at
every phase. A second activation for the same plan is rejected. A crash before
mutation converges to the unchanged predecessor; a crash after mutation uses
the journal and verified backups to restore state, selector, environment, and
unit bytes before starting the predecessor service/socket. Completed rollback
and failed rollback are hard stops, not new attempts.

## Post-target metadata-only readiness

The separately owned post-target repair/rollback controller has one shared
incident identity and permits at most one mutually exclusive action. Its
readiness plan projects the current opaque state using only path role, file
type, link count, mode, UID/GID, size, and stable stat-generation fields. It
does not open, hash, parse, copy, or expose either state file, and it marks
`opaque_content_read_deferred_to_action_owned_backup=true`. This metadata is a
drift oracle only; it is never represented as exact-byte evidence or used as a
rollback source. The source-owned preflight command may emit two canonical,
byte-identical ready projections without creating an incident namespace.

Only after the controller has claimed the incident with O_EXCL semantics and
durably written its plan, consumed ledger, and journal may it read state
bytes. Before the first stop it validates the predecessor backup, then takes a
new non-overwriting action-owned backup using stat-before/copy/stat-after and
streaming SHA-256 read-back. The journal cannot enter `attempt_owned` until
the exact backup and its plan-bound state binding are durable. Failure during
this phase consumes the incident and hard-stops before service mutation.

Post-target convergence and recovery may restore opaque bytes only from that
action-owned backup. Prepare-era stat drift, action-era content drift,
same-size replacement, spoofed mtime, hardlink/symlink substitution, partial
copy, crash, replay, and competing repair/rollback allocation all fail closed.
The predecessor backup remains separately bound for a predecessor rollback;
it is not substituted for current authoritative state during a repair
convergence.

## Layering and authority

P07 remains the stable long-term Owner Profile/memory layer. P08 remains the
days-scale temporal layer. The 128-message SQLite store remains session-only.
P10-B remains the trusted-time provider contract and is not implemented here.
P15 remains responsible for later task-specific context selection. There is no
implicit write, fallback, schema reuse, or migration across these layers.

This ADR and its controller are T1 source only. Building or testing them does
not create a live plan, backup, journal, preflight, attempt, release install,
selector change, restart, protocol call, Owner E2E, or T2 authority.
