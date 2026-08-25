# P16 Phase 1 T2 design v1

## Rollback-bound live controller

`scripts/activate_p16_phase1_t2_v1.py` is the only Phase 1 live entrypoint. The
bundle binds its exact source SHA-256 and the exact Deploy commit; the
controller runs from that clean local main with the matching Core source on
`PYTHONPATH`. It is intentionally not enabled or imported by any installed
runtime artifact.

The controller exposes `preflight-live`, `activate`, and `rollback`. Activation
requires two byte-identical fresh preflights, an exact plan digest, and the
explicit `ACTIVATE:<digest>` token. It installs immutable artifacts, provisions
the Telegram-only history directory, writes the selector while still default
off, restarts only Core and Telegram, verifies fixed generation-13 readiness,
then creates the marker last. Rollback removes the marker first, restores exact
Core/Telegram bindings and desired service state, and preserves artifacts,
history, backups, receipts, and both immutable attempt-series namespaces.

No command calls a health endpoint, channel, model, provider, Profile, session
store, database, or log reader. P07 release-set, P08, plugin selection, Effective
V6, QQ, old epochs, and unrelated services are invariant inputs.

## Immutable attempt-series lineage

Bundle v3 cryptographically links the exact terminal v1 series: predecessor
ledger bytes, terminal attempt-2 transition, activation receipt, sealed backup,
active marker/selector/drop-in, bundle, plan, artifacts and source identities.
Those objects stay byte-identical and are never rewritten, reset, migrated or
reopened.

The successor has a distinct content-addressed series identity and starts at
zero inherited attempts with a maximum of two. Each activation atomically
appends `attempt-0001` or `attempt-0002` under the existing protected lock before
any target mutation. Receipts bind the successor bundle, strategy, exact plan,
previous attempt digest and terminal-lineage digest. Missing/stale terminal
evidence, arbitrary bundle substitution, branch, gap, duplicate, partial/crash
residue, replay, schema/digest/permission/type/symlink drift or concurrent
writers fail closed. No `attempt-0003` exists; rollback and uninstall preserve
both series and all activation receipts.

Status: executable source contract with deterministic build and rollback-bound
live preflight. Authority is external to this document and must bind the exact
plan digest; importing or installing artifacts alone remains default off.

## Inactive activation boundary

Importing or installing the adapter cannot enable history. The adapter requires
both the canonical `myuna.p16-incident-history-selector.v1` file and the
separate root-controlled marker. The successor prestate contains the active
terminal predecessor marker; activation backs it up exactly, removes it first,
writes and verifies the successor selector/drop-in while default-off, then
creates the successor marker last. The selector is root-owned, readable only by the Telegram runtime
group, fixed to the exact bundle and Telegram channel, and rejected on any
field, owner, group, mode, size, framing, type or symlink drift. QQ remains
outside this activation design.

The source-only systemd drop-in adds one write path for the existing
`myuna-gateway-telegram` identity. It adds no capability, identity, socket,
service or start/restart instruction. The history parent is root-controlled;
only its Telegram child is owned by the service identity.

## Durable content-free boundary

Capacity is fixed at 128 active occurrences. Exact duplicates are idempotent;
older entries roll into a digest-chained content-free manifest. Exclusive
no-follow lock creation, atomic replace, file and directory fsync, strict file
modes and state/occurrence digests fail closed on crash, replay, concurrency,
permission, type, symlink or digest drift. Uninstall and rollback must preserve
the history directory and its digest/count evidence.

The receipt accepts only fixed request boundary, stage, namespace/gate,
latency/HTTP/provider classes, attempt count, called booleans, release-set,
epoch deltas, actual incident reference status and digest-chain metadata. It
does not accept message/caption/media, identity/request id, prompt/response,
Profile/session/DB content, raw logs/errors/stacks, path, secret/credential,
provider/model payload, cost/amount or arbitrary detail.

## Generation-13 and rollback boundary

The deterministic bundle overlays the exact P16 Core and Telegram sources on
the accepted generation-13 Core/runtime bases, preserves the Telegram plugin
bytes, references the accepted P08/P07/Effective V6 identities, and builds a
standalone P16 adapter release. Two independent build roots must produce equal
bundle, artifact and complete-inventory identities.

The accepted generation-13 checkpoint is historical evidence, not a fresh
live observation. Artifact-only preflight therefore returns
`design_ready_live_preflight_required` and `activation_ready=false`. A later
separately authorized live gate must bind fresh exact selector/config/release,
service/socket/restart and epoch aggregate prestate, reproduce the same design
identities twice, establish backup/rollback state, then explicitly create the
marker last. Any drift fails closed.

Rollback removes the marker first, then the selector, restores the exact fresh
prestate release/unit binding and desired service/socket state, and never
deletes incident history or modifies old epoch, Profile, session, Writer, QQ,
P01-B or P09 state. Functional rollback requires exact identities, stable
restart counters, preserved history digest/count, unchanged public reply
contract and no fabricated incident.

## Owner canary plan

Only the Owner may send one natural ordinary-text message in the existing
authenticated Owner-private Telegram channel. The task must not send it. The
expected outcome is exactly one reply with unchanged public wording. Safe
correlation may use only CST/UTC time, latency bucket and an actual opaque
incident reference when present; no message text is read or retained and no
fault is injected.
