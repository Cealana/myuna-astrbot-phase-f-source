# ADR-067: P07 full filesystem mutation-set v1

Status: accepted for inactive T1 source only

## Context

The exhausted P07 dual-state recovery v2 target contract predicted the Core
credential drop-in inventory as the exact prestate plus one memory drop-in.
The same transaction also replaced the Core release selector inside that
inventory root.  Postflight correctly observed both changes and rejected the
stale add-only digest.  Offline reconstruction proved that the selector delta
alone reproduced the observed receipt digest.

The predecessor `2/2` and v2 `1/1` lineages and all their evidence remain
immutable.  This ADR does not name or create a live strategy, series, attempt,
plan, preflight or activation.

## Decision

P07 filesystem transitions use one versioned declarative mutation set.

Each root binds a normalized absolute root, deterministic inventory pattern,
non-secret content class, allowed logical paths, recursion policy and exact
UID/GID allowlist.  Each ordered operation is exactly one of `add`, `replace`
or `remove` and binds:

- normalized root and logical path;
- exact before and after existence, type, SHA-256, size, UID, GID and mode;
- deterministic generator ID, source SHA-256, input digest and output-state
  digest;
- operation kind and order.

Duplicate, overlapping, escaping, symlinked, replayed, stale, unmodelled and
impossible transitions fail closed.  The complete target inventory is derived
by applying every operation to the exact prestate.  There is no add-only
shortcut.

The production overlap is represented as one set containing, in order:

1. replacement of `10-core-release-selector-v1.conf`; and
2. addition of `90-p07-owner-private-memory-v1.conf`.

Credential semantic identity remains a separate exact contract.  It cannot
substitute for filesystem byte identity, and filesystem equality cannot
substitute for the five credential-semantic fields.

## Staging and commit gate

Every changed path is rendered into a protected, plan-bindable, off-live
staging bundle before mutation.  The bundle contains exact before bytes for
replace/remove and exact after bytes for add/replace, plus a canonical
content-free manifest.  Staged paths are derived from operation order and a
logical-path digest; target absolute paths are not mirrored into the bundle.

The staging verifier requires exact contract ID, target inventory digest,
payload SHA/size/mode, canonical manifest bytes and a closed file inventory.
Two builds from identical source and inputs must be byte-and-mode identical
and bytecode-free.

The installer verifies exact prestate, applies each path atomically, fsyncs the
file and directory boundary, reads back every changed path, and then verifies
the complete target inventory.  A future daemon reload, service start or
provider-egress callback may run only after the full target gate is green.

## Crash evidence and rollback

The journal is canonical, content-free and transaction-bound.  It persists:

- contract and transaction identity;
- current stage and operation order;
- completed forward and reverse orders;
- per-path logical label and digest;
- expected and observed state digests;
- atomic rename and fsync completion;
- rollback started/completed/failed state.

No file content, private message, credential value or secret is recorded.

Any normal forward failure starts one exact reverse rollback.  A process crash
before completion deterministically enters the same rollback action.  Reverse
operations are replay-safe: a path already at exact before state is accepted;
a path at exact after state is restored; any third state fails closed.  A
crashed rollback may resume from its recorded order, but a recorded rollback
failure cannot be retried or silently reset.

Rollback restores every changed path in reverse order and verifies the full
prestate inventory.  It does not rewrite either exhausted P07 lineage.

## Content-free mismatch evidence

Postflight evidence records only fixed fields: logical path, path digest,
expected and observed existence/type/SHA/size/UID/GID/mode, mismatch fields,
inventory digests and typed status.  This distinguishes the affected path
without retaining bytes or credential values.

## Consequences and boundary

- A transaction cannot omit a planned in-root replacement from its expected
  inventory.
- Unexpected concurrent changes are not overwritten during rollback.
- Read-back corruption may make rollback fail closed instead of overwriting an
  unproved third state.
- Staging and transaction code is exercised only against synthetic temporary
  roots in this phase.
- No live path, service, selector, config, archive, attempt or evidence is
  changed by this T1 source integration.
