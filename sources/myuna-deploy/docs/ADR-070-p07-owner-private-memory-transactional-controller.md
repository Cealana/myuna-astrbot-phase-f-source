# ADR-070: P07 owner-memory transactional mutation controller

Status: accepted for inactive T1 source only

## Context

The exhausted predecessor (`p07-policy-overlay-v1`, `2/2`) and dual-state
recovery v2 (`1/1`) are permanent read-only evidence.  V2 failed because its
target credential inventory model included the new memory drop-in but omitted
the simultaneous Core selector replacement in the same scanned root.  The
accepted full filesystem mutation-set source proved that adding the selector
delta reproduces the observed target digest exactly.

This ADR integrates that source contract into a future controller.  It does
not create a strategy, namespace, plan, backup, preflight, ledger, attempt or
live state.

## Independent source identity and lineage

The source identity is
`p07-owner-private-memory-transactional-mutation-controller`.  It is not a
rename, reset or continuation of either exhausted runtime strategy.  A future
runtime namespace must be absent before planning and may allow exactly one
activation.  A pre-existing state root, backup root or ledger fails closed.

Before a future plan can exist, the controller must verify:

- the complete immutable predecessor evidence and exact `2/2` ledger;
- the v2 terminal handoff, exact `1/1` ledger, receipt/journal, state tree and
  backup tree;
- the root-cause and full-mutation-set handoffs;
- the accepted full-mutation source bundle and manifest identities; and
- the exact Core and Deploy source boundary.

Evidence is imported as content-free hashes, counts, schemas and protected
tree identities.  Missing, substituted, reset, relabelled or replayed evidence
is terminal.

## Complete plan contract

A future pure plan binds one complete add/replace/remove mutation set and its
derived target inventory.  Every operation is assigned exactly once to a
closed category: Core release, runtime release, plugin release, selectors,
drop-ins, archive roots, index roots or diary roots.  Protected directory
transitions additionally bind exact before/after existence, path digest,
UID/GID and mode.

The plan also binds exact public prestate for releases, selectors, drop-ins,
credential semantics, archive roots, calendar zone, epoch, services and
container; the approved diary/recall/calendar/Profile/P15 policy identities;
and immutable P01/P08/P09/P10/P15/P16 boundaries.  It carries only
content-free projections and all private/provider/channel/model/health and
old-history-migration flags are false.

## Backup and staging

The plan-derived backup path is non-overwriting.  It contains exact before
bytes for every replace/remove operation, exact target metadata, the complete
mutation-set identity, protected staging/journal path identities and a closed
canonical manifest.  Root ACL, type, owner, mode, file inventory and every
blob read-back must match before any attempt may be consumed.

After backup verification, all before/after bytes are rendered into the
existing deterministic protected staging contract.  Staging substitution,
extra files, stale bytes, path/type/owner/mode drift or inventory mismatch
fails before mutation.

## Ordered activation and egress barrier

The controller order is fixed:

1. verify immutable evidence and exact namespace absence;
2. create and verify the plan-bound backup;
3. create and verify protected staging;
4. consume the sole future attempt;
5. stop and verify target services stopped;
6. atomically apply all files, read back each path and verify full target
   inventory and credential semantics;
7. daemon reload;
8. start and verify Core;
9. start Telegram and verify the complete target.

No egress-capable step can precede full byte and semantic target acceptance.
The controller itself has no provider, channel, model or health client.

## Crash evidence and rollback

The low-level mutation journal remains canonical, fsync-bound and
content-free.  The controller adds a plan-bound journal that distinguishes
pre-attempt, in-attempt, post-attempt and rollback states, records only typed
categories/digests, and permits one rollback invocation.

Any in-attempt failure reverses all filesystem operations in exact reverse
order, then reloads and restores Core before Telegram, followed by exact
functional prestate verification.  A target-complete filesystem state may be
reversed once when a later service or functional gate fails.  A path in a
third state, replayed rollback, prior rollback failure or uncertain service
restoration fails closed.  Neither exhausted lineage is changed or consumed.

## T1 boundary

All execution tests use synthetic temporary roots, injected service hooks and
network-denied identities.  The inactive bundle truthfully records that the
controller source is present while selection, installation, plan, backup,
preflight, ledger, attempt, live mutation and provider call are all absent.
T2 requires a separate exact decision and must preserve both exhausted
lineages.
