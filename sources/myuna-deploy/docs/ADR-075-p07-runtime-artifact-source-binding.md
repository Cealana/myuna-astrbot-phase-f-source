# ADR-075: P07 runtime artifact source binding

Status: accepted source contract; inactive; no T2 authority.

## Context

The owner-private memory transactional controller previously treated the
Telegram runtime directory as an operational locator.  The legacy runtime
validator bound Core and Deploy commits but did not bind the current Deploy
tree, the source-derived Telegram plugin, complete runtime bytes/modes, or the
cross-Program compatibility projection.  A runtime built from an older Deploy
commit could therefore remain structurally acceptable until a later gate.

## Decision

`p07-owner-private-memory-runtime-artifact-source-binding-v1` is the sole
source identity for a future memory-only target runtime.  The runtime builder
emits a canonical hybrid manifest that binds:

- exact Core and Deploy commits and trees;
- base runtime digest and complete regular-file SHA-256/size/mode inventory;
- exact source-derived Telegram plugin release, plugin manifest, config and
  rollback projection;
- disabled-memory-only policy, diary/provider inertness, fixed service
  identities, and immutable P01/P08/P09/P10/P15/P16 public boundaries.

The transactional bundle contains the resulting content-free runtime artifact
projection.  Production constructor, plan, package, backup, preflight,
activation and rollback reopen that projection.  A runtime path is locator-only
and must verify to the sole manifest-bound identity.  Missing, extra, stale,
mixed, replayed, symlinked, byte-, mode-, source-, plugin-, policy-, service-,
or rollback-drifted artifacts fail closed before public observation or state.

## Compatibility and rollback

Existing runtimes, bundles, receipts, backups and exhausted lineages remain
immutable evidence and are never relabelled.  Effective V6 plus compressed
generation13 remains the exact rollback predecessor.  This ADR creates no live
selector, package, prestate, strategy, plan, backup, ledger, preflight or
attempt, and authorizes no provider, channel, private-data or migration action.
