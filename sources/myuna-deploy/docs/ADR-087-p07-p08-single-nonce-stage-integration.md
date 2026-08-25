# ADR-087: P07 binds the reviewed P08 single-nonce status boundary

## Status

Accepted for inactive source and build verification. This decision does not
authorize a P08 status call, service change, P07 activation, or Owner E2E.

## Context

P08 now exposes a reviewed protocol-acceptance contract in which one controller
nonce is carried through one helper invocation, the authenticated server echo,
the content-free helper projection, and controller validation. P07 previously
bound the status-stage and server-rejection contracts but still named the prior
helper and inactive release closure.

P07 must consume the new capability without owning or copying P08's
implementation, adding P08 paths to the P07 mutation set, retrying a terminal
status invocation, or weakening its generic external failure behavior.

## Decision

The P07 production plan derives a versioned, content-free protocol-acceptance
projection from its reviewed stage allowlist. It requires exactly one helper
call, the fixed nonce environment name, the complete five-step nonce chain, no
retry or fallback, no retained raw stderr, the exact P08 source path and digest,
and the reviewed contract digest.

The P07 runtime and status intent also bind the exact P08 helper, inactive
release and manifest, source and future-installed inventories, full metadata
inventory, controller and strategy provenance, Core and Deploy source boundary,
service identities, and unchanged stage/server contract identities. Unknown,
mixed, stale, substituted, or malformed identities fail closed before status
intent creation.

P08-owned source, builders, units, release selection, controller lineage, and
live state remain P08-owned and read-only. P07 continues to present a generic,
no-retry unavailable result externally while preserving only the reviewed
content-free stage projection in its own O_EXCL evidence.

## Preserved boundaries

- The request collection remains closed at two; no request is replayed or added.
- The immutable continuation and all exhausted or rejected lineages remain
  byte-exact, read-only evidence.
- The target remains memory-only and diary/provider inert.
- P07 does not add P08 release, selector, environment, unit, socket, or service
  paths to its production mutation set.
- This source phase creates no production intent, package, prestate, state,
  plan, backup, ledger, preflight, attempt, service action, or live mutation.

## Rollback

Source rollback is the additive pre-main P07 ref. Inactive artifacts are
non-overwriting and retained. A future live rollback remains the existing
plan-bound, exact-prestate P07 controller contract and is not exercised here.
