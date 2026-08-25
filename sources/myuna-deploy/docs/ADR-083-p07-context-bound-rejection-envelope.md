# ADR-083: P07 context-bound rejection envelope

Status: accepted for source-only implementation

## Context

The durable fresh-status evidence already bound the source-derived strategy,
but the outer canonical CLI rejection envelope always emitted the legacy
`STRATEGY_ID`.  A rejected fresh status could therefore be persisted correctly
while its outer content-free projection named a different lineage.  The
product remained fail-closed, but the receipt identity was not authoritative.

## Decision

An outer rejection may name a strategy only through a private, versioned,
source-verified context:

- A fresh context is created only after the complete fresh strategy has been
  rebuilt and validated against the exact runtime manifest, source commits and
  trees, immutable continuation reference, and immutable lineages.
- A legacy context is created only from the exact legacy max-one strategy
  contract.  It cannot accept a fresh, renamed, partial, or caller-supplied
  mapping.
- Missing, malformed, mixed, stale, conflicting, or caller-attached context
  produces an explicit generic unavailable projection with no strategy ID or
  strategy digest.  Generic rejection never defaults to the legacy identity.

The fresh status observer binds the same verified context used by its durable
O_EXCL intent/result/completion evidence.  Package reopen validates its exact
fresh or legacy context before binding backup, ledger, formal preflight,
activation, rollback, and postflight failures.  Errors before a trustworthy
strategy context exists remain generic and fail closed.

The outer envelope stores only source IDs, typed reason codes, fixed booleans,
strategy identity/digest when verified, and the already reviewed allowlisted
P08 stage projection.  It never stores raw exceptions, stdout, stderr, paths,
configuration, authentication material, UID data, temporal content, request
content, provider payloads, or channel content.

## Immutable predecessor boundary

The historical terminal v5 rejection is reproduced by a dedicated historical
serializer solely for byte-exact evidence verification.  It is never used for
new runtime rejection output and is never interpreted as ready.  Existing
status evidence remains rejected and immutable; no P08 retry, third request,
continuation replay, strategy reset, or evidence rewrite is introduced.

## Artifact boundary

Production source names only the new fixed A runtime and bundle roots for this
contract version.  Deterministic B roots remain inactive comparison outputs.
Both roots must be built from the final clean source commit, and the copied
runtime script must be byte-identical to source.  Predecessor, mixed, scanned,
environment-selected, aliased, or symlink-substituted roots reject before a
status intent or any later state.
