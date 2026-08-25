# ADR-080: P07 immutable continuation reference and fresh max-one strategy

Status: source-only, inactive

## Decision

The completed continuation created by the terminal P07 T2 is immutable
predecessor evidence, not a reusable request and not the current target
contract.  Production code verifies its fixed content-free identity read-only:
the continuation ID, three file identities and metadata, terminal rejection and
handoff digests, closed two-request collection, historical source/artifact
identity, and `reinterpreted_as_ready=false`.  Verification never requires the
historical target to equal the current target and never writes, relabels,
replays, or removes the predecessor.

The closed request collection has an exact historical storage owner of root
(`0:0`). The terminal request payload separately binds its target runtime owner
as `999:989`. ADR-081 defines the versioned schema and exact inventory that keep
those roles distinct without modifying the historical evidence.

A future run uses a source-derived fresh strategy contract.  Its identity binds
the exact current Core/Deploy/runtime/plugin/bundle closure, the immutable
continuation-reference digest, the exhausted P07 2/2 and dual-state v2 1/1
lineages, a terminal-before-attempt predecessor, maximum attempts one, and
source-declared path roles for state, backup, target package, and status
invocation evidence.  Dispatch input cannot name or replace these identities or
roots.

Before public prestate or package creation, one source-owned status invocation
is recorded under a dedicated protected namespace.  Intent is O_EXCL and
content-addressed; a reviewed P08 helper is called at most once; result and
completion are append-only with completion last.  Accepted evidence contains
only the allowlisted content-free status projection.  Rejected evidence contains
only the reviewed 17-stage projection and causes a hard stop before package,
state, attempt, service mutation, or egress.  Partial, duplicate, replayed,
concurrent, stale, mixed, symlinked, or metadata-drifted evidence fails closed
and is never silently resumed or cleaned.

The current package, public-prestate, plan, non-overwriting backup, two identical
formal preflights, max-one activation, and one exact reverse rollback mechanics
are rebound to the fresh strategy and immutable reference.  The target remains
disabled-memory-only: diary selectors, workers, timers, previews, generation,
and provider/channel egress stay absent or inert; no old-data migration occurs.

## T1 boundary

This ADR and implementation create no production continuation, invocation,
request, package, prestate, state, plan, backup, ledger, preflight, attempt, or
service action.  Synthetic roots and fixtures only are permitted.  A future T2
requires independent acceptance and a fresh exact freeze.
