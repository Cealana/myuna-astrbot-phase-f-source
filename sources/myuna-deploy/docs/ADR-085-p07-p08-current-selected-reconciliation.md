# ADR-085: P07 current-selected P08 dependency reconciliation

## Status

Accepted for inactive T1 source/build verification only. This decision does not
authorize P08 selection, a status protocol call, P07 preflight, activation, or
any live service operation.

## Decision

The P07 memory-only transactional runtime binds the reviewed P08 capability
closure selected by the exact current Deploy source. The binding includes the
inactive release and manifest, source and future-installed inventories, helper
and service entrypoint bytes, service and socket unit bytes, and the canonical
server-rejection and status-stage target projection digests.

The helper's own reviewed source contracts remain independently bound. Target
manifest projection digests do not replace or reinterpret those helper source
identities.

P07 does not own P08 selection. P08 release, selector, environment, service,
socket, or controller paths are not added to the P07 mutation set. A future P08
selection must complete under P08 authority before a separately authorized P07
transaction can observe a fresh content-free status.

## Fail-closed properties

- Production artifact roots are fixed in source; caller, environment, scan,
  latest-build, fallback, and symlink substitution are rejected.
- Predecessor, mixed, stale, missing, extra, type, mode, and digest drift reject
  before status evidence or state creation.
- The terminal request collection remains closed at two requests. Continuation,
  rejected invocation, old lineages, and all prior evidence remain immutable.
- The target remains memory-only and diary/provider generation remains inert.
- P07 keeps its exact single-status, two-identical-preflight, max-one activation,
  and one-bounded-rollback contracts without creating any real T1 state.
