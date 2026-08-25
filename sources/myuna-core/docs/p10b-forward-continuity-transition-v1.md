# P10-B Forward Continuity Transition v1

Status: source-only and inactive. This contract defines a Core-owned recovery seam for a
trusted-time anchor that is valid but cannot pass the ordinary same-boot residual bound. It
does not activate P08, select a runtime, or authorize a production transition.

## Invariants

- The ordinary trusted-time sample path and its two-second drift bound are unchanged.
- P08 remains a one-sample consumer with no fallback. It never calls the transition seam.
- Assessment is read-only. It observes the configured source once, returns content-free
  categories and digests, and performs no durable mutation.
- A transition is a separate, explicit call. It accepts exactly one assessment and one
  externally issued, versioned authorization bound to that assessment, source contract,
  source evidence, lineage, caller identity, policy, watermark, anchor, and residual window.
- The authorization is forward-only, has `max_attempts=1`, and expires after at most 300
  seconds. A transition identifier and prior-anchor digest are atomically unique. SQLite
  `BEGIN IMMEDIATE` plus strict unique constraints provide O_EXCL-equivalent claim semantics.
- The committed candidate has the same source, source class, authority, and boot as the prior
  anchor; its sequence is exactly prior sequence plus one; its trusted instant and consumer
  watermark floors never decrease.
- The old anchor is written to immutable append history before the current anchor advances.
  History and transition records form a digest-linked chain. Existing history is never
  overwritten or rewritten.
- Missing, partial, truncated, mixed-source, substituted, expired, replayed, concurrent, or
  ambiguous evidence fails closed.

## Assessment outcomes

`DurableTrustedTimeProvider.assess_continuity()` distinguishes:

- `initial` and `consumer_reconciled`: ordinary sample eligibility;
- `boot_transition`: ordinary sample eligibility under the existing restart-continuity rule;
- `same_boot` within the configured drift bound: ordinary sample eligibility;
- `same_boot` positive residual above the bound: explicit forward transition eligibility;
- `same_boot` negative residual above the bound: ineligible regression.

The public assessment contains schemas, fixed categories, and SHA-256 digests only. The exact
observation and residual remain process-local inputs to binding and validation; they are not an
audit payload. The process-local assessment clock is also represented only by a digest and is
revalidated before mutation. Corrupt, partial, or otherwise ambiguous state produces a typed
fail-closed error and no assessment object; ambiguity is never represented as eligibility.

## Commit and recovery semantics

The transition validates the assessment and authorization before acquiring the store write
transaction, then validates the current anchor and ledger again under `BEGIN IMMEDIATE`. It
appends one history record, appends one transition record, advances the current anchor, and
updates the chain head in one transaction.

- Failure before commit rolls back the entire transaction. Read-only reconciliation reports
  `not_committed` only when the exact prior anchor still exists and no matching record exists.
  That result does not authorize replay: `max_attempts=1` remains the controller contract, and a
  later operation requires a fresh independent plan and gate.
- Failure after commit is persistence-ambiguous to the caller. The caller must not retry.
  Read-only reconciliation reports `committed` only when the exact authorization and candidate
  bindings are present in a fully valid chain.
- Reconciliation never writes state and never substitutes a new sample.
- Source-code rollback does not roll durable state backward. After a committed transition, the
  new anchor remains authoritative and the old anchor remains append history; restoring old
  state bytes is outside this contract and is not an allowed rollback mechanism.

## Boundary

This source foundation uses only synthetic or temporary roots in tests. It does not read or
materialize production state, invoke a live provider, alter provider selection, modify P08/P07
paths, or change any service, configuration, release, host, WSL, network, or time policy.
