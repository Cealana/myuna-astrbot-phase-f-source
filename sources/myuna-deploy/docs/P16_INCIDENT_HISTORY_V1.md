# P16 content-free incident history v1

Status: source-mainline foundation with a separately built, default-off T2
design. It remains inactive until an exact selector and independent marker are
installed under a later live gate; importing or installing source alone cannot
enable writes.

## Contracts

- `myuna.incident-occurrence-evidence.v1` accepts only fixed enums, booleans,
  bounded counters, safe UTC metadata and existing safe projections.
- `myuna.incident-occurrence.v1` adds a monotonic sequence, evidence digest,
  previous-occurrence digest and occurrence digest.
- `myuna.incident-history.v1` retains at most the configured active capacity.
  Oldest entries roll deterministically into
  `myuna.incident-history-rollup.v1`; rollup count, time boundary, terminal
  digest and chained summary digest prevent silent overwrite.
- `myuna.incident-problem-attachment.v1` exposes only an active occurrence
  digest and its safe fingerprint digest. It creates no Incident, Problem,
  Known Error, closure, recovery or runbook record.

The store never accepts message text, identity, request id, prompt, provider or
model response, Profile/session content, database rows, raw logs/errors/stacks,
paths, secrets, tokens, costs, amounts or arbitrary details. Source projection
fingerprints are validated as fixed safe tokens and domain-separated before
storage. Missing projection/correlation remains `unknown` or JSON `null`; the
store never creates a public code, incident reference or fingerprint.

## Failure provenance bridge

The frozen mapping keeps `provider-transport-failure` in namespace `provider`,
gate `transport_failure`, outcome `transport_failure` and retryable status.
Known 5xx evidence with `provider_called=false` keeps the Core pre-provider
family. Legacy `myuna.core-failure-provenance.v1` evidence keeps the
`core_pre_provider_fail_closed` gate and does not claim a subtype. Version 2
adds one allowlisted, content-free `failure_gate`; reviewed projection-budget,
context-contract and egress-safety gates become the incident `typed_gate`,
while any unreviewed value collapses to `core_pre_provider_unknown`. Public
wording and `MYU-*` codes do not change. Telegram and QQ use the same
channel-neutral mapping.

Normal 128-message capacity, continuity reset, successful recovery, complete
rollback, affinity absent and affinity abstained are not fault occurrences.
History does not treat a later success as closure and does not fabricate the
three previously observed live occurrences.

## Storage and recovery boundary

The source store uses a strict owner-controlled non-symlink directory, an
exclusive create-only append lock, canonical JSON, atomic replace, file and
directory fsync, exact file modes, digest-chain validation and unexpected-file
rejection. Exact duplicates inside active retention are idempotent. A stale
event at or before the rollup watermark fails closed because bounded storage
cannot prove its exact prior membership. A reused active incident reference
with different evidence also fails closed.

Permission/type/symlink/digest drift, an existing append lock, a crash temp
artifact, malformed state or inconsistent call/outcome evidence never causes a
best-effort write. T2 activation would require a separate reviewed runtime
adapter supplying actual release-set, latency, call, service/restart and epoch
evidence plus an exact prestate, rollback, content-free receipt and tests. This
design changes neither `myuna.user-visible-fault.v1` nor its public index. The
current T2 design and rollback contract is documented in
`P16_PHASE1_T2_DESIGN_V1.md`.
