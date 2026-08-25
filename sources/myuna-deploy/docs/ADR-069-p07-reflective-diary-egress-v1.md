# ADR-069: P07 reflective-diary generation and egress v1

Status: accepted T1 source contract; inactive until a later P07 live gate.

## Decision

P07 may generate one append-only reflective diary revision for each closed original
calendar day through the existing authenticated Telegram Owner-private DeepSeek route.
The job contains the complete eligible delivered-turn set for exactly one day, in
trusted chronological order, and uses `deepseek-v4-flash` under the dedicated
`p07_external_daily_reflective_diary` role. It is a distinct, digest-bound purpose;
historical recall consent does not silently imply diary generation, and diary consent
does not authorize any other egress.

Raw local turns remain the sole factual authority. A diary is Myuna's derivative
perspective and separates factual observations, interpretation/reflection,
uncertainty, and intention. Every selected turn must be covered by a source sequence
and digest. The diary cannot write Profile or P08 temporal-validity state.

## Closure, capacity, and privacy

- A later exact trusted-time binding in the same IANA zone proves that the original
  day is closed. The original zone/day remains stable across later default-zone changes
  and follows IANA DST rules.
- All eligible model-history turns in that day are selected exactly once. Missing,
  unresolved, conflicting, or drifted source/time evidence produces a typed
  `coverage_incomplete` gap before provider egress.
- The complete day is serialized as one bound request. It must fit the existing
  request-character, projection-character, serialized-byte, token, and output-reserve
  oracles. An over-limit day produces `coverage_incomplete` and no provider call.
- Partial-day generation, silent event omission, whole-history transmission, image
  bytes, Profile/DB/log/secret expansion, cross-channel/identity egress, and new
  provider/storage/retention boundaries are prohibited.
- Receipts and audit projections contain only counts, booleans, categories, digests,
  day/zone identity, source ranges, attempt state, and limiting oracle.

## Lifecycle and recovery

The first exact turn in a later day creates an event-driven ready job for the closed
day; there is no time polling. A ready job is archive-head, closure-binding,
source-selection, persona, release, overlay, policy, and style bound. Dispatch intent
is persisted before the provider path. Generation has at most three bounded attempts;
failure records a retryable gap and finally a typed missing gap. Chat and raw archival
never wait for the diary worker.

The durable call projection is tri-state rather than optimistic: pre-capacity
rejection is `not_called`, a received candidate/commit is `called`, and a crash or
transport failure after dispatch intent is `unknown`. A final crash at the third
attempt becomes a typed missing gap and cannot create a fourth provider call.

Diary entries and job events are immutable. Replay of identical events is idempotent;
conflicting replay fails closed. Late backfill may create revision 1 and is explicitly
labeled. Corrections append revision N+1 with the prior revision link and never rewrite
raw turns or an earlier diary. Source-pointer, archive-head, policy, persona, release,
capacity, or candidate drift rejects the operation.

The rollback mode is local-only/disabled: absence of the future diary selector keeps
the worker absent, while the Core route independently requires the exact protected
egress-binding digest. The job, runtime selector, and Core gate bind the same release,
archive, policy, style, persona, model, and role identities. Missing or mixed state
therefore rejects before provider egress while raw archive/chat behavior continues.
Existing history is never migrated or mined by this release; only newly archived
complete turns may enter a later activated job.

## Component boundary

- Core owns strict job/capacity/candidate validation and the dedicated internal HTTP
  route, using the existing provider adapter only under the diary role.
- Telegram runtime owns delivered-ack day closure, immutable job state, bounded worker,
  and append-only local commit.
- P10-B remains the trusted-time source; P08 owns active temporal-validity memory; P15
  remains inactive and does not duplicate prompt ownership; `/Benchmark` remains the
  sole Profile mutation lane; `/Check`, `/Diary`, P01 visual, V7.1, and P16 lineages
  retain their existing isolation.

This ADR authorizes no install, selector change, service restart, provider call, old
data migration, or Owner E2E. Those remain future T2 gates.
