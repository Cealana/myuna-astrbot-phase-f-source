# ADR-073: P07 Owner-day reflective diary v2

Status: source-only, inactive. This ADR supersedes civil-midnight diary closure
for any future v2 selection. It does not relabel or migrate the v1 diary.

## Decision

P07 defines an independently versioned, digest-bound Owner-day policy. The
reviewed default is `Asia/Shanghai` with a local `06:00` boundary and a
120-minute soft-close grace. The selector carries the IANA zone, local boundary,
grace, schema, and policy digest. Each job, preview, final, addendum, candidate,
and revision binds the policy, exact source-turn watermark, source digests,
trusted-time bindings, release/persona/model identity, and append-only revision.

An Owner-day is computed by converting authoritative UTC to the selected IANA
zone and comparing local wall time with the configured boundary. No fixed UTC
offset and no host timezone is used. A nonexistent or ambiguous boundary in the
selected zone rejects the policy. Switching a selector changes future grouping;
it does not resample or rewrite archived turns.

## Separate selectors and modes

The memory v4 selector owns lossless archive, dynamic raw-first context, recall,
and P08/P15 boundaries. It carries no diary provider identity. The diary v2
selector is separate and must bind the exact memory selector and Owner-day
policy. Absent or disabled diary selection means no diary state, worker, timer,
job, or diary provider egress. Mixed v3/v4 memory or v1/v2 diary selectors, an
orphan diary selector, or any stale/partial identity fails closed.

The currently reviewed production target is `disabled-memory-only`. It installs
the memory v4 selector and explicitly marks diary mode disabled. The old
Effective-V6 plus compressed-generation13 predecessor remains the exact rollback.
The v1 midnight diary is neither upgraded nor treated as v2.

## Closure, soft close, and revisions

Only a delivered complete Owner+Myuna turn advances Owner-day state. A typed
goodnight signal is admitted only on the authenticated Telegram Owner-private
path and becomes a soft-close candidate after that response is delivered. The
deadline is the earlier of grace expiry and the hard Owner-day boundary. A later
complete turn before generation clears the candidate. Duplicate delivery and
action signals are idempotent; conflicting replay, sequence gaps, time regression,
or policy drift reject.

The next local Owner-day boundary creates a hard-close requirement for the prior
day. Exact archive coverage is mandatory. Missing time/source coverage or any
capacity-oracle overflow yields typed pending/coverage-incomplete and no provider
call. Each rollover appends a content-free, digest-bound finalization requirement
to the crash-recoverable state; later Owner-days cannot erase an ungenerated prior
day. A soft-close result is not an irreversible closure. Later same-day turns
produce an append-only addendum; prior revisions are immutable. A final revision
may advance coverage and may supersede the preceding diary revision.

## Open-day preview

An exact Owner-private preview phrase may be admitted as a typed transport
request. A broader model choice must arrive through a future typed Core action;
string guessing is prohibited. Preview uses all eligible complete turns in the
current Owner-day through an exact as-of watermark, applies all reviewed capacity
oracles before egress, and creates an append-only private preview revision. It
does not close the day, replace a final diary, mutate Profile/P08, or send an
out-of-band message.

The provider boundary is the existing authenticated Telegram Owner-private
DeepSeek route and only the approved closed-day or open-day diary purpose. No
full-history corpus, image bytes, cross-channel identity, Profile/DB/log/secret,
new provider, or new storage is admitted. Receipts and audits contain only
counts, booleans, digests, categories, source ranges, and capacity results.
Closed-day and open-day-preview egress use distinct policy and binding digests;
neither can be substituted for the other.

## Crash and rollback

Owner-day state is a derived content-free snapshot backed by an append-only,
digest-chained journal. Journal completion is fsynced before an atomic snapshot
replacement; a missing/stale snapshot can be reconstructed from the journal.
Partial records, symlinks/hardlinks, ACL/type/owner/mode drift, duplicate identity
conflict, stale policy, or replay fail closed. Raw archive completion never waits
for diary generation, so diary failure cannot block chat or lossless history.

Rollback removes the independent v2 selector/state capability and restores the
exact compressed predecessor; it never rewrites raw turns or previous diary
artifacts. Existing history is not imported by activation.

## Deliberately remaining seam

This source boundary includes deterministic Owner-day grouping, jobs, capacity,
candidate validation, delivered-ack state, and typed explicit ingress. The
gateway still rejects selecting the v2 diary provider adapter; therefore a future
diary-enabled target requires a separate reviewed adapter/store/worker integration
before T2. In particular, automatic grace/boundary finalization requires a
source-owned one-shot P10-B trusted-time sample port; host wall time, stale
per-turn samples, background polling, and private P08 snapshot calls are not
acceptable substitutes. The memory-only target is provider-inert. A
model-initiated open-day preview likewise requires a separately typed Core action
seam and must not be simulated with phrase inference.
