# ADR-059: Active Temporal Context v1 source foundation

Status: accepted for repository-only T1 candidate

## Context

Myuna currently has three different context boundaries:

1. P07 Owner Profile stores stable Owner-authored facts and durable preferences.
2. The 128-message per-channel SQLite snapshot stores recent alternating dialogue.
3. P10-A defines neutral capability-runtime ports but has no live consumer or trusted-time
   provider.

None is the correct owner for days-scale information such as a current task, temporary
plan, deadline, waiting item, next action or short-lived constraint. Reusing any existing
schema would blur retention, authority, privacy and expiry semantics.

## Decision

P08 v1 is an additive Core package named `myuna_core.active_temporal_context`. It uses the
independent schema `myuna.active-temporal-context.v1` and content-free audit namespace
`active_temporal_context_v1`.

Allowed categories are exactly `current_task`, `short_term_status`, `temporary_plan`,
`next_action`, `deadline`, `waiting_item`, `temporary_constraint`,
`temporary_availability` and `short_lived_preference`.

Stable Profile facts, raw session messages, capability results, credentials, raw
messages/media, third-party private facts, exact live location and high-sensitivity
medical/financial/legal content are rejected. Stored text is always data, never an
instruction, permission, capability result or authority change.

## Time and validity

Every fact has authenticated source provenance plus `observed_at`, `valid_from`, optional
`valid_to` and required `expires_at`. All times are timezone-aware UTC instants. The maximum
`observed_at -> expires_at` horizon is 31 days. Future-valid facts are not retrieved before
`valid_from`; facts are excluded at `valid_to` when present, otherwise at `expires_at`.

P08 defines `TrustedTimePort`, `TrustedTimeSample` and monotonic guard semantics but provides
no real clock implementation. System wall clock, channel timestamps, filesystem/database
timestamps and model output are forbidden fallbacks. T1 uses only a deterministic fake.
P10-B must later provide the concrete trusted-time implementation before live expiry is
eligible.

## Authentication and lifecycle

Writer scope is authenticated Telegram Owner-private plus explicit memory-candidate intent.
QQ has no writer scope. T1 reader scope is also Telegram only; any future QQ read scope is
separately authorized and never implies write scope.

Every mutation is proposal-first and binds candidate bytes, scope, request, trusted time,
confirmation code and a one-to-30-minute proposal expiry. Accepted facts move through
active, superseded, conflicted, expired and revoked states. Exact duplicates return
`no_change`; conflicts never replace the current active fact; refresh/supersede create new
revisions; restore is permitted only from an eligible revoked fact after new confirmation.
There is at most one active fact per slot.

Physical purge, destructive migration and content erasure are not v1 lifecycle operations;
they remain a new T3 confirmation boundary.

## Private store

The source foundation uses a new private SQLite store with:

- application id `0x4D594154` (`MYAT`), user version 1 and exact schema label;
- a 16 MiB limit, 4,096 facts, 16,384 lifecycle events and 256 pending proposals;
- expected private parent/file ownership and exact `0700`/`0600` modes;
- no symlink following, no automatic repair/migration/export and no fallback;
- foreign-key, integrity, event/state and active-slot invariant checks;
- full transactions, exact request idempotency and explicit unknown-commit recovery.

Unknown schema, corruption, oversize, permission/type drift, time regression, duplicate,
conflict, stale/expired data, busy/timeout and crash/partial commit fail closed.

## Retrieval and audit

Retrieval is deterministic and model-free using exact filters plus normalized lexical
evidence. It selects at most six facts, 500 characters per summary and 2,400 characters in
the rendered block. Empty or untrusted-time results inject nothing. Read-time expiry is
immediate; a separate fake-time T1 mutation proves persisted expiry without activating a
live scheduler.

Audit contains only fixed operation/outcome/category counts, selected count, lifecycle
transition, length/duration buckets, retryable status, time-source class and fixed errors.
It never records content, raw query, ids, source refs, codes, digests, precise activity
timestamps, identity, private paths, provider/model fields or responses. It explicitly
states that P07, session, legacy memory and P10 were not written.

## Source-ready boundary

The T1 candidate includes only source, synthetic tests and these contracts. It adds no
conversation consumer, config field, socket, service, identity, private path, installed
release, selector, migration, channel/model/provider call or live expiry implementation.
It does not push, merge or deploy.

## Rollback

Repository rollback is removal or rejection of the isolated P08 candidate. No live or data
rollback exists because this phase creates no real store, release, service or Owner data.
