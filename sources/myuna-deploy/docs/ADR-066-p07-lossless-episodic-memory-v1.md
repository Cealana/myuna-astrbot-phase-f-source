# ADR-066: P07 lossless archive, episodic recall, reflective diary, and memory seams

Status: T1 source-only candidate; inactive; no migration, writer, index population, provider
egress, service, selector, or live activation.

## Decision

Myuna's primary product purpose is truthful ultra-long-term shared memory. Storage and
indexing optimize for preservation and exact later location, never for deleting,
rewriting, or substituting derivatives for the original record.

The successor architecture has five non-flattened layers:

1. **Raw archive — original record.** Every complete delivered turn (one committed Owner
   input and its one delivered Myuna reply) is appended automatically to an Owner-private
   local lossless archive. Raw text is the sole semantic authority across session, epoch,
   and release boundaries. Failures and half-turns receive typed lifecycle records but are
   never represented as complete turns. This phase stores text only; for an image it may
   store only an already-authorized textual description plus content-free media identity
   and provenance, never image bytes. No retention or deletion action is implemented here.
2. **Episodic index and capsules — catalog and map.** A rebuildable derivative index binds
   immutable source turn pointers and digests. Turn, event, date, and interval capsules may
   locate candidates, but never become factual authority. There is no capsule-of-capsule,
   summary-of-summary, or cumulative rolling summary in this successor.
3. **Daily reflective diary — Myuna's authored perspective at that time.** Diary statements
   are explicitly typed as factual observation, interpretation/reflection, uncertainty, or
   intention. They bind calendar day and IANA zone, creation time, model/persona/release
   provenance, and source pointers where applicable. Entries and corrections are append-only
   revisions. Late backfill is labelled late. Missing or failed generation is a typed gap,
   does not block chat or raw archival, and cannot silently mutate Profile, /Benchmark, or
   P08. Diary text never satisfies an exact raw-source requirement.
4. **Profile and /Benchmark — confirmed durable semantic state.** Stable facts, inferred
   preferences, identity/relationship claims, and subjective Owner state remain
   proposal-first and confirmation-gated. Ordinary archive, index, diary, or interval data
   cannot silently promote them.
5. **P08 temporal-validity memory — active time-bounded facts.** P08 remains the only owner
   of active interval storage and expiry. All active non-conflicting items are intended to be
   supplied to every ordinary prompt as an always-present layer. Expiry removes prompt
   residency only; it never migrates, rewrites, or deletes raw. P07 exposes an append-only
   revision and expired-span episode seam so planned, observed, confirmed-started, changed,
   ended, and cancelled states remain distinguishable and raw-preferred later recall remains
   possible. P15 later owns prompt orchestration. P07 does not duplicate the P08 writer.

## Trusted time and calendar

P10-B remains the concrete clock owner and P08 remains its existing active-temporal
consumer. P07 consumes their public types/port; it does not create a clock or background
poller.

Each complete turn binds exactly one bounded-age sample plus synchronized/uncertainty
evidence, source and authority, boot identity, sequence/watermark, and received → committed
→ delivered monotonic order. UTC is authoritative. Local calendar representation preserves
the selected IANA zone and offset. The default zone is `Asia/Shanghai`; at minimum
`America/Los_Angeles` is supported with IANA DST rules, never fixed UTC-8.

If time is unavailable, stale, regressed, ambiguous, unsynchronized, or too uncertain, raw
archival still proceeds with an unresolved time-quality record. Exact calendar grouping,
expiry mutation, and diary finalization are prohibited until an append-only provenance-bound
correction is available. The original binding is never silently rewritten. Relative dates
resolve in the selected query/session zone and then map to a UTC interval; changing zone
changes query boundaries, not historical timestamps.

Every ordinary successor prompt must include a concise provenance-bound trusted current-time
context. An unresolved sample explicitly forbids exact-time claims rather than asking the
model to infer time from message text or model knowledge. This ADR does not claim the current
live compressed generation13 path already provides that context.

## Retrieval and context policy

Retrieval is RAW-PREFERRED. The derivative index first locates candidate source ranges;
bounded raw turns are then hydrated normally. Exact chronology, quotes/paraphrases,
commitments, numbers, negation, conflicts, ambiguity, low coverage, or broken pointers require
raw. If raw cannot fit, the system reports a typed coverage/budget limitation rather than
inventing certainty. Broad recap is transient and provenance-bound; it is never written back
as a cumulative summary.

The strict diagnostic lane projects every complete raw turn or fails closed. The production
raw-first lane keeps every complete raw turn while actual request characters, projection
characters, serialized bytes, exact/local token count, fixed context, current message, and
required output reserves fit. There is no hard 64-turn ceiling. Near capacity, only the
oldest raw turns leave the request window; storage remains unchanged. Relevant older raw plus
a contiguous recent raw tail is selected. The cumulative-summary generation13 path remains a
separate explicit rollback release, not a silent fallback.

Reviewed capacity oracles remain distinct:

- request contract: 200,000 characters including required output reserve;
- projection contract: 199,000 characters;
- serialized request: 1,198,096 bytes including reserve;
- local exact token oracle: 999,232 tokens including reserve.

The P08 active temporal-validity layer has its own deterministic reserved budget. It projects
all active non-conflicting items or returns a typed whole-layer overflow; it never silently
omits, summarizes, or expires an item to fit.

## Integrity, crash recovery, and privacy

- Raw turns, lifecycle records, receipts, time corrections, diary entries, and diary job
  events are append-only and replay-safe. Exactly-once identities reject conflicting reuse.
- A complete turn is written only after delivery acknowledgement. Crash-before-commit leaves
  no turn; crash-after-commit is recovered by the immutable receipt.
- Indexes are derivative and rebuildable. Stale/replayed indexes, source digest mismatch,
  broken pointers, conflicting capsules, incomplete coverage, and unresolved date identity
  fail closed before provider egress.
- Content-free audit contains only schemas, counts, booleans, categories, digests, source
  ranges, quality codes, and limiting oracles.
- Historical private raw egress is a separate digest-bound policy decision. Default mode is
  deny. This T1 candidate makes no provider call and selects no egress policy live.
- Raw archival never depends on P08 writer availability and creates no hidden double-write.

## Compatibility and downstream priority

The architecture preserves `/Check` isolation, V7.1 ordered multi-beat and observer-side
inquiry semantics, P16 no-polling/attempt lineage, P01 visual semantics, exactly-once delivery,
and no duplicate writer. Effective V6 and compressed generation13 live remain unchanged.

Program priority is:

1. long-term raw/episodic/diary memory plus temporal-validity and short-term context;
2. explicit provenance-backed search/research and later daily briefing;
3. progressively safe server/computer actions;
4. V7.1 live and other optimization after memory stability.

Items 2–4 are downstream interfaces only and are not implemented or activated by this ADR.

## Rollback and next gates

Source rollback is the exact pre-main refs. Runtime rollback, if separately authorized later,
is absence of this inactive release and continued selection of compressed generation13.
Before any T2, Owner must separately choose the historical raw egress mode, review private
path/permissions/retention and deletion policy, approve a migration/bootstrap strategy that
does not rewrite existing epochs, and authorize exact release/selector/service wiring and
organic E2E. A diary provider/job schedule and P08/P15 live integration are separate gates.
