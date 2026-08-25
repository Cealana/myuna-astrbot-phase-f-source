# ADR-071: P07 Owner-private memory transactional runtime adapter

Status: T1 source-only candidate. Inactive; no live namespace, plan, backup, ledger,
preflight, attempt, service mutation, provider call, or data migration is created by
this ADR or its build.

## Decision

Add `p07-owner-private-memory-transactional-runtime-adapter` as a production-bound,
non-resetting wrapper around the accepted full-mutation engine and transactional
controller. It is a new source identity, not a replacement or relabel of the
exhausted `p07-policy-overlay-v1` (2/2), dual-state recovery v2 (1/1), or the
earlier T2 invocation that stopped before state creation.

The future runtime strategy is
`p07-owner-private-memory-transactional-runtime-max1`. Its state and backup roots
are unique, its maximum attempt count is exactly one, and a pre-existing root or
namespace is rejection evidence rather than resumable state. T1 contains only the
source contract and an inactive deterministic bundle.

## Bound identities

Every reviewed runtime plan binds:

- exact Core commit/tree and Deploy commit/tree from the accepted inactive bundle;
- the adapter bundle and manifest, immutable parent controller bundle and manifest,
  and full-mutation bundle, manifest, and source identities;
- the structured predecessor/v2 lineage evidence and the independently accepted
  combined terminal-evidence digest;
- the complete typed add/replace/remove mutation set, inventories, protected roots,
  and exact public service/container identities;
- approved calendar-zone, diary egress, historical-raw recall, prompt-owner, and
  Profile-confirmation policy digests plus immutable P01/P08/P09/P10/P15/P16
  boundary projections;
- unique plan-bound state, staging, journal, backup, attempt, and receipt paths.

Missing, stale, replayed, substituted, partially mixed, symlinked, or unexpected
identities fail closed before service commands or any egress-capable step.

## Modes and ordering

The canonical CLI exposes only: offline self-test, plan contract, backup contract,
ledger creation, formal preflight-only, activation, and postflight. Requests must
be strict canonical ASCII JSON with exact fields. External commands are injected
through an allowlisted runner; no legacy/v2 activation command can be dispatched.

Future activation ordering is:

1. verify immutable plan, non-overwriting backup, max-one ledger, and two identical
   ready preflights;
2. verify all protected staged bytes and metadata;
3. consume attempt 1/1, stop the exact target units, atomically apply every path,
   read back each path, and accept the complete target inventory and semantics;
4. daemon reload, start/verify Core, then resume/verify Telegram;
5. persist an immutable content-free terminal receipt.

No provider/channel/model/health command exists in the allowlist. No egress-capable
step precedes full filesystem target acceptance.

## Crash, replay, and rollback

The max-one ledger is exclusively created, mode/UID/GID/inventory checked, and can
move only from 0 to 1. Its attempt receipt is immutable. Plan-specific journal,
staging, filesystem journal, attempt, and terminal receipt names are the only
allowed state-root entries; arbitrary prefix lookalikes are rejected.

The parent transaction journal preserves the original typed activation cause and
allows at most one exact reverse rollback. Rollback restores all add/replace/remove
paths and protected roots in reverse order, reloads units, restores Core then
Telegram, and verifies the exact functional predecessor. A failure before attempt
consumption is typed `pre_attempt_failed`; it is never reported as rollback
verified. Rollback failure remains a terminal hard stop with both typed causes.

## Privacy and ownership

The adapter handles only public/fixed projections and content-safe byte copy/hash
boundaries. Receipts contain categories, counts, booleans, digests, and state
classes only. Raw/private chat, Profile, DB rows, log or journal bodies, secrets,
credential values, provider payloads, and model/channel content are excluded.

P07 owns this adapter. Core is unchanged. P01/P08/P09/P10/P15/P16 and legacy
attempt lineages are immutable inputs and cannot be consumed. Existing data is not
migrated, rewritten, or backfilled.

## Rollback posture and later gate

The exact live predecessor remains Effective V6 plus compressed generation13.
This source has no live authority. Any later T2 requires a new exact source/build
decision, fresh public prestate, a new non-overwriting backup, exactly two identical
ready formal preflights, and separately authorized activation. The source identity
does not itself create or authorize that state.
