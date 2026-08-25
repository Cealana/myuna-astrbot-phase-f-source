# ADR-067: P07 Owner-private lossless-memory runtime integration v1

Status: T1 source candidate, inactive until an independently verified T2.

## Decision

The authenticated Telegram Owner-private gateway is the temporary and unique
prompt owner while P15 prompt projection remains inactive.  When the additive
P07 memory selector is absent, the exact compressed generation13 parent remains
selected.  When an exact selector is present, new complete delivered turns are
written once to a new Owner-private local raw archive after delivery ack.  No
existing epoch, session, turn, summary, Profile, diary, or P08 row is imported,
rewritten, migrated, or deleted.

The product egress policy is
`p07-historical-raw-recall-egress-v1`: only the existing authenticated Telegram
Owner-private chain and existing DeepSeek route may send the minimum
source-bound complete historical turns relevant to the current question.
Expansion is bounded by the actual request-character, projection-character,
serialized-byte, token, fixed-context, current-turn, and output margins.
Cross-channel or cross-identity recall, full-corpus broadcast, image bytes,
Profile/DB/log/secret expansion, a new provider, or new external storage are
prohibited.  Insufficient budget or source coverage is typed
`coverage_incomplete` before provider egress.  Audit remains content-free.

## Runtime ownership

- P07 owns the lossless raw archive, append-only failure lifecycle, rebuildable
  episodic/date/event index, raw-preferred retrieval, and reflective-diary job
  ledger. Raw text is the sole factual authority.
- P10-B supplies exactly one bounded-age trusted-time sample per turn through
  the existing P08 service operation. P07 stores UTC, IANA zone, local
  representation, uncertainty, source/synchronization, boot identity, and
  monotonic sequence. Unavailable time preserves raw order with an unresolved
  binding and blocks exact relative-date claims and diary finalization.
- P08 owns active temporal-validity facts and expiry. Its all-active snapshot is
  projected all-or-none on every ordinary turn; overflow fails before provider
  egress. The activation selector freezes the current P08 lifecycle watermark;
  only later lifecycle records enter a bounded, cursor-checked derivative
  interval index. Every interval statement must resolve to an archived delivered
  `/temporal` source turn or remains blocked/unresolved. P07 does not duplicate
  or mutate P08 storage and does not silently import earlier P08 history.
- P15 remains inactive. The runtime binds
  `myuna.p07-p15-prompt-ownership-handoff.v1`; a future P15 activation must
  atomically replace, not duplicate, P07 prompt ownership.
- Profile and `/Benchmark` remain proposal-first and confirmation-gated. Raw,
  episodic derivatives, diary, and temporal-validity items cannot promote facts
  to Profile.

## Delivery and control isolation

One preparation is durably recorded before a reply carrying a delivery token.
Only a matching delivered outcome appends a complete turn. Cancellation,
provider failure, projection failure, and crash-pending work create typed
incomplete lifecycle records and never masquerade as complete turns. Replay is
idempotent and conflicting outcomes fail closed.

`/Check`, `/Diary`, and `/temporal` complete turns are also archived after
delivery ack because the archive is lossless. They carry an explicit
`control_isolated` provenance category. Ordinary model-history projection and
historical raw recall reject these control turns, preserving `/Check`, diary,
and P08 command isolation while retaining the original record. A temporal
command reuses the P10-B sample already bound to its P08 operation; other
control lanes request one snapshot solely for the turn-time binding. There is
no background polling or duplicate writer.

## Context, retrieval, and derivatives

All model-history-eligible complete raw turns are projected while every actual
capacity oracle fits. The runtime independently accounts the 200000-character
request contract, 199000-character projection contract, serialized bytes, and
input tokens, including fixed/current/output reservations. Near the boundary,
the runtime keeps source-selected
older raw turns plus a recent raw tail. It never silently enters cumulative
summary. Active cumulative summaries in the immutable parent are ignored by
the successor; compressed generation13 is a separate rollback release.

The index is rebuilt from raw authority. Turn capsules cover every complete
turn; date and conservative event capsules cover only contiguous non-control
turns with exact trusted time. Capsules locate candidates but never replace raw.
Relative dates are resolved in the bound IANA calendar zone. Missing time,
broken pointers, stale/replayed indexes, source digest mismatch, conflict, or
insufficient raw budget fails closed.

The diary is append-only and versioned. Its automatic pending job is created
after raw archival and cannot block chat or archival. Missing time leaves a
typed diary gap. Any future diary model output must distinguish factual
observation, reflection, uncertainty, and intention; it cannot rewrite an old
perspective, satisfy an exact raw-source requirement, mutate Profile, or mutate
P08.

Creating the pending job is in this runtime contract; sending historical raw
turns to a model for diary authorship is a separate purpose from question-time
historical recall and therefore requires its own digest-bound egress decision.
Until selected, pending/missing diary states are truthful and no model-authored
entry is fabricated.

## Privacy, filesystem, and rollback

Archive, journal, index, and diary roots are selector-bound to the exact service
UID/GID and private modes. Existing path, type, owner, group, mode, symlink, or
digest drift is rejected rather than repaired in place. Index crash sidecars are
promoted only after full verification against authoritative raw turns.

T2 must atomically bind the exact Core/runtime/plugin artifacts, immutable
generation13 parent release-set/selector/epoch, egress-policy digest, protected
RuntimeConfig, credential projection, P08/P10-B/P15 public identities, service
states, and new empty local roots. Rollback removes only the additive selector
and new local service wiring and restores exact compressed generation13. Raw
archive data created after activation is retained locally; rollback never sends
or deletes it. Existing history backfill/import requires a separate Owner
decision.

## Non-goals of this T1

No real private history is read, no provider/channel/model/health endpoint is
called, no old history is migrated, no diary is generated, no P08 state is
mutated, and no release is installed or selected. P09 V7.1 remains inactive;
P01/P16/legacy attempt lineages and evidence are immutable.
