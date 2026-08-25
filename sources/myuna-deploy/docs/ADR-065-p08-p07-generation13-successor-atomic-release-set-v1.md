# ADR-065: P08/P07 generation-13 successor atomic release set v1

Status: T1 source candidate; source mainline and live activation are separately gated.

## Decision

Generation 13 is a new content-addressed P08/P07 release set. It binds the P07
Core release, Telegram runtime, authoritative external-epoch selector,
protected RuntimeConfig projection, exact effective credential projection, a
fresh `telegram-owner-private-external-d-reset-v7` schema-v3 epoch, the
Telegram plugin release and selected config, and the P08 release, selector,
service and socket units.

The accepted generation-11 reset-v5 state remains the immutable functional
rollback prestate. The failed generation-12 reset-v6 directory, releases,
journals, receipts and evidence remain preserved and are never renamed,
deleted, copied or reused. Generation 13 intentionally starts with an empty
external-authorized epoch; external-context continuity resets at this boundary.
Effective V6 remains selected, and P09/V7 is neither imported nor selected.

## Transaction and rollback

The only apply order is P07, Telegram plugin, then P08. A phase becomes
rollback-required before its first mutation. Failure or acceptance mismatch
executes the exact reverse order: P08, plugin, then P07.

P08 rollback restores its absent prestate. Plugin rollback restores the exact
prior selected-config bytes. P07 rollback restores the exact generation-11
Core/runtime/selector/release-set, ACL-aware epoch-bundle permissions and
functional service states. Rollback acceptance requires stable services and
non-increasing restart counters in addition to exact bindings and inventories.
All installed immutable artifacts, journals, receipts and failed state remain
preserved.

## Fail-closed gates

Preflight, post-start verification and rollback consume one canonical source of
truth and exact service identities. They reject selector ambiguity, a missing
or mixed release binding, credential multiplicity, RuntimeConfig drift,
schema/type/symlink/permission mismatch, a pre-existing reset-v7 path, partial
schema-v3 initialization, readiness drift, plugin/P08 inventory drift, replay,
service instability or exhausted attempt ledger.

Plan, journal and receipt projections contain only paths, digests, counts,
booleans, typed gates and service-state metadata. They contain no message,
Profile, epoch row, provider payload, model response or credential value.

## Source/live boundary

This ADR authorizes no mainline move, build installation, selector change,
service restart, provider/channel call or Owner E2E. A future combined T2 gate
must freshly rebuild all four artifacts, recompute the plan, prove exact
generation-11 rollback readiness and separately authorize activation.
