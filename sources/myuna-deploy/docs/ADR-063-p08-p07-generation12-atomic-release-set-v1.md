# ADR-063: P08/P07 generation-12 atomic release set v1

Status: T1 source candidate; mainline and live activation are separately gated.

## Decision

P08 is activated only as part of one content-addressed generation-12 release
set.  The release set binds the P07 Core release, Telegram runtime, external
epoch selector, protected RuntimeConfig projection, effective credential
projection, a new `telegram-owner-private-external-d-reset-v6` schema-v3 epoch,
the Telegram plugin release and selected config, and the P08 release, selector,
service and socket units.

Generation 11 remains immutable rollback prestate.  Generation 12 intentionally
starts with an empty external-authorized epoch; the Owner has accepted that
Telegram external-context continuity resets at this boundary.  No turn, summary
or other content is copied from generation 11.  Effective V6 remains selected;
P09/V7 is neither imported nor selected by this contract.

## Transaction and rollback

The only apply order is:

1. P07 Core/runtime/selector/protected release set and fresh epoch;
2. immutable Telegram plugin release and selected plugin config;
3. P08 immutable release, selector, service, socket and empty state.

Every phase is considered rollback-required before its first mutation.  A
failure or final acceptance mismatch runs the exact reverse order: P08, plugin,
then P07.  P08 state is moved intact to the plan-addressed evidence directory,
never deleted.  Plugin rollback restores the exact prior config bytes.  P07
rollback restores the exact generation-11 Core/runtime/selector/release-set,
epoch-bundle permissions and functional service states.  Installed immutable
code and all journals, receipts and failed state remain preserved.

Rollback is accepted only when the generation-11 functional observation is
restored, not merely when config bytes match.  Any rollback failure is a typed
hard stop and later reverse-order rollback phases are still attempted.

## Fail-closed gates

Preflight and post-start acceptance use the same content-addressed plan and
combined release-set ID.  Unknown fields, mixed source commits, wrong artifact
digest, generation-11 drift, non-empty or partial P08 prestate, existing reset-v6
path, credential multiplicity, RuntimeConfig drift, plugin inventory/config
drift, schema/type/symlink/permission mismatch, service instability, replayed
plan or exhausted attempt ledger are rejected.

Plan, journal and receipt projections contain only paths, digests, counts,
booleans, typed gates and service-state metadata.  They do not contain message,
Profile, epoch rows, provider payload, model response or credential values.

## Source/live boundary

This ADR authorizes no mainline move, install, selector change, service restart,
provider/channel call or Owner E2E.  A future T2 gate must freshly rebuild all
four artifacts, recompute the exact plan twice, verify generation-11 rollback
prestate and then explicitly select the combined release set.
