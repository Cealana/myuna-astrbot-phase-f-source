# ADR-054: Owner Profile write lifecycle v1

Status: accepted; source foundation implemented; baseline registered; channel writer disabled

## Context

P07-A established one Owner-authored, immutable, read-only Profile baseline. P07-B must
support controlled change without letting a model, provider, gateway, legacy memory writer,
or ordinary conversation mutate that baseline. It must also support confirmation, revoke,
removal, recovery and audit while preserving the P08 temporal-context boundary.

Creating a second free-form memory database would add a second retrieval source, duplicate
conflict semantics and recreate the legacy namespace problem. Rewriting an installed Profile
in place would destroy exact approval provenance and make rollback unverifiable.

## Decision

P07-B v1 is an immutable Profile revision lifecycle. A write is represented by a complete
candidate Profile revision, not an instruction for a model to edit individual facts.

The lifecycle is:

1. register the already Owner-approved baseline release;
2. prepare a complete candidate whose `profile_id` is unchanged and whose revision is the
   current revision plus one;
3. compute a content-free change summary and the exact candidate digest;
4. wait for the Owner to review the exact candidate and confirm that digest;
5. publish the exact bytes as a new immutable release and atomically select it;
6. preserve prior releases for rollback unless a separate deletion lifecycle is completed;
7. allow revoke or restore only through another Owner-confirmed lifecycle event; and
8. append each transition to a private hash-chained metadata ledger.

No event permits an in-place rewrite. Replaying the strict event log deterministically
reconstructs the active revision and every revision state. Sequence drift, duplicate event
IDs, broken hash links, base revision drift and invalid transitions fail closed.

Event schemas also bind allowed reason categories and base fields to each operation.
Preparing a candidate with the active release digest, restoring the already-active release,
or presenting a full next revision with no section-level semantic change is rejected as a
no-op rather than recorded as a successful lifecycle transition.

## Write authority

Only the Owner's confirmation of exact candidate bytes authorizes publication. The
confirmation artifact is separate from the candidate and is referenced by its own digest.
A conversation statement, model output, inferred preference, previous approval, similarity,
or gateway credential is never sufficient.

P07-B v1 source does not implement automatic extraction, summarization, model-authored
candidates or a channel write command. A future channel UX must still use authenticated
Owner-private context, deterministic confirmation and the same exact-digest gate. It may not
make the selected provider an approval authority.

## Revision and change semantics

The candidate contains the full stable Profile. Added, updated and removed sections are
derived by exact `topic_key` comparison. Audit may record only the three counts; it does not
record titles, bodies, keywords, topic keys, source refs, Profile IDs or digests.

Stable self-introduction, preference, goal and ongoing-project categories remain the only
allowed content. Deadline, next action, current status, observed time, validity windows and
expiry remain P08 data and are not added by this lifecycle.

## Revoke, restore and deletion

`revoked` makes a published revision ineligible. `restored` selects a preserved published,
superseded or revoked revision and supersedes the previous active revision. Neither operation
rewrites Profile bytes.

Section-level deletion is an ordinary new candidate revision with the section absent, then
the same exact review and publication flow. Historical release deletion is different:

- `deletion_requested` is a reversible logical state and is forbidden for the active release;
- `deletion_cancelled` restores the previous non-active state;
- `purged` records completion of a separately confirmed physical deletion; and
- a purged release cannot be restored unless the Owner separately supplies and re-approves
  exact bytes from an authorized backup.

Physical purge is irreversible and remains a hard stop requiring a new exact target and
impact confirmation even when Standing Authority is active. P07-B source tests may exercise
purge only on synthetic fixtures. This Work does not purge the Owner's real revisions,
receipts, approvals, backups or releases.

## Storage and crash recovery

Profile and candidate bytes remain only in Owner-private candidate or immutable release
directories with `0700/0600` or equivalent controls. Lifecycle metadata uses a separate
private root and contains digests, revision numbers, operation categories and confirmation
references, but no raw Profile or message text.

Events use canonical JSON, a contiguous sequence and `previous_event_sha256`. Each append
holds an exclusive ledger lock, verifies the prior chain, creates one mode-`0600` pending
file without overwrite, writes and fsyncs the exact canonical bytes, hard-links the exact
final event name without overwrite, removes the pending name, then fsyncs the directory.
Ordinary readers hold a shared lock and reject any pending marker.

Recovery is request-bound: only the deterministic pending name and exact event bytes for the
retried operation may resume. A pending-only event is revalidated against the prior chain
before publication; an exact pending/final hard-link pair is replayed before the pending name
is removed. Unrelated, partial, mismatched, over-linked or permission-drifted state fails
closed and is preserved for review. An existing exact event/release is idempotent; existing
conflicting bytes fail closed. Release publication and selector replacement must apply the
same no-overwrite, fsync and replay principles. Recovery never guesses that a write or
deletion completed.

## Audit projection

The audit namespace is `owner_profile_write_lifecycle_v1`. Its allowlist is limited to:

- outcome and fixed operation category;
- sequence and target revision;
- confirmation-present boolean;
- fixed release-effect and error categories; and
- `legacy_namespace_written=false` plus `raw_content_recorded=false`.

It excludes raw candidate/Profile text, query or message text, identity, path, event ID,
Profile ID, content/confirmation digest, source refs, provider/model payload and exceptions.
The private lifecycle ledger is not the audit projection and is never exported in a normal
handoff.

## Isolation

P07-B does not write legacy Owner Memory v1/v2, session context, P08 temporal context or P10
capability results. It does not change the 128-message session window. Retrieval continues
to consume one selected Profile release through the P07-A read-only worker.

The write manager and read worker use separate identities and permissions. The read worker
cannot append lifecycle events or select, revoke, restore or purge releases. Core/provider
conversation execution is not granted filesystem write access.

## Activation boundary

Source completion requires deterministic event/revision tests, malformed/tampered chain
tests, content-free projection tests, full relevant suites, independent diff review,
deterministic archives and rollback refs.

Installing the approved P07-A baseline and starting its read-only socket may be evaluated as
a separate bounded activation. Injecting real Profile data into conversation remains blocked
until provider egress is explicitly authorized and the authenticated Owner-private channel
gate is selected. P07-B channel writes remain disabled until their own UI, exact-confirmation
and recovery E2E are independently reviewed.

## Implementation status - 2026-08-01

- The immutable transition model, strict candidate comparison, content-free projection and
  crash-recoverable hash-chained ledger are implemented and covered by synthetic tests.
- The already approved revision 2 release is registered as sequence 1 through one
  `baseline_registered` event. Repeating the exact registration is idempotent.
- The private lifecycle root and ledger are root-owned mode `0700`; the single canonical
  event is mode `0600`, and there is no pending event.
- No revision 3 candidate, channel writer, automatic extraction, model-authored change,
  legacy/session/P08/P10 write or physical purge has been enabled. Physical purge remains a
  hard stop requiring a new exact-target and impact confirmation.
