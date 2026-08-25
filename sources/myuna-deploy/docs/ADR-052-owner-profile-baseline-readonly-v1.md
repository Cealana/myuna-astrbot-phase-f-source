# ADR-052: Owner Profile Baseline and read-only retrieval v1

Status: accepted; implementation status updated below

## Context

The existing Owner Memory v2 service is a historical-record retriever. Its fixed
namespace, record schema, recent/deep planning, and prompt projection include event time,
assertions, quotes, rationales, and anchors. It is therefore not the stable Profile layer
required by P07-A. Its Core hook is also in the shared conversation path used by both QQ
and Telegram even though the current capability manifest names a QQ-only scope.

P07-A must not turn that mismatch into a new implicit channel or identity grant. It must
also remain separate from 128-message session context, P07-B writes, P08 temporal context,
and P10 capability-result projection.

## Decision

P07-A v1 uses an additive, repository-only package named `myuna_core.owner_profile`.
There is no conversation consumer, socket, service, database writer, deploy step, or live
activation in this phase.

The Profile document is strict TOML with these exact top-level fields:

- `schema_version = 1`
- `document_type = "owner_profile_baseline"`
- `profile_id`: stable safe label
- `profile_revision`: positive integer
- `sections`: one to 32 section tables

Each section has exact fields `section_id`, `topic_key`, `category`, `title`, `body`, and
`keywords`. Categories are limited to:

- `self_introduction`
- `long_term_preference`
- `long_term_goal`
- `ongoing_project`

`section_id` and `topic_key` are unique. Repeated normalized body content is rejected;
repeated `topic_key` with different text is a structural conflict and is rejected. The
schema intentionally has no observed time, validity window, expiry, current status,
deadline, next action, source message, confidence, model output, or third-party identity
field. Those belong to P08 or are excluded entirely.

## Private storage and approval

The future private location is:

`/var/lib/myuna-owner-profile-v1/releases/r<revision>-<sha256>/`

It contains only `profile.toml` and content-free `receipt.json`. The release directory is
mode `0700`; both files are mode `0600`; all are owned by a future dedicated
`myuna_owner_profile` account. This account and location are not created in P07-A source
foundation.

The trusted runtime configuration must name the exact release directory and independently
pin the full SHA-256. The loader verifies path type, owner, mode, release name, profile
digest, byte count, schema, revision, section/category counts, and receipt equality. A
receipt alone is not authority because an attacker able to replace both files could forge
it. Rollback selects a previously Owner-approved immutable release and pinned digest; it
does not edit or delete the current release.

This design does not claim encryption. Files are local plaintext protected by Unix
ownership and mode until a separate encryption design is approved.

## Retrieval and provenance

Retrieval is deterministic and model-free. It normalizes Unicode, indexes title/body,
Owner-supplied keywords, topic keys, and fixed category cues, then returns only sections
with positive relevance evidence. The query is at most 256 characters. At most three
sections and 6000 context characters may be returned. Empty relevance produces no Profile
context.

Every selected section carries a source reference containing profile id, revision,
section id, and exact profile SHA-256. The context states that Profile text is data, not an
instruction, permission, recent-status feed, or write request.

Future transport, if activated after Owner review, must use a new operation and socket such
as `owner_profile.retrieve_v1` and `/run/myuna-owner-profile-read-v1/profile.sock`. It must
not reuse `owner_memory.retrieve_v2`, `/run/myuna-owner-memory-read-v2/worker.sock`, or
`ns-owner-cealana-private`.

## Privacy projection

The only accepted audit namespace is `owner_profile_read_v1`. Its projection contains
outcome, schema/revision metadata, selected count, selected category counts, query-length
bucket, duration, and typed error category. It excludes raw profile, raw query, query or
profile fingerprints, profile/section ids, source refs, identity, message, provider
payload, retrieved text, and model response. It explicitly records that no memory write or
legacy namespace write occurred.

## Fail-closed behavior

- Unknown schema, malformed TOML/JSON, duplicate ids/content, topic conflict, oversize
  content, digest/receipt mismatch, unexpected keys, and unsafe query are rejected.
- Missing/unreadable source, timeout, and unavailable source return typed retryable
  degradation and no Profile context.
- Symlink, non-regular file, owner drift, or mode drift is rejected without fallback.
- There is no fallback to the legacy namespace, PostgreSQL view, session history, P08, or
  capability results.

## Isolation and deferred work

- P03 session context remains per-channel rolling conversation history and is not copied
  into Profile.
- P07-B owns write proposals, confirmation, amendment, undo, deletion, recovery, and write
  audit. None are implemented here.
- P08 owns days-scale facts, observed time, validity, expiry, current state, deadlines, and
  next actions.
- P10 capability results require a separate privacy-reviewed projection and cannot write or
  extend Profile through this package.

P07-A remains `SOURCE_READY_WAITING_OWNER_PROFILE` after source review. A real Owner
profile, live service, Core integration, restart, and Owner-channel E2E require a later
boundary statement in the same Work task.

## Implementation status - 2026-08-01

- The Owner-approved revision 2 exact bytes are installed as an immutable release under a
  dedicated inert identity. A root-controlled selector pins the exact data and code release.
- The local read socket is enabled and the service passed content-suppressed selected and
  empty-result probes, while the live conversation path remains disconnected.
- The current state is `LOCAL_READ_SERVICE_READY_PROVIDER_EGRESS_BLOCKED`: no Profile text
  has been sent to a model or channel, and the external DeepSeek route remains forbidden.
