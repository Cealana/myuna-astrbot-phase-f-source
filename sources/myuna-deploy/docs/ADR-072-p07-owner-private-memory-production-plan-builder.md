# ADR-072: P07 source-bound production plan builder

Status: T1 source-only, inactive. This ADR creates no live observation, strategy
state, plan, backup, ledger, preflight, attempt, archive, service action, or egress.

## Decision

The transactional runtime now has one production plan constructor. Caller JSON
may name only content-addressed candidate locations and the reviewed runtime
manifest/lineage evidence. It cannot provide policy digests, Program-boundary
digests, path roles, public prestate, mutation coverage, mutation operations, or
target bytes.

The constructor derives those identities from reviewed source constants and a
fixed protected observer. The observer uses only fixed generation13 release,
selector, service/container, epoch, RuntimeConfig, credential-semantic, calendar,
and P08 content-free projections. It never exposes credential values or private
turn, Profile, database, log, journal, provider, model, or channel content.

P08 supplies that projection through the authenticated, versioned
`status_content_free` operation. A fixed Owner-private scope and protected
RuntimeConfig determine the request identity. The reply contains only the exact
lifecycle watermark, bounded counts, completeness booleans, source/scope/time
binding digests, and nonce-bound response evidence. Private `snapshot_active`
context is not a valid plan input. Wrong scope/source/schema, stale or replayed
responses, unknown fields, unavailable transport, and bounded-count overflow are
typed rejections. The constructor binds the verified status identity and
watermark; existing P08 read/write and lifecycle behavior is unchanged.

## Complete production target

The target is a single typed full-mutation transaction. It binds new immutable
Core, Telegram runtime, and plugin release trees; Core binding/selector/gate and
memory drop-ins; Telegram config/drop-in; memory and diary selectors; and one
distinct empty archive/index/diary root. Existing unrelated files in each scanned
root are preserved in the exact prestate and target inventory. Unchanged reviewed
fixed paths are explicit `preserve` identities, not fabricated mutations.

Every add/replace/remove operation binds logical path, protected root, role,
before/after existence, type, SHA-256, size, UID, GID, mode, deterministic source,
input digest, order, and allowlisted ownership. Recursive release-tree staging
creates only bound mode-0550 parents, scans only regular files, rejects links and
special files, and prunes transaction-created empty parents during exact reverse
rollback.

## Fail-closed identity

The immutable policy set is derived from the calendar selector, approved
reflective-diary and historical-raw-recall contracts, inactive P15 single prompt
owner, and `/Benchmark`-only Profile confirmation gate. P01/P08/P09/P10/P15/P16
boundaries are source-hashed immutable no-mutation claims. Category/path swaps,
missing or additional production paths, wrong roots or roles, caller substitution,
old target-builder reuse, stale/replayed targets, and type/owner/mode/symlink drift
are rejected before a service command or any egress-capable step.

The successor inactive bundle imports the prior transactional runtime bundle and
manifest as immutable evidence. It does not reset or reinterpret the permanently
exhausted predecessor 2/2 or dual-state v2 1/1 lineages, and it creates no future
max-one namespace during T1.

## Source-bound after-payload package

The production constructor is invoked exactly once by `prepare-package`. Its
canonical plan and complete add/replace/remove target bytes are materialized into
one source-declared protected package namespace. Callers cannot supply an
`after_payload_root`, replace fixed identities, use a test helper, or select an
older target builder. The package identity binds the plan, mutation order, every
path/root role, target SHA-256/size/type/UID/GID/mode, exact source and bundle
manifests, P08 content-free status schema/source, immutable lineage digest,
strategy identity, schema/version, bounds, and package digest.

Materialization creates the namespace non-overwriting, writes through an
exclusive temporary sibling, verifies each regular single-link file after write,
fsyncs files and directories, writes the completion marker last, and atomically
finalizes the directory. Reopen verifies the complete inventory and every bound
byte/metadata identity before backup, formal preflight, or activation can derive
the internal target-byte mapping. Symlink, hardlink, ACL, owner, mode, type,
missing/extra file, stale source/plan, partial crash residue, replay, or package
substitution is a typed rejection. No partial package is resumed or relabelled.

Package receipts expose only status, counts, booleans, and digests. Payload bytes
and private content never enter receipts, audit output, or command arguments. T1
tests inject temporary roots; this phase creates no real package or future live
namespace.

## Production ordering and rollback posture

A later, separately authorized T2 must freshly bind this exact source/build,
protected public prestate, a non-overwriting backup, and exactly two identical
ready formal preflights. The existing runtime order remains protected staging,
complete file mutation, per-path read-back, full inventory and semantic
acceptance, daemon reload, Core, then Telegram. Any later failure permits only the
controller's one exact reverse rollback and terminal hard stop.

Effective V6 plus compressed generation13 remains the live rollback predecessor.
No old history is migrated or read. Historical recall and reflective diary remain
limited to their existing Owner-private purpose approvals and are not triggered by
plan construction or activation.
