# P07-B Owner Profile write lifecycle threat model v1

## Protected assets

- Exact Owner-authored candidate, approved and historical Profile bytes.
- Owner confirmation and the distinction between proposal and authority.
- The active release selector, immutable releases and recoverable prior state.
- Lifecycle metadata and content-free audit separation.
- The P07/P08/P10 and legacy-memory isolation boundaries.

## Threats and controls

| Threat | Control | Failure behavior |
| --- | --- | --- |
| Model output is treated as write authority | Only exact Owner-reviewed candidate digest plus separate confirmation artifact can publish | Candidate remains unconfirmed |
| Conversation is automatically extracted | No extractor, summarizer or channel writer exists in v1 source | No candidate is created |
| Candidate is based on stale active release | Event pins active base revision and digest; candidate revision must be base plus one | Reject transition |
| Candidate changes after confirmation | Publication rechecks exact candidate, receipt and confirmation digests | Reject publication |
| Revision is rewritten in place | Immutable content-addressed release; existing conflicting bytes reject | Preserve prior bytes and stop |
| Event log is reordered or truncated | Contiguous sequence, unique event ID and previous-event hash chain | Replay fails closed |
| Crash creates ambiguous event publication | Locked pending write, file fsync, no-overwrite hard-link publication, directory fsync and exact retry-bound replay | Reject unrelated or mismatched recovery state |
| Revoked revision remains selected | Selector verification intersects lifecycle state; revoked revisions are ineligible | Disable Profile retrieval |
| Active revision is deleted | Logical deletion rejects active target; physical purge is a separate hard stop | No deletion |
| Purge is silently reversible | Purged state cannot restore without separately supplied and re-approved exact bytes | Reject restore |
| Reversible deletion is mislabeled as erasure | `deletion_requested` is explicitly logical; only confirmed physical purge is deletion | Report accurate state |
| Raw content leaks to audit | Fixed projection has operation/result/count metadata only | Projection rejects unknown fields |
| Digest or identity becomes audit correlation | Audit excludes Profile/event IDs, digests, paths, identity and source refs | No audit emission |
| Legacy Owner Memory is updated too | No legacy DB role, socket, operation, namespace or adapter in lifecycle package | `legacy_namespace_written=false` |
| Stable Profile acquires days-scale status | Existing Profile schema categories only; candidate still passes strict loader and Owner review | Reject or return for revision |
| Capability result becomes memory directly | P10 result requires a separate privacy-reviewed projection and Owner confirmation | No write |
| DeepSeek reads candidate or Profile | No model call in write lifecycle; live read egress remains independently blocked | No provider payload |
| Ordinary Core process gains write access | Separate write-manager identity and paths; read worker remains read-only | Permission failure |

## Confirmation boundaries

A confirmation applies to one exact candidate or one exact lifecycle action. It does not
authorize later revisions, broad write access, automatic extraction, a provider, a channel,
or physical purge. Confirmation metadata may be retained privately for provenance, but its
digest is not copied to normal audit or sanitized handoff.

## Deletion boundary

Section removal is versioned and reversible through an older release until that older
release is separately purged. Logical deletion is reversible and retains bytes. Physical
purge is irreversible, target-specific and outside Standing Authority hard-stop exemptions.
Synthetic tests are not evidence that real Owner bytes were deleted.

## Residual risks

- Unix modes do not encrypt Profile, candidate or lifecycle data at rest.
- A malicious privileged administrator can read or alter local private state; digest and
  chain checks detect many changes but do not replace host trust.
- Human review is still required to distinguish stable Profile content from P08 temporal
  context and to detect subtle third-party data.
- Until a non-DeepSeek provider is explicitly authorized, a published Profile may be stored
  and served locally but cannot be injected into Myuna conversation prompts.
