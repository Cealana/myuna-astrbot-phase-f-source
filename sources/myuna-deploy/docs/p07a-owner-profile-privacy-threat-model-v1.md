# P07-A Owner Profile privacy threat model v1

## Protected assets

- Exact Owner-authored profile bytes and their immutable approval digest.
- The distinction between stable Profile, session context, temporal context, capability
  results, and future write lifecycle.
- Owner/channel scope and the absence of third-party data.
- Audit/log boundaries that must remain content-free.

## Trust boundaries

The Owner authors and reviews the document. A future controlled installer copies exact
approved bytes into a private content-addressed release. The read-only loader validates the
release and builds a deterministic local index. Retrieval may return only bounded sections
to Core. Audit receives a separate projection, never the retrieval payload.

## Threats and controls

| Threat | Control | Failure behavior |
| --- | --- | --- |
| Blank or unreviewed template is deployed | Template has `template_only` and revision zero, both rejected by the strict schema | No profile loaded |
| File/receipt replaced together | Trusted config independently pins full digest; release name and receipt must match actual bytes | Reject digest/identity mismatch |
| Symlink, device, directory, owner, or mode drift | `lstat`, `O_NOFOLLOW`, inode recheck, exact regular-file/0700/0600/uid validation | Reject without fallback |
| Corrupt, unknown, or oversized input | Strict keys/schema/types, 64 KiB file limit, section and character budgets | Typed rejection, no context |
| Duplicate or conflicting facts | Unique section id, unique topic key, normalized-body duplicate detection | Reject whole profile |
| Broad query injects the whole profile | Positive relevance evidence, maximum three sections, 6000 context characters | Empty or bounded result |
| Profile text attempts prompt injection | Context labels all text as data, not instructions/permission/routing/write authority | Core must ignore embedded instructions |
| Days-scale status leaks into stable Profile | No temporal fields; Owner filling guide excludes deadline/current status/next action | Owner review blocks release; P08 remains separate |
| Raw text or content-derived identifiers leak to audit | New allowlisted projection excludes query/profile fingerprints, ids, digest, source refs, and text | Projection test fails closed |
| Legacy namespace receives Profile data | New namespace; no legacy socket/client/writer or fallback | `legacy_namespace_written=false` |
| Telegram/QQ scope is inferred from shared Core | No live consumer in P07-A; future integration requires authenticated scope to reach retrieval | No activation until reviewed |
| Gateway credential is mistaken for per-message Owner proof | Require a strict authenticated context produced only after signed event, durable claim and exact Owner-binding verification | Reject before retrieval |
| Profile is sent to the selected DeepSeek route | Independent provider egress allowlist structurally forbids DeepSeek | Do not call the Profile service or inject Profile text |
| Worker response forges provenance or query metadata | Core reparses exact fields, request/channel/query length, rank, revision and full source reference | Reject the entire response |
| Source stalls or disappears | Typed timeout/unavailable errors | Continue with no Profile context only after future consumer policy approves degradation |
| Third-party/private chat is copied into Profile | Owner-only authoring rule; no extraction/importer/history reader exists | Content is rejected at human review boundary |
| P07-B/P08/P10 behavior appears early | Package exposes only load/index/retrieve/projection; no write/time/capability API | Out-of-scope behavior is absent |

## Residual risks

- Unix modes protect local access but do not provide encryption at rest.
- Free-text semantics cannot mechanically prove that every sentence is long-lived or solely
  about the Owner; Owner review remains mandatory.
- A future Core integration must repair or explicitly redesign the current shared-channel
  scope before any live activation.
- Current Core has no non-DeepSeek model implementation authorized for Profile data, so
  conversation activation remains blocked after the service/source boundary is complete.
- Content relevance is deterministic lexical matching; false-empty results are preferred
  over broad disclosure.
