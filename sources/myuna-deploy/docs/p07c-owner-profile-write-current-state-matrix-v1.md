# P07-C current-state capability matrix

| Capability | Verified current state | P07-C decision |
| --- | --- | --- |
| Stable Profile schema | v1 has four stable categories and strict limits | Reuse unchanged |
| Read retrieval | Dedicated read-only socket, bounded relevance and fail-closed loader | Reuse; provide only relevant sections to analyzer |
| Lifecycle | Immutable prepared/confirmed/published/revoke/restore ledger exists | Reuse as commit state machine |
| Exact candidate comparison | Full revision comparison and exact approval digest exist | Extend from Owner-authored to Myuna-prepared candidates |
| Authenticated context | Owner/private/channel/namespace binding exists | Require Telegram Owner-private exact scope |
| Memory candidate consent | Metadata field exists | Enable only for authenticated exact `/Benchmark`; `/Diary` is control-only |
| Write capability profile | Capability name exists | Parser currently forbids it; add a dedicated write scope |
| Local structured analysis | Local provider supports single-attempt `json_object` | Use only behind strict schema validator |
| Candidate persistence | Not implemented | Add private bounded TTL store without raw source message |
| Publication service | No channel-callable writer exists | Add separate least-privilege writer boundary |
| Active read refresh | Read worker loads one pinned release at startup | Add reviewed atomic selector refresh before live activation |
| Audit | Read and lifecycle projections are content-free | Add candidate analysis/write content-free projection |
| Owner confirmation UX | Manual exact-content approval exists outside channel | Add same-scope `/Benchmark confirm <code>` one-shot confirmation |
| Automatic extraction | Disabled | Remains disabled in v1 |
| Physical purge | Hard stop | Remains disabled |

## Current conclusion

P07-A/P07-B supply a strong storage and retrieval base, but no Myuna analysis or
channel-callable write path exists. The smallest correct implementation is an isolated
candidate analyzer and writer bridge; replacing the read service or introducing another
memory namespace would create unnecessary risk.

## Source-foundation result

The dedicated branch now contains the isolated candidate analyzer, strict protocol,
private TTL store, immutable publisher, dynamic read selector, writer socket, local-only
environment contract and rollback-capable activation transaction. All fixtures remain
synthetic. This document does not claim those changes are installed or live; commit,
release provenance, T2 activation and Owner Telegram E2E remain separate gates.
