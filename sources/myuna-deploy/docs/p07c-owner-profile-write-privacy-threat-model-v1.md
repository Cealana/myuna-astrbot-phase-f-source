# P07-C privacy threat model v1

| Threat | Required control | Failure behavior |
| --- | --- | --- |
| External provider receives Profile/input | Local-provider-only policy and literal loopback adapter | Reject before retrieval or model call |
| Group/other user invokes write | Authenticated Owner/private/Telegram capability intersection | Reject without candidate creation |
| Model invents a fact | Explicit-statement contract, strict schema, Owner-visible diff and confirmation | Candidate rejected or remains uncommitted |
| Temporal fact pollutes stable Profile | Temporal cue validator and P08 exclusion | Mark temporal-only and do not write |
| Duplicate/conflicting fact is silently merged | Deterministic normalized comparison plus topic conflict state | No commit; request Owner resolution |
| Model gains write authority | Analyzer returns data only; writer validates exact contract | Reject malformed candidate |
| Confirmation applies to changed candidate | Bind code to candidate digest, base digest and authenticated scope | Reject stale/mismatched confirmation |
| Replay or concurrent confirmation | One-shot state, lifecycle sequence and active-base check under lock | Idempotent exact replay or fail closed |
| Candidate leaks through audit/logs | Content-free allowlist; provider runtime logging remains disabled | Reject projection drift |
| Raw source message persists | Candidate store excludes source text and conversation history | Reject store schema containing raw source |
| Candidate remains indefinitely | Seven-day maximum TTL and explicit expiry state | Expired candidates cannot commit |
| Permission/symlink/type drift | 0700 directories, 0600 regular files, exact uid and no-follow opens | Writer unavailable; old revision remains active |
| Crash during publication | Atomic temp/link/rename/fsync sequence and recoverable pending marker | Recover exact transaction or keep old selector |
| Writer affects read availability | Separate units, read-only reader sandbox and narrow paths under one dedicated Profile identity | Disable writer and return reader to the preserved selector |
| Rollback deletes evidence | Logical restore only; immutable releases/ledger retained | Physical purge remains hard stop |

## Content retention

The active Profile and prepared candidate are local plaintext protected by Unix
permissions and systemd sandboxing; this design does not claim encryption. Ordinary
audit contains no raw input, candidate, Profile, reply, identity or confirmation code.
The candidate store contains exact candidate content and a private scope binding only
for the bounded confirmation window.
The local provider activation gate also requires loopback bind, offline mode and
`--log-disable`; a drifted provider command fails closed before writer activation.

## Independent review gate

Before T2, review the exact source diff, systemd identity/path permissions, all audit
fields, local-provider request construction, failpoints and rollback transaction. Real
Owner content must not be used in source tests or review artifacts.
