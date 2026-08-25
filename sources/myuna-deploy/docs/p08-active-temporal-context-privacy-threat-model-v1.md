# P08 Active Temporal Context v1 privacy threat model

Status: repository-only T1 candidate; synthetic data only

| Threat | T1 control | Failure result |
| --- | --- | --- |
| Stable P07 fact is misrouted into P08 | Exact temporal category allowlist and 31-day horizon | Reject, no write |
| Session transcript or raw message is retained | Proposal accepts bounded structured summary and opaque source ref only | Reject, no write |
| QQ gains writer authority | Authenticated writer allowlist contains Telegram only | `write_scope_rejected` |
| Unauthenticated or group context reads data | Owner/private/channel access policy | Empty/rejected, no fallback |
| Candidate self-publishes | Same-scope exact confirmation is mandatory | Candidate remains pending |
| Conflicting fact silently wins | One active fact per slot; conflict is non-retrievable | Existing active fact remains |
| Expired or future fact reaches prompt | Trusted-time gate plus read-time validity filter | No temporal block |
| Untrusted wall/message/filesystem time drives expiry | P08 exposes only a port; no concrete clock or fallback | `trusted_time_*` rejection |
| Database is replaced, linked or permission-drifted | Exact owner/mode/type/size/application/schema checks | Store refuses to open |
| Crash publishes a partial mutation | SQLite full transaction and event/state invariants | Rollback or unknown-commit stop |
| Retry duplicates an uncertain write | Scope/request/digest idempotency record | Return exact prior result or reject |
| Audit leaks Owner activity/content | Fixed content-free allowlist and coarse buckets | Projection rejects/omits field |
| P07/session/P10 receives an implicit write | Package-level no-import/no-write static gate | Candidate rejected |
| Model treats temporal text as instruction | Rendered boundary labels content as data, not authority | No authority expansion |
| Store grows indefinitely | Hard file/row/event/proposal ceilings | Fail closed; no auto purge |

The source foundation contains no real Owner content and does not claim encryption. A later
private deployment must use a dedicated identity and storage boundary; its exact ownership,
backup, retention, availability and rollback behavior are T2 design inputs. Physical purge
or destructive migration remains T3.
