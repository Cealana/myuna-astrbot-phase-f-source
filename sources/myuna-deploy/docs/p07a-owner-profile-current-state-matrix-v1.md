# P07-A current-state capability matrix

Evidence date: 2026-08-01 Asia/Shanghai

No health endpoint, model, channel, raw message, memory row, secret, or provider payload was
read to produce this matrix.

| Area | Classification | Current evidence | P07-A consequence |
| --- | --- | --- | --- |
| Core source | Verified current source | Core `main` is clean at `dc29df2`; owner-memory v2 package and Core client files are byte-identical to the selected live Core release | Safe as a compatibility reference, not as the new Profile schema |
| Deploy source | Verified current source | Deploy `main` is clean at `e817ecc` | New docs/template use an isolated worktree |
| v2 worker | Verified live | Service and socket are active; release package matches current source; installed service/socket/tmpfiles hashes match source | Freeze existing worker in P07-A |
| v2 Unix socket | Verified live | `/run/myuna-owner-memory-read-v2/worker.sock`, directory `0750`, socket `0660`, owner/group `myuna_memory_runtime:myuna` | Do not reuse for Profile |
| v2 runtime identity | Verified live/source | Dedicated OS/DB role `myuna_memory_runtime`; safe view grants SELECT and denies INSERT/UPDATE/DELETE | Existing read-only boundary is real but coupled to the legacy record schema |
| v2 namespace/operation | Verified source and live-selected bytes | `ns-owner-cealana-private`; `owner_memory.retrieve_v2`; verified Owner private text boundary | New Profile gets a separate operation/socket/audit namespace and no legacy dual write |
| v2 request/response bounds | Verified source and live-selected bytes | Query 256 chars; request 4096 bytes; response 65536 bytes; timeout 100-3000 ms; one recent or three deep records; Core context 12000 chars | Profile uses its own smaller 3-section/6000-char bound |
| v2 record schema | Verified live metadata/source | 28-column safe view includes assertion/event/quote/time/rationale/anchor/review fields | It mixes historical and temporal data and cannot represent the stable P07-A layer |
| v2 audit | Verified source and live-selected bytes | `owner_memory_read` records query fingerprint and hit ids; conversation audit records only counts/mode/degraded/version | New Profile audit excludes fingerprints, ids, source refs, and all text |
| Core consumer | Verified source and live-selected bytes | Retrieval runs in the generic conversation path whenever the runtime is enabled | Future Profile integration must receive an authenticated channel/scope gate before retrieval |
| Telegram consumer path | Verified live/source | Telegram runtime requires and calls `myuna-core@qq.service`; authenticated channel header is not passed into `engine.converse` | Existing manifest's QQ wording does not isolate retrieval from Telegram |
| QQ consumer path | Verified live | QQ socket is listening and starts its gateway, which calls the same Core | Channel separation cannot be inferred inside current conversation engine |
| v1 rollback | Verified live | v1 socket remains active/listening, v1 service is socket-activated/inactive, and v1/v2 env layers plus multiple private backups remain | Existing v2 rollback remains available and untouched |
| P03 session context | Verified live baseline | QQ and Telegram use separate 128-message/131072-character SQLite snapshots | Never copy or merge session rows into Profile |
| P10-A capability runtime | Verified current source only | Repository-only and has no source consumer | P07-A does not consume capability results |
| Historical P07 memo | Historical input only | S-03 proposed 0700/0600, digest/receipt, bounded retrieval, and separate gates | Re-evaluated here; it is not current authority |
