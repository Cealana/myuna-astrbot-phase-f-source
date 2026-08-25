# ADR-013: synthetic memory in the loopback development Core

Status: approved for bounded dev testing on 2026-07-16.

## Decision

Connect the existing CPU-only retrieval worker to Myuna Core through its
owner-only Unix socket. Retrieval is performed only when an authenticated test
request explicitly sets `synthetic_memory=true`.

The searchable corpus is the existing fictional fixture at a fixed SHA-256 and
fixed synthetic time. Worker hits contain identifiers only; Core independently
maps the single top-ranked identifier back to the checksum-verified fixture and
rejects unknown, tombstoned, out-of-scope, or multiple records. Replies based on
that record must explicitly call it synthetic or fictional test data and may not
invent details absent from the record.

## Non-authorizations

This change does not import conversations, Skill source material, Notion data,
or any personal record. It does not enable memory writes, extraction,
consolidation, confirmation, forgetting, correction, automatic retrieval,
operational-record access, tools, AstrBot, or an external listener.

## Runtime boundaries

- Core remains on `127.0.0.1:18080` with Bearer authentication.
- Retrieval uses `/run/myuna-retrieval-dev/worker.sock`; there is no memory TCP
  port.
- The worker remains disabled at boot, private-networked, CPU-limited, and
  synthetic-only.
- The embedding model runs offline at its pinned revision and unloads after its
  idle timer.
- Audit records contain a query fingerprint, hit identifiers, mode, duration,
  and outcome, never query or memory plaintext.
- Any worker, checksum, schema, scope, or disclosure failure stops the request
  before a response is accepted.
