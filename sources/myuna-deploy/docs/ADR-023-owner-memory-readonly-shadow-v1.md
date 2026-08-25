# ADR-023: Owner memory read-only Shadow v1

Status: accepted and activated in dev on 2026-07-17.

## Decision

The verified QQ owner private-text gateway may make a one-way, non-blocking
post-reply copy of at most 256 characters to a local Unix datagram socket after
the client reply connection has closed. An independent sidecar reads only the
fixed owner namespace and only non-restricted rows from the existing safe
PostgreSQL view.

The sidecar computes a deterministic `would_inject` set and writes a strict
metadata-only trace. The set has no return path to QQ Core, DeepSeek, prompts,
tools, replies, or memory writers.

## Required invariants

- QQ Core request body remains unchanged with `synthetic_memory:false`.
- Core long-term memory read/write and real-memory authorization remain false.
- The live SQL predicate fixes the owner namespace and excludes `restricted`
  before rows leave PostgreSQL.
- The gateway has no database role or PostgreSQL socket access.
- Shadow socket absence, queue pressure, permission errors, worker failure, or
  database failure cannot change the already-sent QQ reply.
- Trace stores hashes, counts, IDs, reason codes, and latency only; it never
  stores QQ text, memory text, quotes, rationales, accounts, or credentials.
- No TCP/UDP listener, model call, embedding, tool, or memory write is added.

## Activation and rollback

Activation requires the root-owned marker:

`/etc/myuna-gateway/qq-owner-memory-shadow-v1-enabled`

Rollback begins by deleting that marker. The Shadow socket and service can then
be stopped without touching Core, AstrBot, NapCat, or the memory database.

Approved plan digest:

`132daf8df609c234086c170c74094e791b13944c6b0889f5710fb870068b86fe`

The next gate, if any, is a separate approval for read-only prompt injection.
This ADR does not authorize that gate.
