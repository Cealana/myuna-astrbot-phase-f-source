# Owner Memory Retrieval v2 QQ Bridge Contract

Status: inactive R3D capability-binding repair candidate

## Purpose

This bridge allows the existing verified Owner QQ private-text conversation path to
use the independently versioned Owner Memory Retrieval v2 worker. It does not add
memory writes, restricted-memory access, cross-namespace access, tools, vision, or
external actions.

## Deterministic binding

`MYUNA_OWNER_MEMORY_PROTOCOL` selects the protocol and must match the fixed local
socket exactly:

| Protocol | Operation | Socket |
| --- | --- | --- |
| `v1` | `owner_memory.retrieve` | `/run/myuna-owner-memory-read-v1/worker.sock` |
| `v2` | `owner_memory.retrieve_v2` | `/run/myuna-owner-memory-read-v2/worker.sock` |

Unknown protocols and mismatched sockets fail during configuration loading. The v1
implementation remains installed in the same Core release as the rollback path.

The runtime capability scope is version-bound as well:

| Protocol | Required capability response scope |
| --- | --- |
| `v1` | `qq_owner_private_dev_readonly_memory_v1` |
| `v2` | `qq_owner_private_dev_readonly_memory_v2` |

The Capability loader and deterministic policy router accept both scopes only when
the existing Owner-private, non-restricted, read-only boundary remains exact. The
conversation runtime additionally requires the selected protocol and response
scope to match. A v1 scope with a v2 socket, or a v2 scope with a v1 socket, fails
closed before any model request.

## v2 request ownership

Core supplies only the bounded final user text, verified boundary, and request ID.
The v2 worker owns intent and horizon selection. Core must not send a v1 `mode`
field to the v2 worker.

## Data boundary

- Namespace remains fixed to `ns-owner-cealana-private` in the worker.
- Only `normal`, `user_confirmed`, non-restricted records may be returned.
- Maximum result count remains one for recent and three for deep retrieval.
- Internal memory IDs may be recorded only in metadata audit and are excluded from
  the model prompt and public response.
- Query text and memory text must not be written to the audit log.
- Worker failure degrades to a stateless QQ response; it must not become a write or
  a fallback to a broader memory source.

## Activation boundary

Repository application, immutable-release installation, and QQ activation are
separate transactions. This candidate does not authorize any systemd change or
service restart.

At activation time, v1 stays enabled and warm for the initial v2 observation
period. Activation changes only the Core immutable release, capability manifest,
late environment binding, and v2 socket state, then restarts only
`myuna-core@qq.service`.

## Rollback

Rollback restores the prior v1 Core drop-in, environment binding, and capability
manifest; restarts only QQ Core; stops and disables the v2 socket; and verifies the
prior Core release, v1 socket, QQ transport, and unchanged memory fingerprint.
The installed v2 release and receipts remain immutable for audit.
