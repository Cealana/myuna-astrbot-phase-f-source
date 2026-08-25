# ADR-012: v5 loopback-only development Core

Status: approved for dev on 2026-07-16.

## Decision

Activate the immutable Definition v5 release only in `dev` and run Myuna Core
on `127.0.0.1:18080`. The HTTP conversation endpoint requires a generated
Bearer token delivered through a systemd credential. DeepSeek is the only live
provider and retains the USD 2.00 daily budget gate.

This gate authorizes conversation only. Long-term memory reads and writes,
tools, vision, external data and actions, system administration, AstrBot/QQ,
LAN/Radmin exposure, staging, and production remain disabled.

## Safety properties

- Definition files come from a hash-verified, non-writable release tree.
- The active path is an atomic environment-specific symlink; source material is
  never used as a runtime path.
- The capability manifest is bound to the exact Definition build.
- Both the provider key and loopback token are root-owned source credentials;
  neither appears in Git, environment files, logs, or status responses.
- Prompts and replies are not written to the audit log. Only request IDs,
  routing, token usage, cost, response length, and outcomes are retained.
- The unit remains disabled at boot during this test gate and can be stopped
  without affecting PostgreSQL, Minecraft, or the Definition repository.

## Next gate

Synthetic memory retrieval may be connected later through the owner-only Unix
socket. It requires a new capability manifest and does not authorize importing
real data or writing any memory.
