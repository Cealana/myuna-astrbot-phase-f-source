# ADR-020: verified owner QQ private runtime v1

Status: implemented as inactive source; activation requires an evidence-bound plan digest.

## Decision

The first live QQ runtime is intentionally narrow:

- Myuna's separate QQ account remains the channel endpoint through NapCat and AstrBot.
- Only the verified binding `binding-astrbot-qq-owner-cealana` may reach Core.
- Only private, plain-text messages are accepted.
- Group chat, media, memory read, memory write, tools, external actions, and system
  administration are disabled.
- AstrBot continues to stop its own LLM dispatch before forwarding a signed envelope.
- Myuna Core remains bound to `127.0.0.1`, on a separate `myuna-core@qq` instance and
  port `18081`.
- The gateway may connect only through Unix sockets and `127.0.0.1/32`.
- A distinct systemd credential authorizes the gateway to call the QQ Core instance.
- DeepSeek remains the only enabled provider, with a daily budget of USD 2.00.

## Identity and database boundary

The raw QQ account ID is present only in the incoming signed envelope and process
memory. The gateway derives the domain-separated HMAC fingerprint, then calls the
security-definer function `gateway_runtime.resolve_verified_binding`.

That function returns only the exact owner binding when all of these are true:

- principal is the active owner;
- namespace is active and owned by that principal;
- binding is verified and has `verified_at`;
- channel is `astrbot_qq`;
- the HMAC fingerprint matches.

The gateway database role still has no direct `SELECT` privilege on identity or
memory tables. Operational inbound storage contains only opaque event IDs, nonce and
payload hashes, timestamps, state, and a fixed outcome code. It never stores message
text, replies, raw QQ IDs, signatures, or raw nonces.

## Conversation context

Up to 12 alternating messages and 12,000 characters are retained only in gateway
process memory. The history disappears when the gateway restarts. This is short-term
conversation context, not Myuna long-term memory.

The first gate sends `synthetic_memory=false` to Core and does not start the retrieval
worker. It must never expose fictional Stage 5 memory to the real owner channel.

## Rate and failure behavior

The owner is limited to 12 accepted requests per ten minutes. Provider budget
enforcement remains inside Core. Failed identity resolution, tampering, replay,
unsupported content, or consent escalation returns a generic rejection. Core or
provider failure returns a fixed temporary-unavailable response without leaking
backend details.

## Activation and rollback

`scripts/activate_qq_owner_runtime.py` defaults to preview-only mode. Its digest binds:

- owner finalization evidence;
- Core and deploy Git commits;
- the operational source bundle checksum;
- migration, network, rate, model, capability, backup, and rollback scope.

Apply mode requires the exact user-approved digest. It creates verified pre/post
PostgreSQL backups in WSL and checksum-matched C-drive copies, applies migration
`0005`, generates a distinct Core token, installs the runtime units, starts the QQ
Core and socket, and recreates only the AstrBot container.

Initial activation does not enable boot persistence. If activation fails, services
and credentials are removed and migration `0005` is rolled back by exact version and
checksum. Identity rows are never modified by this operation.

After the first real QQ conversation succeeds, boot persistence is a separate change.
