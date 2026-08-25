# ADR-033: AstrBot Telegram Owner private runtime v1

Status: R2 repository-only applied; R3 work-only successor is not applied,
installed, or activated

## Outcome

Telegram is a second channel for the same canonical Owner, but it is not a
second name for the QQ binding. The proposed chain is:

```text
Telegram private plain text
  -> Telegram-only AstrBot container and plugin
  -> /run/myuna-telegram-gateway/owner.sock
  -> myuna-gateway-telegram
  -> myuna_telegram_gateway_app
  -> exact Telegram binding
  -> loopback Myuna Core
```

The existing principal `principal-owner-cealana` and namespace
`ns-owner-cealana-private` remain authoritative. Telegram adds only
`binding-astrbot-telegram-owner-cealana`. It never creates a second Owner
principal or namespace and never inherits authority merely because the same
person operates both accounts.

## Isolation

The candidate separates:

- Linux runtime identity: `myuna-gateway-telegram`;
- PostgreSQL runtime identity: `myuna_telegram_gateway_app`;
- AstrBot data directory and container;
- BotFather token;
- channel-signing secret;
- Unix runtime and challenge sockets;
- runtime config, markers, state, logs, audit identity, rate limit, and
  revocation path.

The Linux identity is not a member of the broader `myuna` group. Direct Core
imports use a read/traverse user ACL applied only to the exact immutable Core
release selected for this channel. Both Telegram service and socket unit
templates are rendered against the same immutable Gateway release before
installation.

The PostgreSQL role has no direct table access. It can call only three
Telegram-specific security-definer functions. Those functions hard-code
`astrbot_telegram`; the caller cannot redirect them to the QQ channel.

The runtime config also requires both the exact channel kind and exact channel
instance. A signed QQ envelope, group event, media event, bot event, stale
event, unexpected instance, memory-candidate request, or tool request fails
closed.

## Token handling

The BotFather token is never accepted in chat, an approval string, a command
line, an environment variable, Git, or a receipt.

The proposed Windows helper:

1. collects the token through `Read-Host -AsSecureString`;
2. starts a fixed WSL helper without token arguments;
3. writes the token only to redirected stdin;
4. clears the unmanaged BSTR after the helper exits.

The WSL helper validates the format and writes a root-owned `0600` authority
secret atomically. AstrBot 4.26.6 currently reads `telegram_token` from
`cmd_config.json`, so a separate renderer must copy the token into the
Telegram-only AstrBot config. That rendered config is also `0600`, has no
provider, no provider source, no AstrBot admin ID, no command registration,
no web search, and no proactive scheduler capability.

This duplication is an AstrBot adapter requirement, not permission to place the
token elsewhere. Receipts contain neither the token nor a token-derived hash.

## One-time Owner discovery and verification

Telegram bots cannot initiate a private conversation with an arbitrary user.
The local discovery helper therefore runs before the Telegram AstrBot poller:

1. it verifies the token with `getMe`;
2. requires that no webhook is active;
3. discards pending updates;
4. displays a fresh one-time `/start <challenge>` command locally;
5. waits only for that exact command from a new private update;
6. reads the numeric sender ID only in process memory;
7. derives the channel-separated HMAC fingerprint;
8. persists only the fingerprint and short-lived discovery evidence, never the
   challenge or raw ID.

The raw numeric ID is never written or printed. The public preview shows only
the first and last eight fingerprint characters.

AstrBot itself consumes `/start` and returns `start_message`, so discovery
cannot share the Bot API polling token with a running AstrBot instance. The
later installer must enforce mutual exclusion.

After discovery, the ceremony is deliberately split:

1. preview pending binding and obtain an exact plan digest;
2. after explicit approval, insert only one pending Telegram binding;
3. generate a one-time challenge without printing it;
4. switch the plugin temporarily to the challenge socket;
5. verify a private plain-text challenge from the same fingerprint;
6. preview a separate finalization digest;
7. after explicit approval, promote only that binding to `verified`;
8. remove the challenge code, config, marker, and socket;
9. leave the Telegram runtime disabled until a separate activation approval.

The repository contains pure SQL builders and challenge/runtime contracts. It
intentionally does not contain an authorized live database executor.

## Initial capability boundary

The first activation, when separately approved, is limited to verified Owner
private plain text. Disabled by default:

- group chats and channels;
- media, files, voice, stickers, albums, and vision;
- memory writes and memory-candidate generation;
- tools, MCP, scheduler, system actions, and external operations;
- AstrBot providers and AstrBot LLM dispatch;
- unknown users and bots.

Memory read is also disabled in this R2 candidate. It may be enabled later only
through an explicit channel capability update after the text-only chain passes.

## Core credential boundary

R2 correctly refused to copy or reuse the QQ credential, but the running Core
accepted only one bearer credential. The R3 successor resolves that prerequisite
with a channel-scoped multi-client Core contract:

- `qq_owner_core_token` is bound to `qq-owner-private + astrbot_qq`;
- `telegram_owner_core_token` is bound to
  `telegram-owner-private + astrbot_telegram`;
- both Gateways send the two fixed identity headers;
- token and headers must resolve to the same configured identity;
- token values must be distinct;
- mixed legacy and scoped Core configuration fails closed.

R3 stages the Core environment and credential drop-in outside live `/etc`.
Inactive installation must not apply either file. A later journaled Core
activation requires its own digest, rollback, and QQ regression check.

## Network

Telegram uses outbound HTTPS polling to `api.telegram.org`. No public inbound
port is opened. The WebUI remains loopback-only at `127.0.0.1:6285`.

PandaFan, Tailscale, Windows routing, firewall, and remote-control settings are
outside this candidate. Their state is a monitored external dependency and is
not modified by this work.

## Staged implementation

1. R2 repository-only application: source, tests, docs, no runtime effects.
2. R3 repository-only application and immutable Core/Gateway release builds.
3. Inactive installation: users, files, units, and empty directories; all units
   disabled/inactive, no marker, no secrets, and live Core configuration
   untouched.
4. Database foundation transaction and independent peer mapping.
5. Separately approved local generation of three independent channel secrets.
6. Local no-echo Bot Token intake and fresh AstrBot config render.
7. One-time scoped `/start <challenge>` discovery while AstrBot Telegram is
   inactive.
8. Pending binding transaction after exact digest approval.
9. One-time private challenge and separate finalization approval.
10. Journaled Core multi-client migration with QQ rollback retained.
11. Text-only Telegram runtime activation and real acceptance test.

Every state-changing stage has a new digest and an independent rollback.

## Rollback boundary

Telegram rollback may remove or disable only:

- the Telegram binding;
- Telegram database role and wrapper functions;
- Telegram container/data/config;
- Telegram system users, sockets, services, markers, state, logs, and secrets;
- Telegram-specific Core credential or dedicated Core instance.

It must not restart, rewrite, revoke, or delete the QQ/NapCat path, canonical
Owner principal, canonical Owner namespace, Owner Memory, Definition, models,
network, remote access, or Minecraft.
