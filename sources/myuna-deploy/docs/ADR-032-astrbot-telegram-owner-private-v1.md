# ADR-032: AstrBot Telegram owner private-text boundary v1

Status: repository candidate only; not installed or activated

## Decision

Telegram is a separate Myuna channel, not another platform entry inside the
existing QQ/NapCat AstrBot instance.

The first release uses:

- channel kind `astrbot_telegram`;
- channel instance `telegram-owner-dev`;
- a separate AstrBot container and data directory;
- a separate plugin, signing secret, Unix socket, runtime config, identity
  binding, audit identity, rate limit, and revocation path;
- the existing canonical Owner principal and private namespace only after an
  explicit one-time Telegram binding ceremony.

## Initial capability boundary

Only an explicitly verified Owner private plain-text message may reach Core.
The following stay disabled:

- groups and channels;
- commands other than AstrBot's fixed `/start` onboarding response;
- media, vision, voice, files, stickers, and albums;
- memory writes and memory-candidate generation;
- tools, MCP, scheduler, system actions, and external operations;
- unknown users and bot senders.

The adapter stops every Telegram event before AstrBot can call a provider.
Rejected non-text or non-private events are silent. Transport failures return a
fixed content-free message and never include account IDs, message text, tokens,
signatures, or internal exception details.

## Identity

The numeric Telegram user ID is used only transiently to compute:

`HMAC(identity_pepper, "myuna-account-v1\0astrbot_telegram\0" + user_id)`

The raw ID must not enter Git, ordinary logs, prompts, documentation, or
receipts. Telegram and QQ fingerprints remain domain-separated even if their
raw numeric values happen to match.

## Secrets

The BotFather token is not an environment variable, command-line argument,
repository value, or approval payload. A later, separately approved local
no-echo intake helper will write it atomically into the Telegram-only AstrBot
data/config boundary. The plugin never reads the bot token.

## Network

Telegram uses outbound Bot API polling. No public inbound port is required.
The optional AstrBot WebUI remains bound to `127.0.0.1:6285`. Current outbound
reachability depends on the host TUN/proxy path and is therefore a monitored
runtime dependency, not an assumed guarantee.

## Rollback

Telegram rollback removes or disables only the Telegram container, socket,
runtime binding, Telegram capability, and Telegram secrets. It must not stop,
restart, rewrite, or revoke the existing QQ/NapCat channel.
