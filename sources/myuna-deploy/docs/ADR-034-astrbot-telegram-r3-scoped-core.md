# ADR-034: AstrBot Telegram R3 scoped Core and activation boundary

Status: repository contract; runtime not installed or activated

## Decision

QQ and Telegram use the same Myuna Core but never the same Core credential or
implicit client identity.

```text
QQ Gateway
  -> qq_owner_core_token
  -> X-Myuna-Client-Id: qq-owner-private
  -> X-Myuna-Channel-Kind: astrbot_qq

Telegram Gateway
  -> telegram_owner_core_token
  -> X-Myuna-Client-Id: telegram-owner-private
  -> X-Myuna-Channel-Kind: astrbot_telegram
```

Core loads a fixed registry from credential names, not secret values in an
environment file:

```text
qq-owner-private:astrbot_qq:qq_owner_core_token,
telegram-owner-private:astrbot_telegram:telegram_owner_core_token
```

Authentication succeeds only when the bearer token and both fixed identity
headers select the same registry entry. Swapped token files, duplicated token
values, unknown channels, duplicate client IDs, missing headers, mixed
legacy/scoped configuration, and ambiguous registry entries fail closed.

The existing single-client setting remains code-compatible only to support a
journaled migration and rollback. Live activation must replace it rather than
mixing both forms.

## Core migration boundary

The renderer accepts exactly one existing line:

```text
MYUNA_DEV_TOKEN_CREDENTIAL=qq_owner_core_token
```

It replaces only that line and preserves every other byte-level line choice.
It rejects missing, duplicate, unexpected, or already-scoped declarations.

The Telegram Core credential drop-in contains only one additional
`LoadCredential=` directive. During inactive installation, both the rendered
environment and drop-in are staged under `/opt`; neither enters live `/etc`.

## Local secrets

Four secret values are involved, and none may appear in Git, chat approvals,
command-line arguments, environment variables, logs, or receipts:

- BotFather Bot Token, entered later through the no-echo Windows-to-stdin helper;
- Telegram channel-signing secret;
- Telegram identity pepper;
- Telegram-to-Core token.

The latter three are generated independently on the server by a root-only
initializer. It is create-only, uses atomic target creation, rejects existing
or symlink targets, rolls back partial creation, and prints only fixed secret
names. It does not echo or hash secret values.

The Linux gateway process and the AstrBot Telegram container use the same
dedicated no-login identity, `myuna-gateway-telegram`. The container receives
that account's numeric UID/GID. No second, implicit `myuna-telegram` account is
allowed.

## Owner discovery

Plain `/start` is no longer authority-bearing. The local root helper:

1. validates the Bot Token with `getMe`;
2. requires an empty webhook URL;
3. drains stale updates;
4. generates and locally displays `/start <one-time challenge>`;
5. accepts only that exact command from a non-bot private sender whose sender
   and chat IDs match;
6. persists only a channel-separated HMAC fingerprint and short-lived evidence.

The challenge and raw Telegram ID are never stored. Discovery and AstrBot
polling are mutually exclusive.

## Inactive installation

`telegram_r3_inactive_install_contract.py` defines the next state-changing
transaction. It binds formal Core/Deploy commits and immutable release digests,
then permits only:

- creation of the no-login `myuna-gateway-telegram` identity;
- installation of content-addressed Core and Telegram Gateway releases;
- deterministic rendering of both Telegram service templates and both socket
  templates against those exact release roots;
- a user ACL granting `myuna-gateway-telegram` read/traverse access only to
  the exact Core release used by this channel; the identity is not added to
  the broader `myuna` group;
- staging of Core migration candidates outside live `/etc`;
- installation of Telegram-only units and empty runtime directories;
- one `daemon-reload`;
- verification that all Telegram units remain disabled/inactive, both approval
  markers are absent, and the secrets directory is empty;
- a non-sensitive receipt.

It explicitly forbids token intake, secret generation, Telegram API calls,
identity discovery, database schema/role/grant/row changes, Core selection,
live Core environment or drop-in writes, and every service start/restart.

The Telegram database migration, peer-auth role, grants, and verification are
a separate post-install gate. They require a verified logical backup and their
own approval digest before discovery or pending binding can run.

The source `.service` and `.socket` files are templates, not installable live
units. They use only `@CORE_RELEASE_ROOT@` and
`@GATEWAY_RELEASE_ROOT@`. The R4 renderer accepts only lowercase 64-hex
release digests and derives:

```text
/srv/myuna/releases/core/<core_digest>
/opt/myuna/telegram-gateway/releases/<gateway_digest>
```

It rejects mutable repository paths, the legacy `/usr/local` Telegram layout,
`current`/`latest` aliases, unexpected placeholder counts, extra `ExecStart`
directives, unresolved placeholders, noncanonical `PYTHONPATH` values, and
unexpected socket paths or groups.
The inactive-install plan binds both template and rendered SHA-256 values.
Only the rendered units may later be staged and installed; the templates must
never be copied to `/etc/systemd/system`.

## Activation gates

Final activation is not one operation. It requires new evidence and approval at
each gate:

1. repository-only application;
2. immutable release construction and verification;
3. disabled/inactive installation;
4. database foundation migration, peer-auth setup, and verification;
5. local secret generation;
6. Bot Token intake and config render;
7. `/start <challenge>` discovery;
8. pending binding and separate finalization;
9. read-only live preflight;
10. journaled Core multi-client migration with QQ health check and rollback;
11. Telegram-only runtime activation and real private-text acceptance test.

No gate inherits authorization from an earlier gate.

## Rollback

Before Telegram activation, rollback removes only inactive Telegram staging,
units, directories, and unselected releases. After Core migration, rollback
restores the previous Core release, legacy QQ environment line, and previous
drop-in set through the journaled selector, then verifies QQ before touching
Telegram. Telegram rollback never deletes the canonical Owner principal,
namespace, QQ binding, Owner Memory, Definition, model configuration, remote
access, network, or Minecraft.
