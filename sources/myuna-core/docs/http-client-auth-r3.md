# Core HTTP client authentication R3

Status: work-only candidate; not installed or active

## Registry

Core accepts either the legacy single-client credential setting or the new
channel-scoped registry, never both.

```text
MYUNA_HTTP_CLIENT_CREDENTIALS=
  qq-owner-private:astrbot_qq:qq_owner_core_token,
  telegram-owner-private:astrbot_telegram:telegram_owner_core_token
```

The environment contains only systemd credential names. Secret values are read
from `CREDENTIALS_DIRECTORY`, never from ordinary environment variables.

Client IDs, channel kinds, and credential names must be unique. Loaded token
values must also be unique. The initial allowlist contains only
`astrbot_qq` and `astrbot_telegram` and permits one client identity per channel.

## Request authentication

Scoped clients must send all three values:

- `Authorization: Bearer <channel-specific token>`;
- `X-Myuna-Client-Id`;
- `X-Myuna-Channel-Kind`.

Core scans the complete credential registry using constant-time token
comparisons. Exactly one token must match, and both identity headers must equal
the identity bound to that token. Missing, unknown, duplicated, or swapped
values return the same `401 unauthorized` response.

Only the resolved configured client ID and channel kind enter the audit event.
The bearer token, credential name, arbitrary caller-provided headers, request
text, and raw account identity are never logged.

## Migration

The legacy single-client form stays code-compatible only for a journaled
migration and rollback. Live configuration must replace:

```text
MYUNA_DEV_TOKEN_CREDENTIAL=qq_owner_core_token
```

with the scoped registry and add a separate systemd
`telegram_owner_core_token` credential. A configuration containing both forms
is not ready and fails during settings load.

The new Core release must be installed content-addressed and selected only
through the Core Release Selector after a fresh read-only preflight and exact
activation approval. QQ must pass after Core migration before Telegram runtime
activation is allowed.
