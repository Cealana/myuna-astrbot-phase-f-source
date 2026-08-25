# Myuna Deploy

This repository owns deployment configuration and operational documentation for
the Myuna service layer. It is deliberately separate from both Myuna Core code
and Myuna Definition content.

Current development state:

- `dev`, `staging`, and `prod` are isolated by port, data directory, log
  directory, and environment file.
- Every environment binds to loopback only.
- The immutable v5 Definition is approved for the dev environment only.
- ADR-012 permits an authenticated Core conversation test on WSL loopback.
- DeepSeek is enabled only for that test and remains behind the USD 2.00 daily
  budget ledger; source credentials are never committed.
- The Core unit remains disabled at boot and is started manually for test
  windows.
- Memory Stage 1 owns a local-only PostgreSQL development database. It contains
  synthetic fixtures only and is not connected to an active Myuna instance.
- DeepSeek Provider Dev contains an offline adapter, a systemd credential
  template, and a Mock-only validation path. No API key is installed, live
  calls remain false, and Core remains disconnected from the provider.
- `dev-v1.json` and `dev-v2.json` remain immutable evaluation evidence.
  `dev-v3.json` enables only authenticated loopback conversation against the
  exact v5 release. Memory, tools, AstrBot, and external listeners remain off.
- `dev-v4.json` is the next bounded gate: it adds explicit opt-in reads from a
  checksum-bound fictional fixture through the private Unix socket. It still
  grants no real-memory or write authority.
- `myuna-deepseek-golden-v5-routed.service` is a static one-shot regression
  surface that applies the manifest-bound routing policy; installation never
  enables it at boot.
- ADR-018 selects a dedicated Myuna QQ account through NapCat/OneBot as the
  primary QQ channel and keeps QQ Official Bot as a fallback. The AstrBot and
  NapCat dev containers use fixed image digests, loopback-only WebUIs, an
  internal-only OneBot port, and an installed but disabled systemd unit.
- ADR-019 adds a read-only AstrBot interception plugin and a socket-activated
  owner-challenge runner. Every OneBot event is stopped before normal AstrBot
  processing; only plain-text private enrollment messages can reach the local
  challenge socket. The socket and runner remain disabled until a separately
  approved pending owner binding exists.
- The exact approved owner fingerprint plan can be committed only through the
  local interactive `apply_owner_binding_pending.py` gate. It requires the
  recorded plan digest, hidden double entry of the QQ account, verified pre/post
  PostgreSQL backups on D and C, and creates pending states only.
- ADR-027 contains a repository-only Turn/Route metadata Shadow candidate. Its
  post-reply fanout, frozen Hybrid classifier, trace schema, worker, systemd
  templates, and tests are inactive source artifacts only. No live files,
  service user, marker, socket, model process, reply effect, memory access, or
  provider switch is authorized or installed.

The first runnable surface is intentionally small: health, readiness, and
non-sensitive status endpoints. Any external network exposure, provider
activation, definition promotion, or persistent-memory backend requires a
separate reviewed change.

## Repository boundaries

- `config/`: non-secret environment templates.
- `systemd/`: service templates. Installation does not enable an instance.
- `scripts/`: local verification helpers.
- `docs/`: ports, secrets, deployment, and rollback procedures.
- `database/`: PostgreSQL configuration, roles, versioned migrations, synthetic
  fixtures, verification, backup, and restore-drill scripts.
- `channels/`: isolated, version-pinned channel-adapter runtime definitions.

Never commit populated secrets. Runtime environment files live under
`/etc/myuna/` with mode `0640` and ownership `root:myuna`.
