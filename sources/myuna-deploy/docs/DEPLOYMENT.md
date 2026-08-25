# Deployment procedure

The bootstrap installer creates three independent source repositories under
`/srv/myuna/repos`, environment directories under `/srv/myuna/environments`,
and isolated runtime data and log directories. It installs the
`myuna-core@.service` template but does not enable or start an instance.

Before any activation:

1. Confirm the definition candidate has passed semantic review and regression
   tests.
2. Record explicit owner approval for the version being promoted.
3. Configure one provider in `dev` without enabling staging or prod.
4. Verify secret handling, audit redaction, health, readiness, and rollback.
5. Promote independently through staging and then prod.

Never point prod directly at a mutable source-material directory.

## AstrBot + NapCat QQ development channel

ADR-018 selects NapCat with a dedicated Myuna QQ account as the primary QQ
channel. The QQ Official Bot adapter is retained as a fallback. Install the
bounded dev stack with:

```bash
sudo /srv/myuna/repos/deploy/scripts/install_astrbot_napcat_dev.sh
```

The installer creates root-only channel secrets, the isolated data tree under
`/srv/myuna/channels/astrbot-qq/dev`, and an installed but disabled systemd
unit. It verifies fixed image digests and Compose syntax but does not start a
container, log in to QQ, connect Core, or create a real identity binding.

Start the stack only for an approved local setup window. Both WebUIs publish on
host loopback only; OneBot port 6199 stays inside the dedicated Docker bridge.
Use the local clipboard helper for WebUI and OneBot tokens so no secret is
printed or pasted into chat.

After NapCat login, the first accepted event must be a Cealana private-chat
challenge. Its authenticated sender ID must match the pending owner fingerprint
before the binding can become verified. AstrBot must not be configured with a
model provider because it is only the channel adapter for Myuna Core.

## v5 loopback development activation

The approved first active surface is intentionally restricted to `dev`:

1. Run `scripts/activate_definition_release.py` as `myuna` with the exact v5
   release, approval, registry, and environments root paths. It verifies every
   release checksum and the non-writable tree before atomically setting the
   environment-specific `current` pointer.
2. Commit the resulting Definition registry activation record.
3. Run `scripts/configure_loopback_dev_core.sh` as root. It creates a random
   root-only dev token if needed, installs the non-secret dev environment, unit,
   and two-credential drop-in, verifies the unit, and leaves it stopped and
   disabled.
4. Start `myuna-core@dev.service` manually for the approved test window.
5. Verify that only `127.0.0.1:18080` is listening, unauthenticated POST is
   rejected, and authenticated synthetic prompts pass the runtime guard.

`scripts/run_loopback_v5_smoke.py` performs the approved five-case synthetic
test. It reads the root-only token locally, never prints it, prints metadata-only
case summaries, and writes the full synthetic request/response evidence to a
protected report path supplied with `--report`.

The service is not enabled at boot during this gate. Stop it with
`systemctl stop myuna-core@dev.service`; this does not stop Minecraft or
PostgreSQL. Never print or copy the provider credential or dev token into a
command argument, report, chat, or ordinary backup.

## Synthetic memory loopback gate

After the five-case Core smoke has passed, stop Core and run
`scripts/configure_synthetic_memory_loopback.sh`. The helper verifies the
fixture checksum and local database, backs up the current non-secret runtime
configuration, installs `dev-v4`, and leaves both units stopped and disabled.

Start the retrieval worker first and Core second. Only authenticated requests
that explicitly set `synthetic_memory=true` enter this path. Verify returned hit
IDs, explicit synthetic disclosure, fixed fixture checksum, and plaintext-free
audit records. Requests without that flag remain ordinary Core conversations.

`scripts/run_loopback_v5_memory_smoke.py` runs five fictional recall cases and
requires the expected top hit, absence of superseded/near-match records,
non-degraded hybrid retrieval, exact fixture checksum, explicit synthetic
disclosure, and a metadata-only audit trail.

This gate must not be reused for real conversations or personal data. Real
memory requires a separate schema/privacy/import/backup decision and explicit
owner approval.

## Memory Stage 1

The development database is intentionally independent from Myuna service
activation:

1. Install the PostgreSQL 18 major package and matching pgvector package from
   the official PGDG Apt repository.
2. Install `database/config/99-myuna-memory.conf` into the cluster `conf.d`.
3. Add only the managed local peer rule documented in
   `database/config/00-myuna-dev.pg_hba.conf`.
4. Run `database/bootstrap/bootstrap_dev.sql` as PostgreSQL superuser.
5. Apply migrations in lexical order with `database/scripts/apply_migrations.sh`.
6. Load only the guarded synthetic fixture with
   `database/scripts/load_synthetic.sh`.
7. Run `database/scripts/verify_stage1.sh` and a custom-format backup/restore
   drill before recording the checkpoint.

The database lives in `/var/lib/postgresql` on the WSL ext4 filesystem. Never
move live database files to `/mnt/c` or `/mnt/d`. Only stopped exports, logical
backups, checksums, and reports may be copied to Windows storage.

No Stage 1 step starts `myuna-core@dev`, activates Definition v5, downloads an
embedding model, or imports real conversations.

## Memory Stage 4 retrieval worker

`myuna-retrieval-worker-dev.service` is a synthetic-only development unit. It is
installed disabled and must not be enabled as a boot service at this stage.

- Transport: owner-only Unix socket; no TCP/UDP listener.
- Database: local peer-authenticated `myuna_dev_app` against synthetic `myuna_dev`.
- Concurrency: one request at a time.
- Model: separate CPU-only subprocess, offline fixed revision.
- Timeout: the model subprocess is terminated; `auto` requests degrade to lexical retrieval.
- Idle lifecycle: the model subprocess unloads after 60 seconds.
- cgroup: CPU quota 200%, memory high 4600M, memory max 5G, tasks max 96.
- Shutdown: `KillMode=control-group` removes the child model process as well as the parent.

Starting the worker does not start Myuna Core and does not authorize real memory.
Use `systemctl start` only for an explicit development test, then stop the unit and
verify that it remains disabled.

## Memory Stage 5 Core adapter

Core contains a dev-only, synthetic-only Unix Socket adapter for the retrieval worker.
The safe environment defaults are:

```text
MYUNA_MEMORY_WORKER_ENABLED=false
MYUNA_MEMORY_WORKER_SOCKET=/run/myuna-retrieval-dev/worker.sock
MYUNA_MEMORY_SYNTHETIC_ONLY=true
```

Stage 5 validation starts the retrieval worker temporarily and invokes the adapter
directly; it does not start `myuna-core@dev` or enable HTTP POST. The Core audit bridge
records fingerprints and retrieval metadata, never query or memory plaintext. Stop the
worker after the integration test and leave both units disabled.

## DeepSeek Provider Dev

Provider Dev is an offline checkpoint. The adapter and Mock transport tests do
not activate Core and do not contact DeepSeek.

The pre-live state must retain all of the following:

```text
MYUNA_PROVIDERS_ENABLED=
MYUNA_PROVIDER_LIVE_CALLS_ENABLED=false
MYUNA_DEEPSEEK_MODEL=deepseek-v4-flash
MYUNA_DEEPSEEK_DAILY_BUDGET_USD=1.00
MYUNA_DEEPSEEK_TIMEOUT_SECONDS=60
MYUNA_DEEPSEEK_MAX_ATTEMPTS=2
```

Before the first live API smoke, perform a separate reviewed gate:

1. Recheck the official model names, API schema, error handling, and pricing.
2. Run the full Core suite and `scripts/run_provider_dev_mock_smoke.py`.
3. Have the operator run `scripts/install_deepseek_credential.sh` locally; do
   not paste the key into chat, Markdown, command arguments, or an environment file.
4. Verify the static `myuna-deepseek-live-gate.service`; it scopes
   `MYUNA_PROVIDER_LIVE_CALLS_ENABLED=true` and the credential to one oneshot
   process. Core's own environment stays false.
5. Start that oneshot unit once for the bounded direct-provider smoke.
6. Verify one fast non-thinking response, usage/cost accounting, audit
   redaction, and the USD 1.00 daily gate.
7. Return live calls to false after the smoke. The later ADR-012 gate may
   activate Definition and loopback Core, but it still does not connect memory
   writes or expose a port beyond WSL loopback.

The older instance drop-in example is retained for the later Core integration
gate. It is not installed or needed for the one-request live smoke.
