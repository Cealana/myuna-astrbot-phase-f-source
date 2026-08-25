# Rollback procedure

Definition, Core, and Deploy are versioned independently.

For a future activated release:

1. Put the affected environment into maintenance mode.
2. Stop only that environment's service instance.
3. Restore its previous immutable Core and Definition release pointers.
4. Apply only the documented backward-compatible data step.
5. Start the instance and run health plus persona regression checks.
6. Record the reason, operator, versions, and verification evidence.

For the v5 loopback dev gate, stop `myuna-core@dev.service` first and leave it
disabled. Restore `/etc/myuna/dev.env` from the newest verified copy under
`/var/backups/myuna/config`, restore the Definition registry from the
pre-activation Git commit, and atomically restore or remove the dev `current`
pointer according to its activation record. Do not delete the immutable release
or source credentials as part of routine rollback.

For synthetic memory rollback, stop Core and the retrieval worker, restore the
previous `dev.env` backup (the ADR-012 `dev-v3` configuration), and start only
Core. The worker must remain disabled and stopped. No database deletion or
fixture modification is required.

For the Provider Dev checkpoint, ensure
`MYUNA_PROVIDER_LIVE_CALLS_ENABLED=false`, remove any instance-specific
credential drop-in, run `systemctl daemon-reload`, and leave `myuna-core@dev`
disabled and stopped. Removing a source API key from `/etc/myuna/secrets`
requires explicit owner approval; disabling live calls does not require deleting
the credential.

For the AstrBot/NapCat dev channel, stop only
`myuna-astrbot-qq-dev.service`. Verify 6099 and 6185 are no longer listening and
leave the unit disabled. This does not stop Minecraft, PostgreSQL, Myuna Core,
or the retrieval worker. Preserve `napcat-qq`, `napcat-config`, and
`astrbot-data`; the QQ login-state directory is a sensitive credential and must
be backed up only to encrypted storage. Never use `docker compose down -v` for
routine rollback.

Memory Stage 1 migrations are forward-only and checksummed. A migration already
recorded in `myuna_admin.schema_migration` must never be edited in place. Add a
new corrective migration instead.

For the synthetic-only dev database, full rollback is:

1. Confirm that `myuna.environment=dev` and `myuna.synthetic_only=on`.
2. Stop no Myuna instance because all instances remain disabled.
3. Take and verify a final custom-format `pg_dump`.
4. Drop only `myuna_dev` after explicit approval, then remove dev-only peer
   mapping and configuration if PostgreSQL itself is being retired.

Once real data is approved in a later stage, database deletion is no longer an
acceptable routine rollback. Restore from a verified logical backup or apply a
new forward migration. Never use an unreviewed `DROP SCHEMA`, `DROP DATABASE`,
or direct mutation of migration history.
