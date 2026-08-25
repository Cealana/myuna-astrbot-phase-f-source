# Secrets policy

- Git stores names and blank examples only, never populated credentials.
- Non-secret runtime settings live at `/etc/myuna/<environment>.env` with
  ownership `root:myuna` and mode `0640`.
- Provider keys must never appear in an environment file or environment
  variable. They are delivered through systemd `LoadCredential`.
- The DeepSeek source credential is `/etc/myuna/secrets/deepseek-api-key`,
  owned by `root:root` with mode `0600`; `/etc/myuna/secrets` is mode `0700`.
- Install a key only with `scripts/install_deepseek_credential.sh` from an
  interactive root terminal. Input is hidden and is never a command argument.
- The instance-specific credential drop-in is installed only at the reviewed
  live API gate. Merely storing the key does not enable a provider or a service.
- Logs and status endpoints must never emit secret values.
- The loopback dev Bearer token source is
  `/etc/myuna/secrets/dev-loopback-token`, owned by `root:root` with mode
  `0600`. The configuration helper generates it locally and never prints it.
- `myuna-core@dev` receives the provider key as `deepseek_api_key` and the
  loopback token as `myuna_dev_token` through separate systemd credentials.
- Backups must not copy populated environment files into ordinary archives.

The Provider Dev installation contains no API keys and keeps live calls disabled.

Memory Stage 1 uses a passwordless PostgreSQL role only through an explicit
Unix peer map from Linux user `myuna` to database role `myuna_dev_app`. The role
has no superuser, database creation, role creation, replication, bypass-RLS,
update, or delete privilege. It cannot authenticate over TCP because no
password is assigned. Future staging and production credentials require a
separate secrets decision and must not reuse the dev role.
