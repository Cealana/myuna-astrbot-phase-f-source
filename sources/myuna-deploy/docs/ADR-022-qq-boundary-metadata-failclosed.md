# ADR-022: QQ boundary metadata and default-LLM fail-closed gate

## Status

Proposed for digest-bound activation.

## Context

After the NapCat account was restored, an owner private-text test was handled
by AstrBot's default conversation path instead of the Myuna gateway.  Core,
the gateway database, and the DeepSeek budget recorded no request.

The immutable `v1.1` plugin release contained `main.py` and `protocol.py`, but
not `metadata.yaml`.  AstrBot imported and instantiated the class, so startup
looked healthy.  Its session plugin manager later dropped the handler because
the plugin metadata name was empty.  The default AstrBot LLM path then ran and
reported that no provider was configured.

## Decision

1. Treat `metadata.yaml` as a required, hash-verified runtime file alongside
   `main.py` and `protocol.py`.
2. Give the plugin the stable name `astrbot_plugin_myuna_gateway`, version
   `0.2.0`, and scope it to `aiocqhttp`.
3. Disable AstrBot's default LLM request chain.  AstrBot remains a channel
   interface only; Myuna Core remains the only model-routing boundary.
4. Recreate only AstrBot.  NapCat, Core, the owner runtime socket, the database,
   memory, tools, budgets, and boot settings remain unchanged.

If the named plugin is unavailable in the future, QQ messages must fail closed
instead of falling through to an AstrBot provider.

## Activation and rollback

Activation is bound to an exact plan digest.  Before mutation, the active
plugin files and AstrBot configuration are copied to root-controlled WSL backup
storage and the encrypted C-drive critical-backup tree, with matching SHA-256
values.

On failure, the previous plugin pointer and exact AstrBot configuration are
restored, the target Git commit receives a compensating revert, and AstrBot is
recreated on the previous release.
