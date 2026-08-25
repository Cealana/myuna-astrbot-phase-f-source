# AstrBot Telegram Owner Private R3 activation runbook

Status: planning and preflight only

This runbook intentionally contains no Bot Token, Telegram user ID, secret
value, live release digest, or approval digest.

## Gate order

1. Apply the reviewed R3 Core and Deploy commits.
2. Build and independently verify immutable Core and Telegram Gateway releases.
3. Render the Telegram service and socket templates against those exact
   release digests.
   Verify that both template and rendered hashes match the inactive-install
   plan, no placeholder remains, and no mutable `/usr/local`, repository,
   `current`, or `latest` path is present.
4. Preview and approve the content-addressed inactive-install plan.
5. Install inactive artifacts. Install only the rendered units, never the
   source templates. Grant the Telegram identity read/traverse ACL access only
   to the exact Core release; do not add it to the `myuna` group. Confirm all
   Telegram units are
   disabled/inactive, both approval markers are absent, the Telegram secrets
   directory is empty, and QQ/Core process state is unchanged.
6. With a separate approval and verified pre/post logical backups, apply only
   migration `0006_telegram_owner_channel_foundation.sql`, install the
   Telegram gateway peer-auth boundary, and verify roles, grants, functions,
   and zero Telegram binding rows. Do not start any Telegram process.
7. With a separate approval, generate the three local secrets. Confirm only
   their fixed filenames and `root:root 0600` metadata.
8. Enter the BotFather token locally through
   `Set-MyunaTelegramToken.ps1`. Never paste it into Codex or an approval.
9. Keep the Telegram AstrBot container stopped. Run discovery locally, then
   send the exact one-time `/start <challenge>` command shown by the helper in
   the Bot's private chat.
10. Review the fingerprint-only pending-binding preview. Apply it only after its
   exact digest is approved.
11. Complete the separate private challenge and approve its finalization
    digest.
12. Render the live Core environment candidate from the current file. Verify
    that only the legacy credential line changes and stage a journaled Core
    activation plan.
13. Read-only preflight must prove: QQ is healthy; previous Core release and
    environment are backed up; two Core credentials exist and differ; staged
    Core/Gateway releases and commits match; no Telegram poller is running.
14. After a new approval, migrate Core, restart only the authorized dependency
    chain, and prove QQ still passes with the QQ-scoped credential.
15. Render the Telegram-only AstrBot config, start only the Telegram socket,
    Gateway, and AstrBot container, then perform one real Owner private-text
    acceptance test.

## Fail-closed conditions

Stop without repair or further mutation if any of these is observed:

- a webhook is configured while discovery expects polling;
- AstrBot and discovery both attempt to poll;
- either Core token is missing, duplicated, or accepted with the other
  channel's headers;
- the live Core environment contains both legacy and scoped declarations;
- an unknown Telegram account, group, bot sender, media event, command, memory
  write, tool request, scheduler request, or external operation reaches Core;
- any Telegram unit starts during inactive installation;
- any installed Telegram unit still contains a template token, mutable
  repository path, legacy `/usr/local` Telegram path, or release alias;
- QQ health changes before Telegram activation;
- a required commit, release digest, plan digest, receipt, file owner, mode, or
  service prestate has drifted.

## Rollback checkpoints

- Before Core migration: remove only inactive Telegram artifacts created by the
  approved installer.
- During Core migration: let the journaled Core selector restore the previous
  release, legacy QQ credential declaration, and drop-in set; then verify QQ.
- After Telegram activation: stop/disable only Telegram units and container,
  revoke only the Telegram binding and credentials, and leave QQ, canonical
  Owner identity, memory, Definition, models, network, and Minecraft unchanged.
