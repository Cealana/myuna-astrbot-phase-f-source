# Owner QQ binding finalization guide

This is the third and separate approval gate for the owner QQ binding. A successful
private challenge does not automatically activate the owner identity.

## Preconditions

- The protected challenge evidence exists and matches the approved pending plan.
- PostgreSQL contains exactly one accepted `owner_challenge_matched` operational row
  for that evidence.
- The principal, namespace, and binding are still `pending`; `verified_at` is null.
- Myuna Core, the retrieval worker, and the one-time challenge gateway are inactive.
- AstrBot and NapCat remain healthy and continue to block all model, memory, and tool
  access.

## Preview only

Run as WSL root:

```bash
/srv/myuna/repos/deploy/scripts/finalize_owner_binding_verified.py
```

The default mode performs no writes. It prints a safe plan and a
`finalization_digest` bound to the retained challenge evidence checksum. The user
must explicitly approve that exact digest before applying it.

To perform all database, runtime, and channel-health precondition checks without
writing anything, use:

```bash
/srv/myuna/repos/deploy/scripts/finalize_owner_binding_verified.py \
  --check-preconditions
```

## Apply after explicit approval

```bash
/srv/myuna/repos/deploy/scripts/finalize_owner_binding_verified.py \
  --apply \
  --approved-finalization-digest <approved-digest>
```

The apply mode is limited to these state changes:

- `principal-owner-cealana`: `pending` to `active`
- `ns-owner-cealana-private`: `pending` to `active`
- `binding-astrbot-qq-owner-cealana`: `pending` to `verified`
- `verified_at`: the timestamp already recorded by the accepted challenge evidence

It creates and verifies pre/post PostgreSQL custom-format backups in the WSL ext4
filesystem and copies checksum-verified duplicates to the C drive critical-backup
directory. It then removes the one-time challenge code, challenge config, and
activation marker, while retaining the safe challenge evidence and a root-only final
receipt.

The tool does not start Myuna Core, the retrieval worker, a model, or any tool. If a
post-commit step fails, the tool uses a digest-bound compensating transaction to
restore all three records to `pending` and clears `verified_at`.

## After finalization

QQ remains a blocked channel boundary until a later, separately reviewed runtime
connection is approved. Identity verification alone does not grant model, memory, or
tool access.
