# Core Release Selector v1 R4C inactive executor installation

Status: repository candidate only; not installed, invoked, or active

## Purpose

R4C must not execute mutable Python files from a Git checkout.  This stage
packages every transitive local Python dependency of the journaled executor
into one immutable, content-addressed release.  It also creates or verifies a
root-owned persistent directory for the crash-recovery journal.

The stage is intentionally inactive.  Installing it does not select a Core
release, call the executor, stop or start a service, run `daemon-reload`, send
QQ messages, call a model, or read or write memory.

## Installed layout

After a separately approved inactive installation:

```text
/opt/myuna/core-release-selector/
├── executors/
│   └── <executor_release_sha256>/
│       ├── EXECUTOR_MANIFEST.json
│       ├── core_release_selector.py
│       ├── core_release_selector_transaction.py
│       ├── core_release_selector_transaction_v2.py
│       ├── core_release_selector_r4c_release.py
│       ├── core_release_selector_r4c_journal.py
│       ├── core_release_selector_r4c_executor.py
│       ├── core_release_selector_r4c_live_backend.py
│       └── run_core_release_selector_r4c.py
└── executor-installations/
    └── <approved_executor_install_plan_digest>.json

/var/lib/myuna-core-release-selector/
└── r4c-activations/
```

The executor release directory is `root:myuna 0550`; each file is
`root:myuna 0440`.  The installation receipt is `root:myuna 0440`.

The state parent and `r4c-activations` directory are both `root:root 0700`.
The first installation creates an empty directory.  Later parallel executor
installations accept an existing non-empty directory only after snapshotting
its complete directory/file shape, ownership, modes, and file hashes.  The
snapshot must remain identical through the install.

## Why the state path is independent

`/var/lib/myuna` is owned by the unprivileged `myuna` runtime account.  A
root-owned child below that directory could still be renamed or removed by
the owner of its parent.  R4C recovery state therefore uses the independent
root-owned path:

```text
/var/lib/myuna-core-release-selector/r4c-activations
```

This prevents the normal Core runtime identity from deleting the recovery
journal as a directory entry.  The journal hash chain still detects content
corruption, while the filesystem boundary protects the journal root itself.

## Content address

The release digest covers a canonical unsigned manifest containing:

- the exact Deploy source commit;
- the eight runtime-file SHA-256 values;
- the activation-plan digest;
- the socket-aware transaction-tree digest;
- the approved inactive transaction-install digest;
- the fixed entrypoint;
- the fixed root-only state path;
- explicit inactive and no-side-effect flags.

`executor_release_sha256` is the SHA-256 of that canonical unsigned manifest.
The signed-by-content manifest then records that digest and is installed
beside the eight runtime files.

Changing one source byte or any binding produces a different release digest.

## Live gate added by this stage

The activation CLI gains two mandatory bindings:

- approved executor-install plan digest;
- expected executor-release digest.

It also verifies:

1. it is executing from the exact content-addressed release, not from Git or a
   symlink;
2. the release file set, hashes, ownership, and modes;
3. the canonical inactive-install receipt;
4. the independent root-only state-directory contract;
5. the existing activation, transaction, and inactive transaction-install
   bindings.

The literal live confirmation remains the first rejection gate.  The previous
inactive-install option spelling remains a compatibility alias, but both
spellings populate the same validated transaction-install binding.

## Failure and idempotency behavior

- A digest or source-contract mismatch fails before installation writes.
- A pre-existing exact release and receipt are accepted idempotently.
- A pre-existing state contract, including old immutable activation journals,
  is accepted only when every entry is a regular file or directory and the
  complete state snapshot remains unchanged throughout installation.
- A pre-existing conflicting artifact fails closed and is never overwritten.
- If a later step fails, only artifacts newly created by that attempt are
  removed.
- Existing artifacts and non-empty state data are preserved on failure.
- A concurrent state change fails closed and rolls back only the new release
  and receipt; it never attempts to rewrite or delete journal data.
- No rollback path touches a systemd unit, active binding, Core release,
  Gateway, QQ, model, memory, or other service.

## Remaining R4C order

1. Apply this repository candidate after digest-bound Owner approval.
2. Build and seal the executor release from the resulting Deploy commit.
3. Install that exact release beside prior releases and preserve the existing
   state contract after a separate Owner approval.
4. Run read-only live preflight and seal the only permitted activation
   command.
5. Obtain separate activation approval.
6. Execute activation and verify the committed or rolled-back receipt.

Repository application, release construction, and inactive installation do
not authorize preflight mutation or activation.
