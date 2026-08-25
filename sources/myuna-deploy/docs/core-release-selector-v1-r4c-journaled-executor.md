# Core Release Selector v1 R4C journaled executor

Status: work-only candidate; not applied, installed, or active

## Purpose

R4C changes the active Core release and temporarily pauses the QQ Gateway. A
plain sequential script is not sufficient because the process, WSL, or host
can stop between any two mutations. The executor therefore treats activation
as a durable state machine rather than a best-effort command list.

This implementation is split into four independent modules:

1. `core_release_selector_r4c_journal.py`
   - append-only canonical JSONL;
   - SHA-256 previous-record chain;
   - non-blocking operation lock;
   - fsync before every backend mutation;
   - atomic, idempotent activation receipt.
2. `core_release_selector_r4c_executor.py`
   - validates the installed v2 transaction and inactive receipt;
   - enforces the socket-aware forward sequence;
   - performs deterministic rollback and crash recovery;
   - owns no systemd command or live destination path.
3. `core_release_selector_r4c_live_backend.py`
   - fixed Core, Gateway Socket, and Gateway Service units only;
   - fixed binding and drop-in destinations only;
   - no shell, model-provided command, or caller-provided unit/path;
   - exact prestate, target, rollback, and Gateway contract verification.
4. `run_core_release_selector_r4c.py`
   - root-only live entrypoint;
   - exact activation digest, transaction tree, inactive-install digest, and
     literal live-confirmation gate;
   - separate `activate-live` and `recover-live` commands.

## Forward order

Every mutation has a durable intent record before the backend is called:

1. verify the installed transaction, inactive receipt, exact Core prestate,
   Gateway Socket, and Gateway Service;
2. journal intent, then stop and verify the Socket;
3. journal intent, then stop and verify the Gateway Service;
4. journal intent, then install the binding and sealed Core drop-in set;
5. journal intent, then run one daemon-reload;
6. journal intent, then restart Core once;
7. verify target release, verifier, binding, drop-ins, working directory, and
   activation restart budget;
8. journal intent, start and verify the Socket;
9. journal intent, start and verify the Gateway Service;
10. journal intent, atomically write the non-sensitive receipt;
11. append the committed terminal record.

The Socket always stops before the Service and starts before the Service.
During the socket-only start stage, systemd may report the fixed Gateway
Socket as `active/listening`; after the Gateway Service is connected it may
report `active/running`.  The live backend treats only those two substates as
socket-ready, keeps `active/running` as the regular Service/Core predicate,
and never treats `active/listening` as inactive.  Final Gateway verification
still requires the sealed Socket/Service relationship and the running
Gateway Service.

## Recovery policy

- Before Core mutation: restore only the sealed Socket/Service prestate; do
  not restart Core.
- After Core mutation but before target health: restore the exact rollback
  drop-ins, remove the binding, daemon-reload, restart and verify legacy Core,
  then restore Socket and Service.
- After target Core health: continue forward only while the target Core
  postcondition remains valid. If it drifted or Gateway recovery fails, perform
  the full rollback.
- After receipt write but before the committed record: verify target Core and
  Gateway, reuse the byte-identical receipt, and append one committed record.
- After committed: repeated execution is read-only verification. Later
  unrelated Core restarts do not repeat activation.
- After rolled back: the approval attempt is terminal and cannot silently
  retry.
- After rollback failure or journal corruption: fail closed and require Owner
  action.

Rollback itself is also phase-journaled before each Socket, Service, file,
daemon-reload, Core restart, and restoration mutation.

## Security boundary

The executor cannot:

- accept an arbitrary shell command;
- accept a model-selected unit or destination path;
- choose another transaction or Core release;
- change Definition, Capability, EnvironmentFile, secrets, network, model,
  memory, tools, vision, OpenClaw, Turn Manager, Minecraft, or QQ account;
- activate without a separately approved v2 activation-plan digest;
- use the superseded v1 transaction.

Command failures record only the executable basename and return code. Journal
records and receipts contain no message text, environment variables, API keys,
credentials, raw logs, or model output.

## Test boundary

The work-only suite uses:

- a self-contained synthetic v2 transaction;
- an in-memory fake backend with deterministic failure/crash injection;
- temporary journal roots only;
- a copied formal Deploy repository for the full regression suite;
- a read-only live prestate probe for the installed v2 transaction.

No test invokes the live CLI with the required confirmation string.

## Required stage order

1. Apply this repository candidate after a digest-bound Owner approval.
2. Install a content-addressed executor release and state-directory contract
   inactive; do not invoke it.
3. Run a read-only, exact live preflight and seal the activation command.
4. Obtain a separate Owner approval for activation plan
   `0c6852ad374d74fb6e09c950246ac4264d42689275f2443a0a53cc4b5f90622b`.
5. Execute R4C and verify the activation or rollback receipt.

Steps 1–3 do not authorize step 4 or 5.
