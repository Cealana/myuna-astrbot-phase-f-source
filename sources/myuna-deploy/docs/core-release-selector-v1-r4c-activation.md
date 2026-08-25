# Core Release Selector v1 R4C socket-aware activation

Status: work-only repository candidate; not applied, installed, or active

## Why the previous transaction cannot be activated

`myuna-qq-owner-runtime-dev.service` is socket-activated by
`myuna-qq-owner-runtime-dev.socket`. The installed v1 transaction only seals
the Gateway service and instructs the future executor to stop that service.
While the socket remains active, a QQ request can immediately start the
Gateway again during the Core migration.

The v1 transaction remains valid historical evidence, but it is superseded and
must never be used as an R4C activation authority.

## v2 state boundary

The v2 activation plan seals all of the following:

- exact Core prestate and target release;
- exact Gateway service fragment and drop-ins;
- exact Gateway socket fragment, drop-ins, listen path, enabled state, active
  state, and trigger relationship;
- the v2 activation-plan digest used by the runtime binding;
- complete forward and rollback Core drop-in sets;
- an ordered socket/service quiescence and recovery protocol.

## Activation state machine

1. Verify the approved v2 activation digest, installed v2 transaction, live
   Core prestate, Gateway service, and Gateway socket.
2. Stop the Gateway socket first and prove it is inactive.
3. Stop the Gateway service and prove it is inactive.
4. Install the v2 runtime binding and complete final Core drop-in set.
5. Delete only the five sealed legacy drop-ins.
6. Run one `daemon-reload`.
7. Restart Core exactly once and verify the canonical release.
8. Start and verify the Gateway socket.
9. Start and verify the Gateway service and its socket trigger relationship.
10. Write a non-sensitive activation receipt.

No chat message, model output, or arbitrary command can change this sequence.

## Failure and crash recovery

The future R4C executor needs an on-disk phase journal written before every
mutation. Recovery is deterministic:

- before Core mutation: restore the original socket/service running state;
- after Core mutation but before Core health: stop socket then service, restore
  the exact rollback Core files, remove the new binding, reload, restart and
  verify Core, then restore socket and service;
- after Core health but before Gateway health: preserve the verified Core
  target only if the sealed postcondition still holds; otherwise perform the
  full rollback above;
- after success: seal the journal and activation receipt; repeated execution
  with the same digest becomes a read-only verification.

The executor itself is intentionally not included in this repository
candidate. It will be built only after the v2 contract is formally applied, a
new v2 transaction is rebuilt, and that transaction is separately installed
inactive.

## Required stage order

1. Apply this five-file v2 contract candidate to Deploy.
2. Rebuild a new socket-aware transaction in `work`.
3. Install that new transaction inactive beside the superseded v1 transaction.
4. Build and test the R4C journaled executor in `work`.
5. Obtain a separate Owner approval for the exact v2 activation-plan digest.
6. Execute R4C and verify rollback evidence.

None of steps 1-4 authorizes activation.
