# P08 Active Temporal Context integration gates v1

## Gate A: source ready (current T1)

- Core package owns an independent schema, store, time port, proposal/confirmation,
  lifecycle, retrieval and audit projection.
- Tests are synthetic and cover schema/corrupt/oversize, permission/type drift, time
  regression, duplicate/conflict, expired/stale, crash/partial commit and cross-layer
  isolation.
- No import or write path targets P07, session context, legacy memory or P10.
- Deploy contains ADR/privacy/integration contracts only.
- Exact diff, deterministic candidate and rollback/provenance are independently reviewed.

Passing Gate A means `source-ready`; it does not mean installed, selected or live.

## Gate B: P10-B trusted-time integration (future source work)

- P10-B supplies a concrete authenticated `TrustedTimePort` implementation.
- Source label, durable monotonic sequence, regression behavior, uncertainty, availability,
  timeout, permission and content-free audit contracts are independently verified.
- Restart recovery advances beyond the persisted P08 mutation watermark.
- No wall-clock, message, model, filesystem or database timestamp fallback exists.
- Provider failure causes P08 read/write/expiry to fail closed without stale context.

Gate B is not implemented by P08 T1 and does not authorize live selection.

### Post-foundation runtime adapter

P10-B source is now present in current Core.  The source-only runtime/protocol adapter
defined by `p08-runtime-protocol-integration-v1.md` binds P08 operations to the P10-B
port and authenticated Telegram envelope without selecting a real synchronization
probe or installing a service.  It is an input to Gate C, not evidence that Gate C
has passed.

## Gate C: T2 private installation and Telegram acceptance

Before any T2 action, provide a decision summary of at most 300 Chinese characters covering
goal, main risk, affected scope, rollback and recommendation, then wait for Owner approval.

The approved plan must define:

- dedicated private identity, directory, database, socket/service and exact code release;
- `0700`/`0600`, no-symlink, selector, backup and uninstall/rollback checks;
- Telegram authenticated proposal, exact confirmation and read wiring;
- separate empty/relevant/duplicate/conflict/refresh/expiry/rollback acceptance;
- content-free audit and proof that P07/session/legacy/P10 were not written;
- no QQ writer scope; any QQ read acceptance is separately named;
- bounded live attempts and restoration of exact pre-activation state on failure.

Real Owner content, channel calls, provider/model calls, installation, selector/config change,
restart and real E2E are forbidden before Gate C approval.

Physical purge, destructive schema/content migration, host/network change or irreversible
data action remains T3 and always requires a new impact-specific Owner confirmation.

## Deferred P15 boundary

P15 may later choose whether a task needs a bounded P08 block. P08 does not perform
cross-source selection, does not automatically analyze complete conversations and does not
write P07/session/P10. Direct P08 retrieval is not proof that P15 exists.
