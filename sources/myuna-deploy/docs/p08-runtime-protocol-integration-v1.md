# P08 runtime/protocol integration v1

Status: source-only T1 candidate; no installation or live authority

## Decision

The first P08 consumer boundary is a transport-neutral Core runtime plus a strict
authenticated Telegram Owner-private protocol.  The runtime binds every read,
proposal, confirmation and expiry operation to exactly one P10-B `TrustedTimePort`
sample.  A caller cannot supply time and no wall-clock, message, filesystem,
database, model or Profile fallback exists.

This candidate does not yet select a host synchronization probe, create a service
identity, database, socket, selector, scheduler or Gateway client.  Those remain a
separate private packaging/activation gate.  In particular, source readiness must
not be reported as Gate C live readiness.

## Request boundary

- schema: `myuna.active-temporal-context-protocol.v1`;
- boundary: `authenticated_telegram_owner_private_temporal_context`;
- operations: `retrieve`, `propose`, `confirm`;
- the strict authenticated conversation envelope is rebound to the already
  authenticated client id and `astrbot_telegram` channel;
- request id must equal the envelope request id;
- write operations require both explicit intent and the existing
  `memory_candidate` consent bit;
- authorization happens before trusted-time sampling or store access;
- QQ, group, member, service and mismatched transport contexts fail closed.

## Data and output boundary

Retrieval returns only the existing bounded P08 rendered block and a count.  A
proposal returns its opaque proposal id, exact confirmation code and expiry so the
Gateway can ask the Owner for confirmation.  Confirmation returns only outcome,
opaque fact id and whether a lifecycle event was committed.  Fixed booleans attest
that no model, stable Profile, 128-message session or legacy namespace was written.

The protocol is not an audit record.  Existing P08 content-free audit projections
remain authoritative for diagnostics and must not contain query, summary, ids,
timestamps or confirmation codes.

## Remaining source and T2 gates

The host attestation, bounded release builder and private service/socket source are
now specified by `p08-private-service-source-v1.md`. Remaining work is:

1. Add the Telegram client/proposal UX and truthful public failure mapping.
2. Add strict selector/install/rollback activation and uninstall rehearsal.
3. Add content-free P16 service wiring.
4. Under separate T2 authority, run empty/relevant/proposal/confirmation/duplicate/
   conflict/refresh/expiry/rollback Owner-private acceptance.  QQ remains excluded.

No real Owner content, live state, Profile, session, Writer, QQ, provider/model,
channel, service or network action is part of this candidate.
