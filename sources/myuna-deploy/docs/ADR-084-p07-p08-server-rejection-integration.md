# ADR-084: P07 binding of the P08 server-rejection subprojection

Status: accepted for source-only inactive integration

## Context

P08 now separates three server-side failure boundaries into fixed content-free
status stages.  P07 previously bound the older 17-stage helper contract and
therefore rejected the new reviewed helper before any status invocation could
be created.  The already terminal status invocation remains immutable and is
not retried or reinterpreted by this change.

## Decision

P07 binds the exact reviewed P08 helper, service entrypoint, future unit,
inactive release, manifest, source inventory, future-installed inventory,
status-stage identity, and server-rejection identity.  The accepted external
server stages are exactly:

- `server_service_peer_rejection`
- `server_authenticated_context_protocol_rejection`
- `server_status_runtime_rejection`

The older `server_peer_auth_protocol_rejection` remains accepted only as the
explicit compatibility output of the same exact reviewed helper when no
server subprojection is present.  It is not a fallback selected by P07.

P07 re-derives both P08 identities from their exact source policies and rejects
unknown, malformed, extra, mixed, stale, substituted, or source-drifted
projections.  Rejected evidence remains content-free and preserves the same
single-invocation, no-retry, O_EXCL, crash-safe contract.  The outer rejection
envelope continues to bind only a verified fresh or legacy strategy context;
without one, it remains generic fail-closed.

## Privacy and persistence

No raw cause, exception, stdout, stderr, path, configuration, UID, auth value,
private content, temporal record, request body, database row, provider payload,
or channel content enters the projection.  The closed two-request collection,
immutable continuation, terminal rejected status evidence, and exhausted old
lineages remain read-only.

## Activation boundary

This decision only changes Deploy/P07 source and deterministic inactive
artifacts.  It does not call P08, create a status intent, install or select a
release, create transactional state, run preflight, consume an attempt, mutate
services, or authorize live activation.
