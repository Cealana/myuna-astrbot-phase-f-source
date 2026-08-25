# ADR-086: P08 protocol acceptance uses one nonce and a content-free rejection projection

Status: Accepted for source-only implementation

## Context

The consumed P08 v2 activation reached the reviewed acceptance helper once and
failed closed, but its parent collapsed every non-zero child exit before
validating the child's existing versioned rejection envelope.  Offline source
review also proved that the helper generated a second request nonce instead of
reusing the controller-provided invocation nonce.  The historical incident and
its receipt remain immutable; neither observation authorizes a retry.

## Decision

- The controller generates one 64-lowercase-hex nonce and passes it through
  `MYUNA_P08_STATUS_INVOCATION_NONCE`.
- The helper validates that nonce and reuses it for the authenticated request,
  server echo, success projection, and parent validation.  It never generates a
  second nonce for this CLI invocation.
- A non-zero child may contribute only the exact
  `myuna.p08-content-free-status-stage.v1` envelope.  The parent validates the
  fixed schema, allowlisted stage/category/retryability, source identity,
  projection digest, and exact nonce before retaining it.
- Empty, duplicate-key, malformed, unknown, oversized, mixed, stale, replayed,
  or nonce-substituted output remains the generic
  `protocol_acceptance_failed` result.  Raw stdout, stderr, exception text,
  paths, credentials, request payloads, and private data are not retained.
- The stage taxonomy covers pre-socket source/privilege/config, transport,
  peer/auth, authenticated protocol/context, status runtime, and response
  validation.  It never changes a failure into readiness and never triggers a
  retry, fallback, alternate helper, or health probe.
- The new v3 current-selected strategy binds the consumed v2 terminal incident
  and the accepted T0 diagnosis by exact content-free identities.  It uses a
  distinct O_EXCL namespace and does not reset any earlier action budget.

## Current-head reconciliation

The v3 source and inactive release remain immutable evidence.  After the
separately owned P07 helper integration advanced Deploy main, P08 derives a v4
strategy and namespace.  Its canonical contract binds the accepted P08 T1 and
P07 integration handoffs, the exact P07 integration base commit, runtime,
bundle, plugin and max-one strategy identities, and all earlier P08 terminal
incidents.  The release builder proves that the seven P07-owned files are
unchanged from that integration commit while allowing only later P08-owned
source commits.  Unknown ancestry, dirty paths, source substitution, or mixed
P07 identities fail closed.

## Consequences

Future separately authorized acceptance can identify one safe internal stage
from a single call while preserving generic external failure semantics.  This
source phase creates no plan, incident, backup, preflight, live call, service
mutation, or activation authority.
