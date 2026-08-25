# Selected Core release upgrade crash recovery v1 — R4A

R4A adds a repository-only recovery contract for the selected-to-selected Core
upgrade path. It does not add a CLI, install an Executor release, inspect live
state, or perform a Core switch.

The recovery executor:

- requires an intact hash-chain Journal and reconstructs the approved prestate
  snapshot from its first `prepared` record;
- validates the forward Journal as an exact prefix of the approved state
  machine before trusting any recovery decision;
- treats `file_apply_intent` and every later file-related phase
  conservatively: files may already have changed and must be restored;
- resumes rollback with the fixed backend only, and records every recovery
  phase in the same append-only Journal;
- never retries a terminal `rollback_failed` state without a new Owner plan;
- treats an existing success receipt as immutable evidence: if a crash occurred
  between receipt creation and the final `committed` record, it verifies the
  target, restores the Gateway to its recorded prestate, and only then appends
  `committed`;
- fails closed if a success receipt cannot be reconciled; it does not delete or
  rewrite the receipt and does not attempt an unrecorded rollback.

Later separately approved stages must still provide a content-addressed CLI,
inactive Executor installation, read-only live preflight, and final live
activation/recovery authorization.
