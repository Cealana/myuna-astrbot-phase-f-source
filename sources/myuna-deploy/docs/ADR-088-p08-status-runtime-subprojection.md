# ADR-088: P08 content-free status-runtime subprojection

## Status

Accepted for source-only candidate validation. Live activation remains a separate gate.

## Context

The P08 server already separated peer, authenticated-context/protocol, and status-runtime
rejections. A consumed max-one activation proved only the fixed outer
`server_status_runtime_rejection` stage, then restored the selected predecessor. The
reviewed installed closure and fixed identity contract did not establish whether the
runtime rejection originated in trusted time, the temporal store, status projection,
response encoding, or an unknown runtime exception.

## Decision

Keep the existing generic server and P07-facing status-stage projections byte-compatible.
For the P08 helper-to-controller acceptance path only, add a separate versioned
`myuna.p08-status-runtime-subprojection.v1` contract with exactly five allowlisted
boundaries:

- `trusted_time_boundary`
- `store_state_boundary`
- `status_projection_boundary`
- `response_encoding_boundary`
- `status_runtime_unknown_boundary`

The subprojection binds the single invocation nonce, schema, source identity, category,
retryability, and canonical digest. It contains only fixed booleans and identifiers;
raw exception text, paths, configuration values, state content, temporal facts, and
credentials are prohibited. Unknown, malformed, mixed-source, wrong-nonce, replayed,
or raw-tainted envelopes fail closed to the existing generic response-projection stage.

`content_free_status_rejection_projection` continues to emit the legacy generic v1
projection for P07. The direct P08 post-target controller preserves the detailed runtime
projection in its content-free failure receipt. No retry, fallback, alternate helper,
health probe, or second socket call is introduced.

## Lineage and activation

The next controller strategy uses a new v5 namespace and max-one incident identity. It
binds the consumed v4 incident and all prior immutable P08 incidents without granting
any of them restore authority. Future rollback remains bounded to the freshly frozen
selected predecessor plus that new action's exact opaque-state backup.

This ADR creates no live namespace, plan, ledger, backup, preflight, attempt, protocol
call, or service mutation.
