# ADR-079: P07 consumption of the P08 content-free status stage projection

## Status

Accepted for inactive P07 source integration. This ADR does not authorize a
P08 protocol call, a P07 request or continuation mutation, a preflight, or a
live activation.

## Decision

P08 owns the status helper and its 17-stage projection contract. P07 treats
that reviewed helper source, stage schema, stage-contract identity, inactive
release, and inactive manifest as immutable dependencies. P07 independently
allowlists every stage with its exact category and retryable boolean before it
can preserve a stage projection.

The product result remains `rejected` with reason
`production_p08_content_free_status_unavailable`. A verified stage is only
additional content-free diagnostic evidence. P07 binds the canonical P08
projection to the exact helper and reviewed artifact identities with a P07
digest. The evidence contains only fixed schema, stage, category, retryable,
nonce, booleans, and digests.

Unknown or extra fields, type drift, unsupported stages, mixed source
identity, stale or mismatched nonce, or digest drift cause the stage evidence
to be omitted. They never change unavailable into ready and never select a
fallback helper or retry the call.

## Compatibility and privacy

The existing terminal request, terminal rejection hash, closed two-child
request collection, and immutable continuation remain unchanged. P07 does not
persist exception text, stdout, stderr, paths, configuration, authentication
material, identities, temporal data, private content, provider payloads, or
channel data. Synthetic tests are the only execution permitted by this source
phase.
