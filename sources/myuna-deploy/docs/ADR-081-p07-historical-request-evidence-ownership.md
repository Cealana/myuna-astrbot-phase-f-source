# ADR-081: P07 historical request-evidence ownership roles

## Status

Accepted for source-only integration. Live selection and activation remain separate.

## Decision

The closed two-child request collection is immutable historical evidence. Its
storage identity is exact root ownership (`uid=0`, `gid=0`), directory mode
`0700`, and regular-file mode `0600`. The terminal request payload separately
binds the future target runtime owner (`uid=999`, `gid=989`). These roles use
different field names, schemas, and validation paths.

The immutable continuation reference binds the exact root and child directory
metadata, all six file type/mode/link/size/SHA-256 identities, the two exact
content-addressed child names, collection count and digest, closed inventory,
terminal rejection, and `reinterpreted_as_ready=false`. It never accepts an
owner wildcard, alternate owner, compatibility fallback, third request, replay,
temporary entry, extra entry, symlink, hardlink, or metadata substitution.

Future status, package, state, backup, ledger, target payload, and runtime files
retain their own source-derived owner and namespace contracts. Correcting the
historical evidence role does not mutate or relabel the historical collection.

## Consequences

The immutable-reference schema and fresh max-one strategy identity are
versioned successors. Runtime and bundle identities are rebuilt from changed
source. Any future T2 must independently accept those final identities and must
not reuse the terminated strategy or dispatch.
