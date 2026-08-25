# ADR-064: P15 source-only context relevance orchestrator v1

Status: candidate, inactive, source-only.

## Decision

P15 consumes separate typed lanes for verified Definition, authenticated current
Owner message, selected Profile sections, P08 temporal facts, P10 trusted time,
P07 external-authorized summary and delivered turns, P01-B visual observation,
and P09 affinity projection. It does not flatten these sources into a shared fact
record and it does not write, migrate, or infer upstream state.

The Core implementation is a pure selector. Matching and duplicate detection use
Unicode NFKC, case folding, and whitespace collapse only in comparison metadata.
Selected content remains the original ordered tuple of Unicode strings. Selection
uses deterministic relevance, authority, count, character, and UTF-8 byte limits;
no candidate is truncated.

Unknown required provenance, replay snapshot drift, or unknown summary integrity
abstains. Unknown optional provenance is dropped. Missing trusted time excludes
temporal input and clarifies when the current request depends on time. Failed,
pending, abandoned, replayed, and crash-orphaned external turns are excluded.
Authorized generation12 continuity reset is a normal transition, not a fault.

## Dependency identity

The candidate binds generation12 to Core commit
`8529ef1f5f24ded15824bdbf0c6f826b0539b8d4`, Deploy commit
`2819d5cf8fd979ffa1c0bf26b0eaa7411663557b`, generation 12, and the committed
release-set, combined-set, and epoch schemas.

P09 is bound through the public source seam on Core main, without a worktree path:
commit `31250bbd015c07ddefaca889d8c56ddf28971a12`, tree
`e23d1259c233a6ab88cfd9b6c30c7463cf383e03`, schema
`myuna.structured-affinity.v1`, capability
`p09-v7-structured-affinity-v1`, capability digest
`bc28be2f125bb7099859dd366d54d59f48053db670ad2d841482c15fa50d5096`, and P15
interface `myuna.affinity-relevance-port.v1`. That mainline capability declares
prompt projection inactive, so it cannot supply candidate content in this phase.

## Exclusions

This candidate adds no release-set member, runtime builder, activator, plugin,
configuration, migration, service action, live verification, or Profile/session
writer. Activation requires a later, separately authorized phase and a fresh P09
identity check.
