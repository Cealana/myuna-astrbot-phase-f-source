# ADR-074: P07 transactional Telegram plugin source binding

Date: 2026-08-08

Status: accepted for inactive T1 source validation

## Context

The memory-only transactional constructor previously accepted a
`plugin_candidate` path and applied the legacy release inventory validator.
That validator proved that a directory was internally content-addressed, but it
did not prove which reviewed Deploy source produced it.  Two different valid
Telegram plugin releases therefore passed under otherwise identical accepted
inputs and produced different target plugin/config trees.

The plugin locator must not be an operator choice.  The target must retain the
current `/Check` ingress and P01/P07/P08/P09/P10/P15/P16 compatibility encoded
in the exact Deploy source while preserving the generation13 plugin as the
explicit rollback identity.

## Decision

Introduce `p07-transactional-memory-telegram-plugin-source-binding-v1`.

The contract derives one target plugin from:

- an exact clean Deploy commit and tree;
- the complete tracked allowlist in
  `build_telegram_gateway_release_v1.COMPONENTS`;
- every source path, Git blob, source mode, payload SHA-256 and size;
- the reviewed release-builder source identity;
- the reviewed Telegram config-renderer source identity and rendered target
  config digest; and
- the exact generation13 rollback plugin and rendered rollback config digest.

The runtime bundle contains the canonical binding and a deterministic plugin
release materialized from those source rows.  `plugin_candidate` remains only a
locator because target bytes are needed to construct the full mutation set.  It
is rejected before P08/public-prestate capture unless its release name,
adjacent manifest, complete file inventory, bytes, sizes, regular-file types,
link counts and modes exactly match the sole manifest-bound target.

The production identity, runtime plan, target-byte package and every later
reopen path carry the same plugin binding projection.  The source-bound
rollback release must also match the fresh public predecessor before plan
construction.  Structurally valid alternate releases, including both releases
accepted by the old oracle, are not interchangeable.

## Safety properties

- No source caller can choose a policy, path role, plugin release or rollback
  plugin by supplying a well-formed digest.
- Tracked missing/extra plugin source, source path/blob/mode drift, renderer or
  builder drift, Deploy commit/tree drift, manifest substitution, symlink,
  hardlink, byte/mode/inventory drift and stale/replayed bindings fail closed.
- Ignored bytecode residue is not source authority and is neither packaged nor
  included in provenance; the exact tracked inventory remains authoritative.
- Memory-only remains diary-inert.  This contract neither selects a diary nor
  creates a package, state, plan, backup, ledger, preflight or attempt.
- Live rollback remains Effective V6 plus compressed generation13 and its exact
  Telegram plugin identity.  No old lineage is reset, relabelled or reused.

## Consequences

The Deploy source and inactive runtime bundle identity change.  Any future T2
must bind the new exact commit/tree, bundle/manifest and target plugin binding,
then start again from fresh content-free public prestate and rollback proof.
No previous T2 authorization or package is compatible.
