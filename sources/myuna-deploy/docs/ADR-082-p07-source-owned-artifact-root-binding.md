# ADR-082: P07 source-owned artifact-root binding

Status: accepted for source-only implementation

## Context

The production transactional entrypoint previously named the final A runtime and
bundle roots from an earlier immutable-continuation source phase.  Current
source correctly rejected those stale manifests before status invocation, but a
fresh build could not become the production reopen target without another
source edit.  That ordering made the final source commit and final artifact
manifest impossible to bind at the same stable boundary.

## Decision

The runtime source declares one versioned root contract with two distinct fixed
roles:

- `/srv/myuna/builds/p07-source-owned-artifact-root-binding-v1-final-runtime-a`
  is the production runtime-artifact root.
- `/srv/myuna/builds/p07-source-owned-artifact-root-binding-v1-final-bundle-a`
  is the production transactional-bundle root.

These canonical names are committed before artifacts are built.  Deterministic
B roots may be created only as inactive comparison outputs; production source
does not name or select them.  The bundle manifest includes the exact root
contract and its identity digest.  The manifest also binds the exact clean Core
and Deploy commit/tree, source inventory, runtime projection, plugin binding,
immutable historical reference contract, and fresh strategy source contract.
The copied runtime script in the bundle must be byte-identical to the script in
the exact Deploy commit.

Production has no root parameter and does not read an environment override.  It
does not scan build directories, select the newest entry, follow a compatibility
alias, or fall back to predecessor roots.  Root, manifest, source, release,
plugin, inventory, type, ownership, mode, link, symlink, and digest drift reject
before status intent, P08, strategy state, package, backup, preflight, attempt,
or service mutation.

## Historical boundary

The two-child terminal request collection, immutable continuation, exhausted
2/2 and 1/1 lineages, terminal dispatches, predecessor roots, and all prior
artifacts remain read-only evidence.  This decision neither replays a request
nor creates a third request.  Historical evidence storage remains exact root
ownership; target payload ownership remains exact service ownership.

## Build order

1. Commit the fixed root contract and all validators/tests.
2. From that exact clean commit, build new non-overwriting runtime A/B roots.
3. From the same exact clean commit and runtime, build new non-overwriting
   transactional bundle A/B roots.
4. Verify byte+mode equality, inventories, source/bundle script equality, and
   production A-root reopening without any source edit after the build.

Any need to modify source after step 2 invalidates the candidate artifacts and
requires new non-overwriting roots from a later clean commit.
