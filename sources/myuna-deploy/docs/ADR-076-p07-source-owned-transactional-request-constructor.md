# ADR-076: Source-owned transactional request constructor

Status: accepted for inactive T1 source; no T2 authority.

## Decision

The production P07 transactional runtime owns construction of its first
`prepare-package` request. The production CLI accepts no caller-supplied Core,
Deploy, runtime, plugin, bundle, policy, lineage, ownership, rollback, path-role
or protected-root identity for this operation.

The constructor reads only these fixed source declarations:

- the clean Core and Deploy repository roots;
- one protected deterministic runtime build root;
- one protected deterministic transactional bundle root;
- the fixed immutable predecessor evidence root; and
- the local `myuna` account identity.

It reopens the canonical bundle, complete source-file inventory, sole plugin,
runtime artifact, Core artifact and both exhausted lineages through the same
reviewed validators used by the controller. The bundle source commits and trees
must equal the current clean repositories. Missing, additional, stale, mixed,
replayed, symlinked, hardlinked, mode-drifted or source-substituted inputs reject
before the P08 observer or any state path is reachable.

## Request materialization

`construct-request` creates one canonical ASCII request package below a fixed
protected `/run` namespace. Creation is non-overwriting. A private temporary
sibling is populated in deterministic order with `request.json`, a content-free
receipt and a completion document. Each regular file is fsynced and read back;
the directory is fsynced; completion is written last; the directory is then
atomically renamed and its inventory, ownership, mode, link count, bytes and
digests are reverified. Crash residue and replay are evidence and reject rather
than being resumed or overwritten.

The generic Python dispatch surface remains injectable for synthetic tests.
The production CLI path additionally reconstructs the source-owned request and
requires byte-for-byte equality before it can invoke the protected P08/public
observer. Thus a caller cannot make an operational request authoritative merely
by supplying well-formed digests or alternate locators.

## Privacy and activation boundary

The constructor reads source, build manifests, content-free lineage evidence and
public Unix account metadata only. It has no provider, model, channel, health,
private history, Profile, database-row or raw-log operation. It does not observe
P08, create a live plan, package target bytes, create a strategy/ledger/backup,
run preflight, consume an attempt or mutate live state.

The target remains disabled-memory-only. Diary selectors, stores, workers,
timers, preview/final/addendum generation and provider egress remain absent or
disabled. A fresh exact T2 decision is required after deterministic artifacts
are built and independently accepted.

## Rollback

This source change is additive and rolls back to Deploy
`d52d14f2991b165cacd6b07a771494a696d82c28`. It does not reinterpret, reset or
reuse the immutable predecessor 2/2 or dual-state v2 1/1 lineages.
