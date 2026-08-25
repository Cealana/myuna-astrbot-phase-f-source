# ADR-078: Immutable failed-request continuation

Status: accepted for inactive T1 source; this decision creates no live continuation, request, plan, or attempt.

## Context

The P07 source-owned request collection is terminal at exactly two immutable children. The second request was canonical, but its only executed prepare-package call ended with the typed content-free rejection `production_p08_content_free_status_unavailable`. The rejection, request files, and collection inventory are historical evidence. They cannot be replayed, relabelled, deleted, edited, or interpreted as ready. A third request is forbidden.

P08 later reached a separately accepted metadata-only repair checkpoint. That fact does not change the old rejection and is not a fresh P08 status result for P07.

## Decision

P07 defines `p07-owner-private-memory-immutable-failed-request-continuation-v1`. A continuation is not a request and never dispatches the terminal request. It is a content-addressed, append-only bridge that may be materialized once in a separate protected collection by a future compatible T2.

The source-owned constructor verifies all of the following before producing continuation bytes:

- the request collection remains canonical, closed, count two, and exact by collection digest;
- the second request ID and its request, receipt, and completion hashes are exact;
- the terminal handoff and canonical rejection receipt are exact, and the rejection remains rejected;
- the accepted P08 repair handoff, release, manifest, source and installed inventories, controller, selector, selector environment, and acceptance projection are exact fixed identities;
- immutable predecessor lineages remain exact;
- the current Core and Deploy source, runtime, plugin, bundle, policy, service, and P08 client identities reopen through reviewed validators;
- the terminal request's projected product intent equals the current source-derived target intent, while current target artifacts are independently bound as successors. No third request object or request-collection child is constructed for this comparison.

The continuation records `fresh_p08_status_required=true` and status `awaiting_fresh_p08_status`. A future fresh authenticated P08 content-free status is a new gate. It cannot replace or rewrite the historical unavailable result.

## Storage and crash contract

The gateway data directory is service-owned and is never a continuation parent or compatibility alias. Continuation persistence has a separately versioned source identity, `p07-owner-private-memory-failed-request-continuation-root-owned-storage-v1`, rooted at the fixed trusted ancestor `/var/lib` (`root:root`, `0755`). The source-owned materializer exclusively creates the dedicated protected parent `/var/lib/myuna-p07-owner-private-memory-failed-request-continuations-v1` (`root:root`, `0700`) and its sole collection root `continuations` (`root:root`, `0700`). It never recursively changes ownership or mode on an existing path.

Before the first write, the ancestor, path relationships, roles, owner, type and modes are exact, while both dedicated paths must be absent. `mkdir` provides exclusive parent and root creation; each creation is read back and directory-fsynced. A pre-existing parent or root, including an otherwise well-formed partial creation, is immutable crash evidence and rejects rather than being resumed or removed. The completed parent and root each have exact link count three and exact one-child inventories. The collection child is `0700`, link count two; its three regular files are `0600`, single-link, canonical ASCII JSON.

Materialization uses an exclusive temporary sibling, write/read-back verification, file and directory fsync, completion marker last, and no-replace atomic rename. Any temp residue, extra entry, partial state, symlink, hardlink, owner/mode/type drift, wrong path or role, concurrent writer, replay, or content mismatch fails closed. No residue is silently resumed or deleted. The request collection remains closed at two and is outside this namespace.

## Downstream contract

The target-byte package context binds the exact continuation. Production package preparation consumes source-derived target material directly, without a third request object. Backup, preflight, activation, and postflight reopen the persisted continuation and compare it with package context before progressing. The legacy terminal request cannot enter the production prepare-package path. The request collection maximum remains two.

No continuation alone authorizes live work. A future T2 must separately create the continuation before mutation, obtain a fresh P08 status, establish a fresh public prestate and rollback proof, and satisfy its own plan, backup, preflight, and attempt gates.

## Privacy and rollback

Continuation, receipt, and completion contain fixed hashes, IDs, schemas, categories, counts, booleans, and public source/release identities only. They contain no raw turns, temporal facts, Profile or database rows, logs, credentials, provider payloads, model output, or channel content.

The inactive source change has no live rollback requirement. Source rollback is the additive pre-main ref. A future live rollback remains exact reverse restoration to its freshly observed predecessor and never rewrites request or continuation evidence.
