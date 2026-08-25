# P16 generation12 / V7-B / P15 diagnostics compatibility matrix v2

Status: `EXACT_MAIN_IDENTITIES_RECONCILED_SOURCE_CANDIDATE`

This source-only successor reconciles the accepted P16 v1 candidate
`b6d0cef33d4bec46a2d9cc75d70e7cf45f61eaa4` onto stable Core main
`527fc1aed963fd3627791e6fafeb8e14bc5bc882` and Deploy main
`2ca38e1c8607a5cc5bd7e474a4ffb6ebac574eac`. It preserves the v0/v1 Git
objects, refs, and worktrees; it does not cherry-pick or rewrite them.

The v1 semantic projection over `policies`, `generation12`, and `v7_phase_b`
is unchanged. Its canonical SHA-256 remains
`18c42a102993bde1a07263946689cfab7ec21678e9e34b6e24e55c0b2a6d888a`.
Only dependency identity/status and the now-committed P15 compatibility seam
are added.

## Stable source identity

- generation12 remains rooted at Core `8529ef1f...` and Deploy `2819d5cf...`;
  both are ancestors of the current stable mains.
- P09 is now committed on Core main through source commit `31250bbd...` with
  schema `myuna.structured-affinity.v1` and capability digest
  `bc28be2f125bb7099859dd366d54d59f48053db670ad2d841482c15fa50d5096`.
- P15 is committed on both mains. Its Core contract is
  `myuna.p15-cross-source-orchestration-contract.v1`; its Deploy identity
  contract is `myuna.p15-deploy-contract.v1`, digest
  `17c1eaa53175f1f225218dd0abe4a286cde93289a1feca7c0241b6a0560f8a17`.

## Preserved public semantics

- Fresh external-context continuity reset is a normal transition, not a
  fault.
- Complete reverse rollback `p08 -> telegram_plugin -> p07` is recovery, not
  a new incident.
- Partial or functionally incomplete rollback is a hard stop at
  `combined_functional_rollback_failed`, but source evidence alone creates no
  public code or incident ref.
- Affinity capability absence and intentional abstention are non-fault states.
  `affinity_dependency_unavailable` remains typed but has no dedicated public
  binding in this source-only matrix.
- `MYU-TIME-01` and `MYU-TEMPORAL-01` remain conditional on actual exact
  underlying evidence. No synthetic row creates either code or a ref.

## P15 relevance and retention seam

P15 selection has statuses `select`, `clarify`, and `abstain`. Its result
contract rejects `fault=true`; an authorized continuity reset is carried as
`normal_transition=true`. Capability-unavailable, duplicate, and budget cases
are typed retention decisions, while required-provenance failure produces a
typed abstention. None is automatically a P16 incident.

The fixture therefore records these typed outcomes without generating a
public projection. A later runtime mapper would still require actual
content-free incident evidence and a separately reviewed public binding.

## Boundary

This candidate contains only this document, one synthetic fixture, and one
test. It does not build, install, select, activate, deploy, restart, call a
channel/model/provider/health endpoint, inspect private content, or perform an
Owner E2E. `myuna.user-visible-fault.v1` is unchanged.
