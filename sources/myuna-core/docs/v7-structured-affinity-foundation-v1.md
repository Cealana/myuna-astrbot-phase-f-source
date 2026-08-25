# V7 structured-affinity foundation v1

Status: inactive T1 source contract. This document does not authorize or describe a live state.

## Frozen first-segment decisions

- The namespace is `myuna.structured-affinity.v1`; it does not reuse legacy Trust storage or identifiers.
- Five long-term dimensions and five short-term dimensions are versioned fields. Values, when a future authorized implementation supplies them, are internal integers from 0 through 100. This source contains no Owner bootstrap or default value.
- Confidence is a categorical evidence band (`none`, `low`, `medium`, `high`), not a probability. `none` cannot accompany a value.
- Abstention is a first-class decision. Insufficient, conflicting, unauthorized, unavailable or schema-unknown evidence creates no value claim.
- A proposal is provisional. Confirmation requires non-regressing confidence and an additional distinct evidence reference. An update returns to provisional; conflict hides the disputed value; repair also returns to provisional and cannot self-confirm.
- The reducer is synthetic-only and performs no I/O. It rejects live sources, durable time, Profile/session/DB content, persistence, retrieval, projection, migration and writer behavior.
- Evidence seams carry only typed references and revisions. They do not copy Profile, P07 context or P08 temporal content into the affinity namespace.
- Diagnostics are content-free and omit values and evidence references.

## Dependency seams

| Dependency | Current boundary |
|---|---|
| P07 Owner Profile | Reference-only protocol; no Profile read or write is performed. |
| P07 external context | Reference-only protocol; generation12 release-set files are untouched. |
| P08 temporal context | Reference-only protocol; no temporal service or activator path is touched. |
| P10 trusted time | Dependency checkpoint: the current concrete consumer binding is not assigned to P09. Only a future port shape is frozen. |
| P15 relevance | Dependency checkpoint: the general relevance contract is not yet frozen. Only a future ranker port shape is frozen. |
| P16 diagnostics | Content-free event protocol only; no public codebook or live diagnostic wiring is changed. |

## Explicitly inactive capabilities

Bootstrap, persistence, writer, retrieval, prompt projection, legacy Trust migration and live state transitions are all false in `AffinityCapabilityContract.phase_b_foundation()`. Phase A Definition remains independently deliverable and is not selected or modified by this package.

## Future gates

Before any non-synthetic state can exist, a later P09/P12 gate must separately freeze storage ownership, event and snapshot durability, conflict authorization, writer/retrieval policy, P10 consumer identity, P15 ranking behavior, P16 public mapping, migration/bootstrap approval, rollback and live activation. None is implied by this candidate.
