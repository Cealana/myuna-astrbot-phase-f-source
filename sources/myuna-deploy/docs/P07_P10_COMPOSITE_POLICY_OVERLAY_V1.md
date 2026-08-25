# P07/P10 composite policy-overlay contract v1

Status: T1 source contract only. No formal preflight, plan freeze, backup,
attempt, installation, selection, restart, live mutation, or Owner E2E is
authorized by this document.

## Decision

The existing `activate_p07_policy_overlay_v1.py` remains the sole owner of the
P07 policy-overlay state, backup, and two-attempt ledger. It is not replaced or
reset. A new composite controller adds closed source and predecessor bindings
around that transaction because the original v1 controller does not explicitly
bind the later P10 `/Check` ingress bytes, inactive P09 compatibility, P16/P01
attempt lineages, or the preserved rejected P07 formal invocation.

The immutable parent remains generation 13 with epoch
`telegram-owner-private-external-d-reset-v7`. The composite changes provider
projection policy only; it never changes the parent `release_set_id`, rewrites
the epoch, creates a new epoch, or migrates session/turn/summary data.

## Closed identities

The content-addressed contract binds:

- generation-13 parent manifest, selector, release-set and epoch identity;
- Effective V6 and the profile-free `p07-hybrid-v2` runtime lane;
- exact current Core/runtime/plugin artifacts and exact P10 ingress source
  blobs;
- `p07-hybrid-verbatim-first-v1` with the reviewed 200,000 request-character,
  199,000 projection-character, serialized-byte and token oracles and at most
  64 complete turns;
- inactive P09 V7/structured-affinity state;
- the preserved P07 rejected formal invocation and unchanged P07 `0/2`, P16
  `1/2`, and P01 `2/2` lineages;
- exact compressed-parent rollback semantics and fixed-field provenance.

Unknown fields, missing evidence, wrong source or artifact bytes, a changed
parent/epoch/config/credential projection, mixed overlay documents, a stale or
replayed identity, or any attempt-lineage drift rejects before provider egress.

## Future activation and rollback

A future separately authorized T2 must start a new exactly-two-call formal
preflight sequence while preserving the old rejected call as immutable
evidence. Both calls must be identical with no intervening mutation. This is a
new invocation sequence, not a new attempt series: it must continue using
`/var/lib/myuna-telegram-gateway/p07-policy-overlay-v1` and its existing
maximum of two attempts.

The future transaction order is plan-bound backup, shared-P07 attempt
consumption, inactive release install, service stop, Core/runtime bindings,
overlay manifest/state/selector/marker, service start, then fixed-field
verification. The marker is last so partial state remains disabled.

Rollback removes the marker first, preserves failed overlay documents as
evidence, restores exact Core/runtime bindings, restarts the target services,
and verifies Effective V6 plus the compressed generation-13 parent twice. The
epoch/session/turn/summary store is never copied, renamed, checkpointed, or
rewritten.

`/Check` remains a deterministic command lane: the plugin admits it into the
signed Owner-private Gateway path, the Gateway projects one user turn, and Core
handles it without P07 epoch/history access or external messaging. This
contract does not send `/Check` and does not infer live acceptance.
