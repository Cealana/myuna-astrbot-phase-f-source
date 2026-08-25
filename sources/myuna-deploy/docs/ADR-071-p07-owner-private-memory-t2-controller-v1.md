# ADR-071: P07 owner-private memory T2 controller v1

## Status

Accepted for source verification. Live selection remains a separate digest-bound gate.

## Decision

The memory successor is an additive selection over the immutable generation-13
release set and reset-v7 epoch. It uses the existing P07 policy-overlay attempt,
state, and backup namespace; the earlier rejected formal call remains separate
immutable evidence and does not consume an attempt.

The content-addressed memory release set binds exact Core, Telegram runtime and
plugin artifacts; the protected runtime configuration and effective credential
projection; the generation-13 parent manifest, selector, epoch and aggregate;
Effective V6; P08 and P15 public identities; the P10-B trusted-time package; the
approved historical-recall and reflective-diary egress contracts; and the
calendar-zone selector.

Selection consists of two protected documents plus one Core service drop-in:

- `p07-owner-private-memory-selector-v3.json` selects the local lossless archive,
  raw-preferred retrieval and dynamic context policy.
- `p07-reflective-diary-egress-selector-v1.json` binds the separately approved
  closed-day diary purpose, model role, style and persona provenance.
- `90-p07-owner-private-memory-v1.conf` binds Core to the exact policy, memory
  release set and diary egress digests.

Both selectors must agree on parent, archive, policy, identities and egress
digests. Partial, stale, replayed or mixed state fails before provider egress.
The archive root is new and empty. Existing epoch/session/turn/summary data is
neither read for migration nor rewritten; only turns completed after selection
can enter the archive.

## Activation and rollback

The controller creates a plan-bound backup before consuming attempt 1, installs
immutable releases, stops only the Core and Telegram target units, writes the
three selection documents atomically, switches the Telegram plugin through the
existing resume controller, and starts the target units. Two fixed-field
observations must agree and prove an empty archive/index/diary, unchanged parent
epoch, Effective V6, P08 identity, stable services and exact container mount.

On any activation failure the same invocation performs one bounded rollback:
new selection documents are moved into the plan backup as evidence, exact prior
Core/runtime/plugin bytes are restored, the resume controller restores the old
plugin mount, and the accepted compressed generation-13 functional prestate is
observed twice. The local archive root is retained but unselected; it is never
deleted or used as authority after rollback.

## Privacy boundary

Preflight, activation and postflight expose only counts, booleans, categories
and digests. They do not call a provider, model, channel or health endpoint and
do not generate a diary. Historical raw recall and reflective diary egress are
product-runtime purposes only after Owner-private selection; this controller
never reads or transmits private content.
