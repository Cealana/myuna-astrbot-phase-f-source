# P07 projection-policy overlay v1

Status: source-only candidate. This document is the frozen interface/ADR for
selecting `p07-hybrid-verbatim-first-v1` without replacing or rewriting the
accepted generation13 schema-v3 epoch.

## Decision

The generation13 P07 release set remains the immutable persistence parent. Its
`release_set_id`, epoch identity/path, committed turns, summaries, delivery
receipts, and pending state are not migrated or rewritten. A separate protected
overlay may change only the provider-visible projection policy.

The overlay is selected by four exact content-free JSON documents:

- `p07-policy-overlay-v1.json`: semantic manifest and `overlay_id`;
- `p07-policy-overlay-selector-v1.json`: exact manifest bytes plus state;
- `p07-policy-overlay-marker-v1.json`: exact selector and state bytes;
- `p07-policy-overlay-state-v1.json`: monotonic transition state.

All four documents are root-owned, group-readable protected files. When all
four are absent, the runtime uses the parent compressed policy exactly. A
terminal `compressed` state may remain after rollback while the other three
active files are absent. Any other partial, mixed, unknown, stale, or malformed
combination fails before provider egress.

## Bound identity

The manifest binds:

- parent generation13 `release_set_id`, manifest-file digest, selector digest,
  epoch identity digest, epoch ID, and epoch path;
- exact Core, Telegram runtime, Telegram plugin, and selected plugin-config
  digests;
- protected RuntimeConfig content/binding digests;
- effective credential projection/drop-in digests and exact count one, never a
  credential value;
- policy/version/digest and the reviewed 200,000 input-character contract,
  199,000 projection-character headroom, 1,198,096 serialized-byte limit,
  999,232 conservative input-token limit, and at most 64 complete turns;
- compressed fallback policy: at most six complete turns / 12,000 characters,
  or a typed failure if the bounded summary+tail is unavailable;
- content-free Core/Deploy source provenance.

Core verifies the selected overlay, immutable parent, and its own installed
Core release identity. Telegram runtime verifies the same protected snapshot,
the parent RuntimeConfig binding, and its own installed runtime identity. A
later T2 gate must independently verify the exact plugin/config identities and
install/select the four documents as one stopped-service transaction.

## Release-bound messages

Overlay traffic uses `myuna.external-context-release-bound.v2` and
`myuna.external-turn-provenance.v3`, each carrying both the immutable parent
`release_set_id` and exact `policy_overlay_id`. The existing v1/v2 wrappers are
unchanged when the overlay is absent. Runtime and Core reject cross-version,
missing, double, wrong-parent, or wrong-overlay combinations before provider
egress or delivery commit.

Summary jobs and candidates remain bound to the immutable parent release set.
Historical provenance from the same parent remains readable; new delivered
turns record the overlay ID. No database schema or row rewrite is required.

## Closed transitions and rollback

Allowed transitions are:

1. no state -> sequence 1 active overlay;
2. active overlay -> next sequence compressed terminal state;
3. compressed terminal state -> next sequence new active overlay.

Every transition binds the prior state digest. Replaying an old active selector
against a terminal state is rejected. Rollback removes the three active files
and preserves the next compressed terminal state; this selects the exact parent
compressed policy while leaving epoch data untouched.

## Privacy and audit

Overlay documents contain only identities, digests, numeric limits, booleans,
and source commits. They contain no message, summary, Profile text, query,
provider payload, response, credential value, database row, or raw log. Audit
may project only schema, status, sequence, parent ID, overlay ID, and typed gate.

## Deferred T2 gate

This source candidate does not provide activation authority. A later T2 gate
must generate a fresh current-head Core/runtime bundle, bind exact live parent
and plugin identities, prove stopped-service atomic apply and bounded rollback,
run two read-only preflights if authorized, and receive a separate Owner organic
E2E gate. The current compressed generation13 release remains the rollback.
