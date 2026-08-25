# ADR-062: Contextual Visual Interpretation v1

Status: T1 exact-head reconciliation candidate after P16 acceptance; current
main and live unchanged

## Decision

P01-B extends the accepted Telegram Owner-private Photo+Caption path without
reopening the original P01 milestone. Gemini remains a bounded visual evidence
extractor. Myuna Core performs the only contextual interpretation generation,
using DeepSeek once with approved Definition/Profile projection, recent external
epoch turns, the authenticated Caption/current request, and a separately marked
untrusted visual observation.

## AstrBot sourcing decision

The installed AstrBot 4.26.6 capability was inspected before custom work. Its
public `Image` component, media resolver, `ProviderGoogleGenAI.assemble_context`,
and provider query path remain the media/provider implementation. No installed
built-in or official adapter provides the required signed visual event, three-way
trust separation, Core projection, or delivery-ack epoch semantics. Custom code
is therefore limited to those Myuna boundary functions.

## Versioned contracts

- Channel visual event: `myuna.telegram-visual-evidence.v1`.
- Core visual context envelope: `myuna.external-context-envelope.v2`.
- Projection policy: `p01b-contextual-visual-interpretation-v1`.
- Structured result: `myuna.visual-interpretation-result.v1`.

The visual event contains only `caption_present`, the bounded observation,
schema, and source. A dedicated HMAC binds its canonical bytes to the already
signed channel-event signature. The runtime verifies both signatures before the
durable inbound claim and includes the complete verified envelope only in the
content-free claim digest.

## Trust separation

1. Trusted system/context: Core supplies a fixed instruction identifying the
   observation as non-authoritative image evidence, requiring Caption/contextual
   interpretation, and forbidding execution of text or prompts found in it.
2. Authenticated Owner input: the signed channel event carries only the bounded
   Caption, or a fixed gateway request when Caption is absent.
3. Untrusted evidence: the Gemini observation remains a typed field and is
   projected as a separately labelled non-Owner message. It is never concatenated
   into the Owner message or the trusted instruction.

Caption is not sent to Gemini. Gemini receives no Profile or conversation
history. DeepSeek receives no raw media or provider payload.

## Generation and failure semantics

Visual context selects a single `json_object` DeepSeek request with thinking
disabled. The exact output fields are `schema`, `focus`, `confidence`,
`uncertainty`, and `final_reply`. Core returns only `final_reply`; audit metadata
contains the confidence enum and whether uncertainty was present. Visual output
has no repair retry. Invalid JSON, unknown fields/schema, invalid bounds, or a
low-confidence result without uncertainty fails closed. The trusted instruction
requires a concise clarification when evidence is weak or conflicts with Caption
or context.

The ordinary P07 text path remains plain text and retains its existing bounded
repair behavior.

### Truthful pre-egress and post-provider failures

The reconciled gateway performs one signed, local-only visual readiness check
before media preparation or Gemini egress. The runtime verifies the original
channel-event signature and Owner-private binding, then reads only aggregate
P07 epoch-v3 capacity state. This check does not claim the event, start a turn,
call Core, read Profile, or expose conversation content. The final visual event
still passes the complete signature, replay, identity, epoch and delivery gates.

The readiness vocabulary is fixed and content-free:

- `external_summary_required` means the bounded direct projection requires an
  already-authorized summary before another visual egress;
- `external_turn_already_pending` means an existing turn or delivery prevents a
  second in-flight turn;
- `external_context_unavailable` covers all other fail-closed local conditions.

A preflight failure states that neither the visual provider nor DeepSeek,
memory, or tools ran. If Gemini has already produced bounded evidence and the
subsequent local context gate fails, the fixed response states that visual
evidence extraction occurred and only claims that DeepSeek, memory, and tools
did not run. The product must never return the generic “no model called” safety
projection after visual-provider egress.

This reconciliation supports both the retained epoch implementation and the
active release-bound epoch-v3 implementation. It does not raise projection
limits, truncate history, synthesize summaries, reset epochs, weaken replay or
identity gates, or fall back to context-free generation. P08 temporal routing,
P16 pre-provider diagnostics/projection budgets, ordinary Telegram text, and
QQ remain outside the visual routing branch and retain their existing contracts.

## Persistence and delivery acknowledgement

The external epoch persists only the authenticated Caption/default request and
the delivered final reply. Visual evidence is attached to the in-memory v2 Core
envelope for the current request and is not added to SQLite schema, summaries,
recent turns, audit details, or delivery receipts. A visual turn is committed only
after the existing Telegram `after_message_sent` delivery acknowledgement; a
cancelled delivery cancels the pending turn.

No chain-of-thought, raw observation, raw media, local path, provider payload, or
provider raw response is exposed in the public response or durable epoch.

## Scope and rollback

Scope is Telegram Owner-private only. QQ, groups, other identities/channels,
provider configuration, Profile writes, and live activation are excluded.

T1 rollback is branch/ref selection back to the recorded Core and Deploy prework
commits. A future T2 activation must preserve the selected live releases and
receipts, verify combined Core/runtime/plugin egress, recheck the P01-B activation
attempt lineage, and stop if byte-exact rollback cannot be proven. This source
reconciliation does not itself mutate or authorize inference about live state.

## Accepted-P16 successor activation

P01-B activation is a separate overlay successor, not a P16 retry or lineage
rewrite. The accepted P16 bundle, marker, selector, incident history, attempt
series, activation receipt, backup, and unused attempt 2 remain byte-exact. The
P01-B bundle copies the accepted Core and P16 adapter releases unchanged and
adds only newly built Telegram runtime and plugin releases. A distinct P01-B
selector declares this layering and becomes the effective release-set evidence
without modifying the preserved P16 selector.

The P01-B attempt namespace is independent, append-only, content-free, and
limited to two attempts. Its strategy and series identifiers bind the exact P16
predecessor bundle and series, the accepted attempt-1 receipt, all target
artifact inventories, and exact Core/Deploy source commits. Attempt files form a
digest chain and are created under one root-only lock. Partial state, unknown
files, replay, digest drift, ACL/type/symlink drift, concurrent writers, or a
third attempt fail closed. A successor name cannot reset the strategy budget.

Activation installs immutable releases, writes the P01-B selector, stops only
the Telegram target, selects the new runtime/plugin through a later systemd
drop-in and existing canonical container resume controller, verifies the target,
and writes the P01-B marker last. Core, P08, generation-13 epoch state and QQ are
not mutated. Every accepted-P16 projection and history file must remain exact.
Failure removes the P01-B marker/selector/drop-in, restores the previous plugin
config byte-for-byte, recreates the canonical predecessor container, restores
the Telegram unit state, and independently re-runs the prestate verifier.
Installed failed releases, attempts, backups, and receipts are retained.
