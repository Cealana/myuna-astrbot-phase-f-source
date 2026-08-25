# ADR-028: Natural Degradation R2B Gateway / AstrBot protocol

## Status

Isolated repository candidate. Not wired, installed, activated or observed.

## Context

The current QQ owner runtime returns either a normal reply or the broad
`owner-runtime-unavailable` code. The AstrBot plugin converts the latter into a
single hard-coded sentence. This loses the already-known failure category,
makes different incidents look identical, and cannot distinguish a provider
transient failure from an Owner-action-required budget or authentication issue.

Core R2A now defines `myuna.safe-degradation.v1`, but deliberately does not wire
it into `conversation.py`, `http_api.py`, the Gateway or AstrBot. R2B must define
the cross-process contract without changing current visible QQ behaviour.

## Decision

Add the versioned top-level response schema `myuna.gateway-response.v2` with
exactly two successful kinds:

- `accepted_reply`: one bounded ordinary text reply;
- `safe_degraded_reply`: one exact `myuna.safe-degradation.v1` projection.

The Gateway owns encoding and validates a Core projection before transport.
AstrBot independently validates the same closed schema before displaying only
the canonical `reply` field. The two validators are intentionally separated by
the process and deployment boundary; a Golden fixture proves that their closed
category and text tables remain equal.

During a future staged migration, the AstrBot decoder may continue accepting
the current exact v1 normal/rejection shapes. Compatibility does not permit an
unknown v2 field, kind, category or schema to fall back to a normal reply.

If Core is entirely unreachable, the Gateway may construct only the fixed
content-free `core_or_gateway_failure` projection supplied by this module. It
must not include an exception, upstream response, message text, prompt, log,
account identifier, Secret or model-generated explanation.

## Validation and failure behaviour

Both boundaries reject:

- unknown schema versions, response kinds, categories or recovery states;
- extra or missing fields;
- integer values used as booleans;
- unsafe detail codes or fingerprints;
- free-form or non-canonical degradation text;
- empty replies and responses larger than the local socket limit.

Protocol errors use fixed content-free exceptions and never echo the rejected
payload. AstrBot remains a channel interface: it disables its own LLM path and
does not call a provider, memory service or tool to rewrite a failure.

## Deliberate non-wiring

R2B adds the Gateway encoder and upgrades the repository copy of the AstrBot
decoder/handler, but `qq_owner_runtime_gateway.py` does not import the new
module. The active immutable plugin directory is not changed. There is no new
marker, socket, systemd unit, database object, EnvironmentFile or Secret.

Therefore applying this candidate to the formal deploy repository would still
not alter the running QQ path. Installation and runtime use remain forbidden.

## Next stages

1. R2B formal deploy-repository application under a separate exact digest.
2. R2C metadata-only Shadow: compare current broad fallbacks with the typed
   category/detail projection without changing the reply sent to QQ.
3. R2D narrow live activation: wire and install one verified fallback category,
   retain the current response as an immediate rollback, and expand only after
   explicit acceptance.

Persistent notification deduplication, local-model rewriting, automatic
recovery, cross-channel delivery and the complete modularity audit remain
separate work and approvals.
