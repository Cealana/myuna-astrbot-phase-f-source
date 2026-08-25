# ADR-039: Modularity Remediation Wave 1 authenticated context

Status: R1 repository-only / inactive / not wired to any runtime

## Decision

Myuna will use a channel-neutral authenticated conversation context between a
verified channel boundary and Core policy.  The context is operational metadata,
not conversation text, not prompt content, and not memory.

The contract binds:

- the authenticated internal client and its channel kind;
- the verified binding, principal, and namespace;
- the channel instance, conversation, event, trace, request, and correlation IDs;
- private/group and authority metadata;
- delivery and explicit consent flags.

It never carries raw platform account IDs, account fingerprints, credentials,
message text, model output, memory content, or tool input.

## Channel-neutral capability profile

The R1 example grants the same verified Owner private text boundary to QQ and
Telegram.  The channels continue to use separate accounts, tokens, signing
secrets, system users, database roles, bindings, rate limits, and transport
adapters.  Sharing an authorization contract does not merge those trust
boundaries.

The neutral response scope is
`owner_private_dev_readonly_memory_v2`.  It replaces QQ-specific naming only in
this inactive candidate.  Existing schema-v1 runtime manifests and live service
configuration remain unchanged.

The R1 profile keeps all of the following disabled:

- long-term memory writes;
- vision and media processing;
- tools;
- external data and external actions;
- system administration;
- group conversations and non-Owner authorities.

## Fail-closed rules

The future Core boundary must reject a request when:

- the authenticated HTTP client channel differs from the verified event channel;
- the internal context contains missing or extra fields;
- the selected profile does not allow the channel, authority, conversation kind,
  delivery capability, requested capability, or explicit consent;
- memory protocol, memory-read grant, and response scope disagree.

The message body cannot assert or override any context field.

## R1 non-effects

R1 adds contracts, tests, this ADR, and an inactive configuration example only.
It does not:

- modify the active capability manifest;
- modify `http_api.py`, `conversation.py`, or either live Gateway;
- install or select a Core/Definition release;
- change systemd, credentials, databases, QQ, Telegram, memory, providers, tools,
  vision, networking, Minecraft, or backups.

## Follow-up

1. Effective Runtime Profile v1 binds a Core Release, Definition Release,
   channel-neutral capability profile, memory adapter, reply contract, provider
   policy, and prompt budget as one inactive identity.
2. Shared Gateway Runtime Kernel v1 creates the context from separately
   authenticated QQ and Telegram adapters.
3. A later, separately approved Core bridge consumes the context before any live
   runtime changes.
