# ADR-053: Owner Profile activation boundary v1

Status: accepted; local read service active; live prompt injection blocked

## Context

P07-A now has an Owner-approved private revision 2 candidate and a repository-only
loader/index/projection. Two independent gaps prevent safe conversation activation:

1. the selected Core models are external DeepSeek models, while this Work explicitly does
   not authorize disclosure of the real Profile to DeepSeek; and
2. the live QQ and Telegram gateways authenticate their own channel-specific loopback
   credentials, but the legacy chat payload does not carry the already verified
   Owner/private/channel context into Core.

Installing a file or starting an unused socket does not resolve either gap. Conversely,
leaving the whole Profile in every prompt would violate the relevance and minimization
requirements even after both gaps are resolved.

## Decision

P07 uses four separate gates. Every gate must succeed for a Profile section to reach a
model request:

1. the gateway verifies the signed inbound event, durable claim, exact Owner binding and
   private-conversation scope;
2. Core authenticates the channel-specific HTTP client and parses an exact
   `AuthenticatedConversationContext` bound to the same client/channel;
3. the channel-neutral capability profile authorizes `conversation` plus
   `long_term_memory_read` for that Owner/private/channel context; and
4. the selected provider is in an explicit Profile egress allowlist.

A missing or conflicting field fails closed before Profile retrieval. HTTP client headers
alone are insufficient Profile authority. Profile text, query text, source refs and digest
never enter the authorization decision.

## Provider egress

P07 v1 structurally forbids `deepseek` for real Profile context. The only names accepted by
the source allowlist are `local` and `openai`; either still requires an explicit deployment
selection and privacy authorization. Unknown providers fail closed.

This ADR does not authorize OpenAI disclosure, add an OpenAI provider implementation, add
credentials or select a local model. With the current DeepSeek route, Core may continue
ordinary conversation but must not call the Profile service or add Profile state text to
the prompt. A content-free denial category may be audited.

## Read-only service

The new operation is `owner_profile.retrieve_v1` on
`/run/myuna-owner-profile-read-v1/profile.sock`. It is separate from every legacy Owner
Memory operation, socket, namespace and database role.

The worker:

- starts as dedicated `myuna_owner_profile`, never root;
- loads one exact content-addressed release using a separately pinned SHA-256 and uid;
- validates `0700/0600`, type, owner, digest, receipt, revision and release name;
- builds one deterministic in-memory index;
- accepts only QQ or Telegram authenticated-channel labels supplied by Core;
- returns at most three relevant sections and never performs a model or memory write; and
- uses `PrivateNetwork`, an AF_UNIX-only address family and a read-only release mount.

The Core-side client reconstructs the prompt context from strict section fields instead
of trusting an opaque context string. Its audit uses only `owner_profile_read_v1` metadata.

## Private installation

The immutable content release remains:

`/var/lib/myuna-owner-profile-v1/releases/r<revision>-<sha256>/`

The first installation must copy the already approved exact bytes and receipt without
normalizing or rewriting them. If the destination exists, the installer verifies equality
and never overwrites it. The Owner approval marker stays in the Owner-controlled draft
location and is used only as intake evidence; it is not copied into the runtime release.

The service selector is root-controlled, pins the exact release path, SHA-256, dedicated
uid and code release, and is backed up before change. Rollback selects a preserved prior
approved release; it does not edit or delete releases, drafts, receipts or approval records.

This remains plaintext local storage protected by Unix ownership, modes and systemd
sandboxing. No encryption claim is made.

## Channel migration

The existing gateway runtime already verifies the exact Owner binding before Core access.
The migration adds a content-free authenticated context to the Core request only after that
verification. It contains opaque binding/principal/namespace identifiers and fixed consent
booleans, but no raw account identifier, account fingerprint, message duplication, secret
or provider data.

Telegram is the primary new-capability channel. QQ may be listed in the same profile only
while its existing Owner-only gateway and channel-specific Core credential remain valid;
neither channel grants access to groups, members, other accounts or other clients.

## Failure behavior

Any of these outcomes produces no Profile context and no fallback to legacy memory,
session history, P08 or P10:

- absent/malformed authenticated context;
- client/channel mismatch or non-Owner/non-private context;
- capability-profile mismatch;
- DeepSeek, unknown or non-allowlisted provider;
- socket timeout/unavailable/oversize/malformed response;
- profile schema/digest/receipt/permission/type drift; or
- empty lexical relevance.

The ordinary conversation path may continue without Profile only when its existing policy
already permits that degradation. It must never claim Profile use or remembered facts.

## Activation gates

Source completion requires focused/full tests, deterministic build, independent diff review
and rollback refs. Private service installation may occur after exact-byte intake checks,
but conversation activation additionally requires:

- a non-DeepSeek provider with explicit Owner privacy authorization;
- authenticated-context migration for the selected channel;
- a matching channel-neutral capability profile;
- Core release selection and bounded restart; and
- content-free local/service checks followed by one Owner-private E2E.

Until all conversation gates exist, the accurate state is
`PROFILE_SERVICE_SOURCE_READY_PROVIDER_EGRESS_BLOCKED`, not live Profile retrieval.

## Implementation status - 2026-08-01

- The dedicated identity, immutable Profile release, root-only selector, systemd socket and
  read-only service are installed. Unit verification and one content-suppressed local socket
  probe passed without a provider, channel, health-endpoint or memory-write call.
- The local result included both relevant selection and empty relevance with bounded output;
  audit/status projection remained content-free and no legacy namespace was written.
- The precise live state is `LOCAL_READ_SERVICE_READY_PROVIDER_EGRESS_BLOCKED`. Real
  Owner-channel E2E requires a separately authorized non-DeepSeek provider and selected
  authenticated channel consumer.
