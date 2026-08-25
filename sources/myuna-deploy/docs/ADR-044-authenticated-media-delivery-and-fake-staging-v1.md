# ADR-044: Authenticated Media Delivery and Fake Staging v1

Status: R1 repository-only / inactive / offline evaluation only

## Decision

Media delivery is represented as metadata bound to an existing
`AuthenticatedConversationContext`. It does not create a second identity system
and does not infer Owner authority from a Telegram or QQ account name.

An offline policy requires all of the following:

- an authenticated Owner/private context;
- explicit media-processing consent;
- a channel-neutral authorization decision containing `vision`;
- exact principal, namespace, and channel agreement between context and decision;
- bounded age, future skew, media count, question, and analysis modes.

Only then may the delivery be projected into a `VisionInputEnvelope`.

## Fake staging

`InMemoryVisionMediaStagingFake` implements the previously defined staging port
for offline contract and integration tests. It:

- receives already bounded streams;
- reads at most the declared byte length plus one byte;
- checks declared length and SHA-256;
- issues opaque tickets and short, single-read leases;
- removes bytes immediately after the single read;
- disposes or expires all remaining bytes;
- emits metadata-only receipts;
- uses injected time and ID factories;
- has no filesystem path, network, platform SDK, model, memory, or tool access.

It is not a production staging implementation and must not be wired into live
QQ or Telegram.

## Current compatibility boundary

The active channel envelope remains text-only and the active channel-neutral
capability profile keeps `vision=false`. This R1 therefore cannot make live media
reachable. The future transport adapter must create the authenticated media
delivery only after platform authentication and bounded download, without
placing raw platform file identifiers in Core or audit payloads.

## Non-effects

R1 adds two Core modules, offline tests, one inactive policy, this ADR, and a
repository contract test. It creates no system user, directory, file store,
Socket, Service, Timer, capability grant, provider configuration, or Secret. It
does not download a real image, connect a channel, call a model, modify prompts,
write memory, invoke tools, or restart anything.

## Next gate

Before any real Telegram Vision Shadow:

1. add thin Telegram media transport and Fake transport parity tests;
2. choose and offline-evaluate provider adapters with fixed image fixtures;
3. implement a private filesystem staging candidate with no-follow and quota
   checks;
4. build inactive content-addressed releases;
5. run metadata-only observation before enabling provider calls.
