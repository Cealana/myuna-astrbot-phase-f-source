# ADR-045: Telegram Thin Media Transport v1

Status: R1 repository-only / inactive / Fake ports only

## Decision

Telegram media handling is a thin channel adapter around a channel-neutral pure
builder. The adapter owns only:

1. checking that an already authenticated context is Telegram Owner/private with
   explicit media consent;
2. asking an injected download port for bounded bytes;
3. asking an injected media probe for decoded MIME and dimensions;
4. comparing Telegram size/dimension hints with the independent probe result;
5. passing bytes and verified metadata to the shared media transport kernel.

The shared kernel derives content hashes and opaque IDs, creates
`AuthenticatedMediaDelivery`, and provides a one-shot stream handoff to the
staging port. The platform file reference is never included in that delivery,
its audit metadata, or object representation.

## Fake parity

`FakeAuthenticatedMediaTransportAdapter` accepts only injected synthetic bytes
and verified inspection results, then calls the same shared builder. Offline tests
require the Telegram and Fake adapters to produce identical authenticated media
delivery and audit metadata for identical content.

The test chain continues through `InMemoryVisionMediaStagingFake`, including
one-shot handoff, length/hash verification, lease, and read. No Telegram SDK or
API is imported or called.

## Trust boundary

Telegram-reported MIME is not accepted. Telegram width, height, and byte count
are hints that must match independently obtained results. The R1 probe is only a
Protocol with a Fake implementation; a production decoder is deliberately absent.

Raw platform file references may be used only inside the injected download port
and opaque-ID derivation. A future implementation must use a keyed derivation;
the deterministic hash factory in tests is not a production identity mechanism.

## Non-effects

R1 adds pure Deploy modules, Fake tests, and this ADR. It does not modify the
active AstrBot plugin or Telegram Gateway, read the Bot Token, call Telegram,
download a real image, create a staging directory, install a release, change a
capability, call a model, alter a prompt, write memory, invoke tools, or restart a
service.

## Next gate

1. add malicious/truncated/polyglot fixture evaluation and a real decoder candidate;
2. define the provider adapter registry and offline vision quality suite;
3. build inactive content-addressed media/Gateway releases;
4. only then prepare metadata-only Telegram Vision Shadow.
