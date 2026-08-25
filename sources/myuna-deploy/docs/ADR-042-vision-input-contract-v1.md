# ADR-042: Vision Input Contract v1

Status: R1 repository-only / inactive / not connected to QQ or Telegram

## Decision

Image understanding is introduced as a separate bounded adapter contract, not as
another responsibility of the channel gateway, reply contract, memory system, or
tool system. A future channel adapter may stage verified image bytes behind a
short-lived media source and submit only a typed descriptor plus an authenticated
conversation context.

The contract has four distinct boundaries:

1. the channel transport authenticates the sender and downloads media;
2. the media boundary verifies MIME type, byte count, dimensions, and SHA-256;
3. a capability decision must explicitly grant `vision` and the context must carry
   media-processing consent;
4. a provider adapter returns a `VisionObservation`, which is untrusted evidence
   for conversation and never an instruction or authority source.

## R1 policy

- JPEG, PNG, and WebP only;
- one to four images;
- at most 8 MiB per image and 16 MiB total;
- at most 8192 pixels on either dimension;
- describe, question-answer, and OCR-assist modes;
- no remote URL fetch;
- no memory write;
- no tool or external action;
- no image-derived instruction execution.

The provider and model are registry references. They are not hard-coded model
names, endpoints, or credentials.

## Data separation

Raw bytes, local paths, remote URLs, account identifiers, credentials, and the
user question are excluded from audit metadata. Image bytes are available only
through `VisionMediaSourcePort`, are length/hash checked, and are not embedded in
the structured request or logs.

OCR and any other text extracted from a picture remain tagged
`untrusted_media_content`. The observation schema has no memory mutation, tool,
external action, authority, or approval field.

## Current non-effects

The current channel-neutral capability profile intentionally keeps `vision=false`,
and the current authenticated context still advertises text delivery only. This R1
therefore cannot be activated accidentally. It adds only a Core contract, an
inactive policy example, tests, and this ADR. It does not download media, call a
vision provider, alter prompts, connect QQ/Telegram, write memory, or restart a
service.

## Follow-up

1. define a media staging and disposal contract;
2. define an authenticated context v2/media delivery extension;
3. build provider adapters behind the registry;
4. run offline fixtures, prompt-injection images, OCR, meme, and Chinese-quality
   evaluations;
5. install inactive releases and observe metadata before any Owner-private opt-in.
