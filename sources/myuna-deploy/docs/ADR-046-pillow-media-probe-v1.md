# ADR-046: Pillow Media Probe v1

Status: R1 repository-only / inactive decoder runtime / no channel wiring

## Decision

Use a dedicated Pillow 12.3.0 Python runtime as the first image decoder behind
`MediaProbePort`. The runtime is isolated under `/opt/myuna/vision-decoder` and
has no active binding or service. Myuna Core and channel gateways do not import
Pillow directly.

The probe accepts only JPEG, PNG, and WebP, with fixed limits of 8 MiB, 8192 by
8192, and 16 million pixels. It validates the exact container boundary, rejects
trailing payload, rejects animation, treats Pillow decompression-bomb warnings
as errors, calls `verify()`, reopens the image, and calls `load()` so malformed
pixel data cannot pass through header-only inspection.

## Trust boundary

Channel-reported MIME, dimensions, and extension are not trusted. MIME and
dimensions come from the decoder. Telegram-specific file references remain in
the Telegram Transport Adapter and are never visible to this probe.

All decoder exceptions are normalized to `media probe rejected`; file bytes,
container metadata, decoder errors, and source references are not returned in
audit or user-visible errors.

## Non-effects

R1 does not create a decoder service, current symlink, capability, provider,
prompt injection, staging directory, or Telegram binding. It does not read Bot
Token, call Telegram API, inspect real user media, call a model, read or write
memory, enable tools, modify systemd, or restart services.

## Remaining gates

1. run the decoder in a separately sandboxed worker with memory, CPU, and time limits;
2. add a larger malicious-corpus evaluation and dependency vulnerability checks;
3. define provider registry and offline vision quality evaluation;
4. install content-addressed worker/Gateway releases inactive;
5. run metadata-only Shadow before any image reaches a model.
