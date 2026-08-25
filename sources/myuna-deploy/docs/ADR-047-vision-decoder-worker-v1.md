# ADR-047: Isolated Vision Decoder Worker v1

Status: R1 repository-only / inactive / no systemd installation

## Decision

Image decoding runs outside Myuna Core and all channel gateways. The Gateway
sends an authenticated, bounded byte stream over a private Unix stream socket.
The request contains only an opaque request ID, byte length, SHA-256, and fixed
probe-policy ID. It does not contain channel identity, platform file reference,
user question, conversation text, model route, memory, or tool state.

The Worker verifies the framing and SHA-256 before calling the Pillow Probe. It
returns only verified MIME, dimensions, and the same content digest. Every error
is normalized to `media_rejected` without decoder or image detail.

## Runtime boundary

The candidate systemd service uses a dedicated no-login identity, a marker-gated
private Unix socket, no network namespace, AF_UNIX only, no capabilities, strict
filesystem protection, and fixed CPU, memory, and task limits. The Pillow venv is
root-managed and not writable by the Worker.

## Non-effects

R1 does not create the user, install units, execute daemon-reload, create the
Marker, start the Socket or Service, bind Telegram or QQ, read Bot Token, inspect
real images, call a model, read or write memory, enable tools, or change a prompt.

## Next gates

1. repository application and isolated Pillow/socketpair tests;
2. content-addressed Worker release plus rendered-unit validation;
3. disabled/inactive installation with Marker absent;
4. no-body synthetic Unix-socket probe;
5. metadata-only Telegram Shadow with no model call and no image retention;
6. Owner-supplied ordinary photo, screenshot, and WebP acceptance fixtures.
