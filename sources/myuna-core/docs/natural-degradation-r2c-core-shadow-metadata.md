# Natural Degradation R2C-Core — private failure metadata producer

Status: isolated repository candidate; not applied, installed or activated

## Purpose

R2C-Core makes Core the sole owner of failure semantics. For an operational
failure that already produces a private loopback HTTP error, Core appends one
canonical `myuna.safe-degradation.v1` projection while preserving the existing
HTTP status, `error` code and compatibility fields.

This metadata is intended only for the later R2C Deploy Shadow consumer. It is
not a QQ reply, Prompt, memory record, model request or public API contract.

## Boundary

The producer may expose only:

- `failure_schema=myuna.core-failure-response.v1`;
- the existing bounded HTTP `error` code and compatibility fields;
- one validated `myuna.safe-degradation.v1` object.

The projection omits request and correlation identifiers, user text, provider
messages or bodies, prompts, logs, account data, credentials, model reasoning
and memory identifiers. Unknown provider codes collapse to the fixed
`core-runtime-fail-closed` profile instead of being copied.

Authentication, malformed requests, unsupported paths and other client or
security rejections do not receive operational failure metadata.

## Compatibility and production effect

Successful `/v1/chat` responses are unchanged. The current Gateway ignores the
body of non-200 responses, so applying this source candidate alone cannot alter
the legacy AstrBot fallback. A new immutable Core release, installation and
activation all require later independent approvals.

R2C-Deploy must independently validate the closed projection before recording
metadata. It must continue returning the exact legacy Gateway response until a
separate R2D live-reply approval.
