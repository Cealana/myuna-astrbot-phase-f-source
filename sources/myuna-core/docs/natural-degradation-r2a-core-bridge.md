# Natural Degradation R2A — Core Failure Bridge

Status: isolated repository candidate; not wired, installed or activated

## Purpose

R2A gives Core a typed boundary between internal structured failures and the
channel-safe degradation protocol. It prevents future QQ wiring from parsing
exception messages, upstream bodies, logs or model-generated explanations.

## Components

`CoreFailureObservation`

- contains only safe identifiers, a closed `CoreFailureCode`, timestamps, a
  count and recovery state;
- cannot contain user text, provider output, prompts, logs, secrets, account
  identifiers or memory record identifiers.

Core failure profiles

- explicitly map current reply-contract, provider, budget, memory and Core
  runtime failures into an R1 `FailureEnvelope`;
- unknown provider and HTTP error codes fail closed instead of silently entering
  a generic category;
- profiles, rather than callers, own category, component, detail code,
  retryability and Owner-action semantics.

`SafeDegradationProjection`

- uses the exact schema `myuna.safe-degradation.v1`;
- exposes only category, retryability, Owner-action requirement, safe detail,
  recovery state, a content-free fingerprint and the deterministic canonical
  reply;
- omits event, correlation, component and fact lists;
- rejects unknown fields, integer booleans, unknown enums, free-form replies and
  non-canonical wording.

## Deliberate non-wiring

This candidate is not imported by `conversation.py` or `http_api.py`. It does
not alter the Core HTTP response, Gateway protocol or AstrBot plugin. It does
not call DeepSeek, inspect raw provider responses, send QQ messages, read or
write memory, create a service, change a capability or persist dedup state.

## Later stages

1. R2A formal repository application after independent digest approval.
2. R2B separately adds a versioned Gateway/AstrBot protocol candidate.
3. R2C observes category projections in metadata-only Shadow mode without
   changing visible replies.
4. R2D replaces one narrow, verified fallback with an explicit hot rollback.

The modularity audit requires these stages to remain separate; Natural
Degradation must not become another block of branching logic inside
`conversation.py`.
