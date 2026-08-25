# Runtime Capability Honesty v1

Status: isolated candidate

## Purpose

This contract prevents Myuna from promising, implying, or claiming a runtime
capability that the active Capability Manifest disables. It addresses the verified
Scheduler promise and indirect Vision promise failures without enabling either
feature.

## Responsibilities

- `capabilities.py` remains the manifest and public API owner.
- `runtime_capability_honesty.py` owns natural-language claim detection, negation,
  repair guidance, and deterministic honest fallbacks.
- `conversation.py` invokes the guard after normalization and after the one allowed
  model repair.
- The guard uses only the reply and manifest booleans. It does not call a model,
  read memory, run a tool, or inspect external state.

## Covered capabilities

- long-term memory reads and writes;
- scheduled/proactive notifications, currently derived from `external_actions=false`;
- direct and indirect image/screenshot understanding;
- live external-data lookup;
- tools, external actions, and system administration.

An explicit `scheduled_notifications` manifest capability should be introduced in
a later manifest schema before Scheduler is implemented. v1 does not pretend that
Scheduler exists.

## Failure behavior

1. The initial candidate is checked deterministically.
2. A violating candidate receives one category-specific, content-free repair request.
3. The repaired reply is checked by the same guard.
4. If the repair repeats only capability-honesty violations, the provider output is
   discarded and a deterministic truthful Myuna reply is returned.
5. Audit contains categories and state transitions, never reply or user content.

## Boundaries

- no capability is enabled;
- no request is executed;
- no memory is written;
- no new listener, service, environment variable, or network path is added;
- repository application, immutable release installation, and QQ activation remain
  separate approval stages.
