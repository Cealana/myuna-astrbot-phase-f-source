# Core runtime single-attempt invariant v1

## Scope

The production DeepSeek runtime constructed by
`build_deepseek_runtime_provider` permits exactly one provider attempt for each
Core request. This bounds the Owner-private QQ and Telegram request chain to one
external model call and keeps the 60-second provider timeout inside the
70-second Gateway deadline.

`MYUNA_DEEPSEEK_MAX_ATTEMPTS` remains syntactically compatible with the reviewed
range `1..3`. Values `2` and `3` are accepted but clamped to an effective value
of `1` before the provider, audit, and budget layers are constructed. Invalid
values still fail closed.

The generic `DeepSeekProvider` retains its bounded retry feature for isolated
library tests and non-runtime callers. The invariant is enforced at the Core
runtime construction boundary, which is the production path used by the
conversation service.

This invariant does not change the model, provider timeout, output-token limit,
credential handling, daily budget, identity, channel, prompt construction, or
session-context retention policy.

## Verification

Offline tests must prove all of the following:

- absent configuration and configured values `1`, `2`, or `3` all produce an
  effective runtime value of `1`;
- invalid attempt values are still rejected;
- a retryable synthetic transport failure results in exactly one transport
  call and reports `attempts=1`;
- the audited budget wrapper reserves only one attempt;
- the generic provider's independent two-attempt test still passes.

No live activation, provider call, service restart, or private-message read is
authorized by this source candidate.
