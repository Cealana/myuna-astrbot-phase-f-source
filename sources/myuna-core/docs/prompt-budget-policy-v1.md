# Prompt Budget Policy v1

## Purpose

Myuna Core keeps three independent limits:

1. Definition prompt budget: the assembled system prompt, selected Definition
   documents, runtime capability boundary, and optional read-only memory context.
2. Complete model input budget: every system, history, user, assistant, and repair
   message sent in one provider request.
3. Short-term conversation window: the volatile history accepted from a channel.

All values in this contract are Unicode character counts. They are deterministic
Core-side safety limits, not provider token counts and not a claim about any
model's context window.

## Initial operational profile

| Budget | Initial value | Code ceiling |
| --- | ---: | ---: |
| Definition prompt | 300,000 characters | 524,288 characters |
| Complete model input | 400,000 characters | 700,000 characters |

The complete input budget must always exceed the Definition prompt budget by at
least 65,536 characters. This reserves capacity for conversation history, the
current user message, repair instructions, and provider framing.

The initial profile is intentionally below the code ceiling. A future Definition
release can use a larger reviewed profile without editing Core constants, while
the hard ceiling still prevents an accidental unbounded expansion.

## Configuration

- `MYUNA_DEFINITION_PROMPT_MAX_CHARACTERS`
- `MYUNA_MODEL_INPUT_MAX_CHARACTERS`

Invalid, out-of-range, or insufficient-headroom pairs fail closed during Core
configuration loading. `DevConversationEngine` passes the selected total-input
budget into every ordinary, Chryna, dual, and repair provider request.

This repository change does not set either variable in a live EnvironmentFile.
It also does not expand `MYUNA_CONTEXT_MAX_MESSAGES` or
`MYUNA_CONTEXT_MAX_CHARACTERS`.

## Layering rule

A larger ceiling is not permission to load every Definition document on every
turn. Runtime assembly continues to select references by topic and persona. The
budget is a safety envelope for v6/v7 growth, not a replacement for modular
reference routing, medium-term state, retrieval, or prompt compaction.

## Change control

Changing an operational profile requires all of the following:

1. measure the target Definition release with representative routes;
2. preserve the 65,536-character headroom invariant;
3. confirm the selected provider model supports the corresponding token load;
4. run Core tests and offline prompt assembly tests;
5. install and activate through the normal immutable release workflow.

Provider context-window values and character-to-token estimates may change, so
they must remain in provider configuration and release evidence rather than this
Core safety contract.
