# ADR-037: Configurable short-term context window v1

## Status

Repository candidate only. No runtime profile is changed by this ADR.

## Decision

QQ and Telegram use one shared `ContextWindowPolicy` and one shared
`ConversationHistory` implementation. The current backend remains
`InMemoryContextStore`, preserving existing process-local and restart-cleared
behavior. A narrow `ContextStore` protocol permits a separately approved
durable backend later without changing the Core request schema.

The allowed contract is:

- even message counts from 2 through 256;
- character budgets from 4000 through 262144;
- message count and character budget enforced independently;
- trimming removes complete user/assistant pairs from the oldest edge;
- the final request remains a user message;
- QQ and Telegram keep separate channel runtimes and identity boundaries.

The checked-in profile catalog keeps 12 as the current default. Profiles 24 and
36 are offline QA candidates. Profiles 128 and 256 document compatibility only.

## Why not only replace 12 with 36

The previous limit existed independently in Core, QQ, and Telegram. Editing one
number could cause a gateway/Core mismatch. It would also preserve two copied
history implementations and make a future durable short-term store harder to
review. A shared policy makes the boundary deterministic and testable while
leaving live behavior unchanged.

## Explicit non-goals

- no runtime activation or configuration write;
- no message-content audit or archive;
- no medium-term temporal context implementation;
- no Owner Memory change;
- no History Archive read;
- no cross-channel history merge;
- no model route, prompt, tool, vision, or scheduler change.

## Promotion gates

Each larger profile requires a separate activation plan, aligned Core and
Gateway values, sufficient HTTP body capacity, isolated provider QA, cost and
latency evidence, rollback to the prior profile, and a post-activation owner
conversation check.
