# Short-term context window v1

## Purpose

This contract bounds the recent alternating conversation supplied by an
authenticated channel gateway. It is volatile conversational continuity, not
Owner Memory, not the future medium-term temporal context, and not History
Archive.

## Configuration

- `MYUNA_CONTEXT_MAX_MESSAGES` defaults to `12` and accepts even values from
  `2` through `256`.
- `MYUNA_CONTEXT_MAX_CHARACTERS` defaults to `16000` and accepts values from
  `4000` through `262144`.
- `MYUNA_HTTP_MAX_BODY_BYTES` remains an independent transport limit. A larger
  context profile must raise it separately and prove that the complete encoded
  request fits.

The Core validates the explicit configured policy. It does not infer the
window from provider limits, model names, API prices, or the number of messages
that happened to arrive.

## Layer boundaries

1. The channel gateway owns recent alternating dialogue and trimming.
2. Core validates the received window again before routing.
3. A future medium-term source may add time-bounded current-life state as a
   separately labelled context block.
4. Owner Memory remains a separate ranked read-only or read-write capability.
5. History Archive remains opt-in historical material and never fills this
   window automatically.

Increasing the count does not authorize memory writes, retrieval, tools,
vision, scheduling, cross-channel identity changes, or additional model routes.

## Staged evaluation

The intended evaluation order is `12 -> 24 -> 36`. A profile may advance only
after isolated tests cover exact recall, superseded facts, distractors,
instruction pollution, capability honesty, persona consistency, latency, token
usage, and cost. Contract support for `128` and `256` is forward compatibility,
not permission to activate those sizes.

No message text is written to configuration, receipts, or context-policy audit
metadata.
