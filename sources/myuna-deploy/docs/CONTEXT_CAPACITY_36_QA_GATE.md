# Context Capacity 36 QA Gate

Status: repository-only candidate. It does not authorize a provider call, channel message, live config change, release install, restart, or activation.

## Defined unit

`36` means at most 36 alternating role messages stored by one channel runtime for one `conversation_id`: 18 user/assistant pairs. At saturation, the next user message causes the oldest complete pair to be removed, so Core receives 35 dialogue messages ending in `user`. The provider then receives 36 messages after Core prepends one system message containing selected Definition/persona/runtime controls and optional read-only Owner Memory context.

This is intentionally the same meaning as historical Context24, whose accepted probe sent 23 dialogue messages. It is not 36 turns and not 36 pairs.

## Fixed deterministic gates

All checks must pass; a failure keeps live capacity at 24.

1. Storage contains exactly 36 messages after 18 completed pairs.
2. Saturated request construction contains exactly 35 alternating dialogue messages, ends in `user`, removes only the oldest complete pair, and preserves the first retained, middle, and tail markers.
3. QQ and Telegram construct byte-identical Core JSON for the same synthetic messages while retaining distinct channel headers and separate runtime processes.
4. Separate `conversation_id` values and separate channel stores never mix.
5. No message is duplicated or lost inside the retained boundary.
6. Chinese, emoji, JSON-escaped Unicode, and the 48,000-character boundary fit a 327,680-byte Core HTTP body candidate. The current live 65,536-byte limit is insufficient and must not be used for a 36 activation.
7. A single message over Core's 4,000-character limit fails closed; a failed Core request is not committed and cannot pollute the next request.
8. System/persona/Definition/Owner Memory do not consume the 48,000 dialogue-character budget, but they do consume the complete 400,000-character provider-input budget. The 36 profile must fit that combined limit, including repair framing.
9. The sanitized offline harness completes 100 iterations within 2 seconds on the target host.

## Fixed external DeepSeek QA budget (confirmation required)

- Provider/model: existing controlled DeepSeek API route, exact model `deepseek-v4-pro`.
- Data: synthetic only; no private messages, media, raw IDs, Owner Memory rows, or real channel identity.
- Planned scenarios and hard maximum calls: 4; automatic retries are disabled.
- Per call: at most 48,000 transcript characters and 128 output tokens.
- Aggregate reported input-token ceiling: 200,000.
- Spend cap: USD 0.10 total. The current fail-closed ledger's conservative four-call reservation is USD 0.066187860; the cap is not an expected charge.
- Latency: at most 60 seconds per call, median at most 30 seconds, aggregate wall time at most 300 seconds.
- Accuracy: 100% exact pass across the four scenarios. Any leaked evicted/channel marker, role/order error, missing first/middle/tail marker, malformed result, budget overrun, or unresolved provider error fails the 36 gate.
- DeepSeek is evidence only. Deterministic assertions and Official Codex review remain authoritative.

## 128 hold

Contract acceptance of `128` is not an activation result. At the current 300,000-character Definition ceiling, a 131,072-character dialogue can exceed the 400,000-character complete model-input limit. A saturated 128 profile also needs a 1,048,576-byte Core body limit for worst-case JSON escaping. Route-specific prompt measurement, provider context verification, latency/cost measurement, rollback, and separate Telegram/QQ Owner E2E are mandatory after every 36 gate passes.
