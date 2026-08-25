# Context Capacity 128 Candidate

Status: repository-only candidate. It does not authorize a provider call, a real Telegram or QQ message, a live config/release change, a restart, or activation.

## Defined unit and candidate profile

`128` means 128 alternating role messages stored inside one channel runtime for one `conversation_id`: 64 completed user/assistant pairs. At saturation, the next user append removes the oldest complete pair, so Core receives 127 dialogue messages ending in `user`; the provider receives 128 messages after Core prepends one system message.

The bounded candidate is:

- history messages: 128;
- dialogue characters: 131,072;
- Definition/system characters: 300,000 maximum, unchanged;
- complete model input: 500,000 characters;
- authenticated loopback Core HTTP body: 1,048,576 bytes.

The current 400,000-character complete-input limit cannot accept the worst permitted 300,000-character system prompt plus 131,072 dialogue characters. The 500,000 candidate accepts that 431,072-character initial request and leaves 68,928 characters for provider reply plus one bounded repair instruction. This is a deterministic Core character budget, not a claim that characters equal provider tokens.

## Offline gates

All checks must pass before requesting any external QA or live authority:

1. Storage contains exactly 128 messages after 64 completed pairs.
2. Saturated construction contains exactly 127 alternating dialogue messages, ends in `user`, evicts only the oldest pair, and preserves first retained, middle, and tail markers.
3. QQ and Telegram construct byte-identical Core JSON from the same synthetic history while retaining distinct channel headers and separate stores.
4. Separate sessions and channel stores never mix; no retained message is duplicated or lost.
5. Character trimming removes only complete oldest pairs.
6. Chinese, emoji, and worst JSON-escaped one-character fills fit the 1 MiB body candidate.
7. A failed request is not committed or replayed.
8. The 131,072-character dialogue plus the maximum 300,000-character system prompt fits the 500,000-character candidate, with at least 65,536 characters of repair headroom.
9. The sanitized offline harness completes 100 iterations within 2 seconds on the target host.

## Holds before final activation

- Provider token count, latency, and cost must be measured with separately approved synthetic DeepSeek QA; source numeric support is not acceptance. The prepared, unexecuted plan uses exact model `deepseek-v4-pro`, four calls, no automatic retries, at most 127 dialogue messages and 131,072 transcript characters per call, 128 output tokens per call, 400,000 aggregate reported input tokens, USD 0.20 total spend, 120 seconds per call, 60 seconds median, and 480 seconds total. Its content-free conservative reservation is USD 0.182291970.
- The production daily spend guardrail must be checked against the larger input before activation.
- The 1 MiB body ceiling increases the loopback request boundary and therefore requires explicit live approval and rollback.
- Telegram and QQ each require owner-private real E2E; health or one channel cannot substitute for the other.
- The 24-message live profile remains the rollback baseline until a later approved activation establishes a newer accepted baseline.
