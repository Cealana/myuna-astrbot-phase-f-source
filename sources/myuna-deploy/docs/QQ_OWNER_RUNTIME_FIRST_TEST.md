# First real QQ conversation test

Do this only after the approved runtime activation receipt reports
`qq-owner-private-runtime-ready-for-first-live-test`.

1. From Cealana's verified personal QQ account, open the private chat with Myuna's
   separate QQ account.
2. Send one short plain-text message, for example: `在吗？这是第一次真实 QQ 对话测试。`
3. Wait up to 90 seconds. The first provider call can be slower than later replies.
4. Confirm that the response is a natural Myuna reply, not AstrBot's built-in model
   and not a fixed identity challenge response.
5. Send 3-5 additional short messages to verify multi-turn context.
6. Do not test images, group chat, memory promises, or tools in this gate; they are
   intentionally disabled.

Report only whether the reply arrived and whether it appeared coherent. Do not send
QQ IDs, tokens, raw logs, or screenshots containing account identifiers.

If the fixed temporary-unavailable response appears, stop repeated retries and let
Codex inspect safe stage codes and service health. If the generic verification
rejection appears, stop and inspect the identity boundary; do not re-enter an account
ID or create a new binding.
