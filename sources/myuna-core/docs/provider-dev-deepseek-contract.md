# DeepSeek Provider Dev contract

Status: implemented offline, not connected to Myuna HTTP, no credential present,
no live request authorized.

## Reviewed upstream snapshot

- Base URL: `https://api.deepseek.com`
- Endpoint: `POST /chat/completions`
- Registered models: `deepseek-v4-flash`, `deepseek-v4-pro`
- Pricing snapshot: 2026-07-15; values live in `providers/registry.py`
- Thinking mode is always explicit. Fast requests send `disabled`; reasoning
  requests send `enabled` plus an optional reviewed effort.
- Deprecated aliases such as `deepseek-chat` and `deepseek-reasoner` are not
  registered and cannot be selected.

Pricing is configuration evidence, not a permanent truth. Re-read the official
model and pricing page before the first live gate and before any later model
registry update.

## Safety boundary

Provider code is not called by the Core HTTP surface in this stage. A runtime
provider can be built only when all of these are true:

1. `MYUNA_PROVIDER_LIVE_CALLS_ENABLED=true` is explicitly set.
2. A reviewed model is selected through `MYUNA_DEEPSEEK_MODEL`.
3. A root-owned systemd credential is delivered as `deepseek_api_key`.
4. A persistent UTC daily budget ledger can reserve the worst-case request cost.

The API key is never accepted from `DEEPSEEK_API_KEY`. Prompts, responses,
reasoning content, Authorization headers, and keys are never written to audit.

## Request and response contract

- Initial roles are limited to system, user, and assistant. Tool calls remain
  disabled for this Provider Dev checkpoint.
- Requests are bounded to 256 messages, 200,000 characters, and 32,768 output
  tokens by Core policy, even when an upstream model advertises larger limits.
- JSON output requires an explicit JSON instruction in the supplied messages.
- The adapter validates model identity, exactly one choice, final text, finish
  reason, token usage, cache accounting, and reasoning-token metadata.
- `reasoning_content` is intentionally discarded.

## Retry and budget contract

- HTTP 400, 401, 402, and 422 are not retried.
- HTTP 429, 500, and 503 are retryable, with a maximum of three configured
  attempts and bounded backoff.
- The daily ledger reserves worst-case cache-miss input plus maximum output,
  multiplied by maximum attempts, before the network call.
- Successful retries conservatively account for the observed final cost plus a
  worst-case allowance for each earlier attempt.
- Network, malformed-success, and upstream failures whose billing state cannot
  be proven leave an `uncertain` reservation. They require operator review and
  never silently release budget.

## Audit contract

Audit records contain only structural request fingerprint, provider, model,
route reason, caller, counts, explicit thinking mode, response format, latency,
attempts, finish reason, token/cache usage, pricing snapshot, cost, and typed
error metadata. Content-redaction tests use unique canary strings and must pass
before any live gate.
