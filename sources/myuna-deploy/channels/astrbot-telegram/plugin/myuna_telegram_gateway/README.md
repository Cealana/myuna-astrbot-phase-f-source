# Myuna Telegram Gateway

Fail-closed Telegram Owner-private boundary with a bounded, reliability-first
native vision-to-Core path.

The plugin:

- stops every Telegram event before normal AstrBot provider or Agent dispatch;
- preserves the existing signed private plain-text Gateway/Core route;
- creates an Owner binding only after the exact binding phrase receives an
  accepted Core result;
- stores only a domain-separated HMAC-SHA256 fingerprint, never a raw Telegram
  identity;
- admits one private, non-bot, single-Image event only when its fingerprint
  matches the stored binding;
- validates the already-downloaded JPEG with 8 MiB, 8192 dimension,
  16,000,000 pixel and one-frame limits;
- optionally performs one aspect-preserving 4096-bound JPEG downscale;
- calls the pinned AstrBot built-in Google GenAI provider for one bounded
  Chinese visual observation, with no Agent loop, tools, memory, OCR service,
  grounding, Search, URL context, Files API, cache, fallback or tiling;
- marks that observation as untrusted image data, combines it with the bounded
  Owner caption (or a default image request), and forwards the resulting text
  through the existing signed Owner Runtime route;
- returns the Myuna Core reply rather than the raw Gemini observation;
- keeps the signed media Shadow datagram as asynchronous audit-only metadata.

AstrBot selects, downloads, tracks and JPEG-normalizes Telegram Photo media
before the Gateway handler runs. The Gateway validates that local result and
deletes any additional downscaled file immediately after the provider call;
AstrBot's original temporary-media cleanup remains lifecycle best effort.

The dedicated Gemini provider resolves its key from
`$MYUNA_TELEGRAM_GEMINI_API_KEY`, injected by the root-owned Gateway environment
file. No credential, raw identity, fingerprint, image or raw provider response
is written by this plugin. The caption and derived observation are carried only
through the signed Owner Runtime handoff and its existing bounded short-term
conversation context.
