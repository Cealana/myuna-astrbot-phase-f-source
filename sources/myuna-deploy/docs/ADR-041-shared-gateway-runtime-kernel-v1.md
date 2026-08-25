# ADR-041: Shared Gateway Runtime Kernel v1

Status: R1 repository-only / inactive / not wired to QQ or Telegram

## Decision

QQ and Telegram will retain separate Transport Adapters and trust boundaries,
while using one channel-neutral Gateway Runtime Kernel for shared orchestration.

The R1 kernel owns only deterministic ordering over injected ports:

1. authorize the authenticated conversation context;
2. load bounded session context;
3. claim the inbound event;
4. apply rate limiting;
5. create a context-separated Core request;
6. call an injected Core client;
7. append successful dialogue context;
8. record an outcome or metadata-only failure observation.

Each inbound message explicitly declares its required capabilities. The current
Owner-private default asks for conversation and read-only Owner Memory, while a
future no-memory or vision-only adapter can request a narrower set. The kernel
authorizes exactly that declared set instead of implicitly granting capabilities
from a channel name.

The R1 kernel has no database, Socket, Telegram, QQ, NapCat, AstrBot, systemd,
credential, model, or memory implementation of its own.

## Trust boundary

The following remain channel-specific:

- platform account and login state;
- Bot Token or QQ session;
- gateway signing and Core client credentials;
- system user and database role;
- identity Binding and channel fingerprint;
- rate-limit configuration;
- inbound decoding and outbound delivery.

The following become shared:

- authenticated context shape;
- capability decision;
- event lifecycle ordering;
- Core request projection;
- session-context port;
- typed failure classification and metadata-only observer projection.

## Session context

The kernel keys session context with `(namespace_id, session_id)`, not with the
channel name.  A future Turn Manager or session coordinator owns `session_id`.
This allows an explicitly continued Owner session to cross QQ and Telegram while
preventing accidental merging based only on display names or message text.

R1 does not persist session context and does not change the current 24-message
Gateway windows.

## Failure boundary

Failure observers receive IDs, stage, and a bounded failure code only.  They do
not receive message text, model output, account IDs, credentials, or memory.
The R1 kernel does not generate a user-visible degraded reply and cannot restart
or repair a service.

## Non-effects

R1 adds a pure module, Fake-port tests, and this ADR only.  It does not replace
`qq_owner_runtime_gateway.py` or `telegram_owner_runtime_gateway.py`, install a
Gateway Release, change Core HTTP, activate the Effective Runtime Profile, alter
systemd, connect a channel, send a message, call a model, or read/write memory.

## Follow-up

1. Add thin QQ and Telegram adapter candidates around this kernel.
2. Run identical Fake and recorded-metadata tests for both adapters.
3. Build an inactive content-addressed Gateway Release.
4. Shadow-compare decisions before any one-channel-at-a-time activation.
5. Vision Input Contract v1 may now be designed against the authenticated
   context and media boundary, but remains disconnected from live channels.
