# ADR-050: Telegram replay and recovery notice v1

Status: candidate

## Scope

This decision is limited to the verified Telegram Owner-private runtime. It
does not authorize QQ, group chat, another Telegram identity, another channel
instance, startup notifications, proactive messaging, or a shared database
schema.

## Duplicate and replay semantics

A platform event that loses the durable inbound claim is an idempotent
transport replay. The already-claimed delivery owns the user-visible outcome.
The replay:

- returns the bounded `duplicate_suppressed` gateway result;
- never calls Core, the provider, session append, or recovery transition;
- produces no second Telegram reply, degradation message, or recovery notice.

This is intentionally silent. Sending an error for a replay would itself be a
duplicate user-visible side effect and would incorrectly imply that the
original conversational request failed.

Two Telegram messages with different event IDs remain two user actions even
when their text is identical. Telegram no longer uses the in-process
content-fingerprint cooldown as an idempotency decision. The QQ runtime is
unchanged.

The replay acceptance contract is:

1. submit the same signed, bounded Telegram event twice;
2. the first durable claim may proceed through the normal path;
3. the second claim is rejected before identity resolution and Core;
4. Core call count, provider call count, and committed conversation count do
   not increase for the replay;
5. the plugin validates `duplicate_suppressed` and yields no outbound result;
6. a distinct event ID with identical text still reaches Core.

## Recovery episode gate

Recovery state is a Telegram Gateway transport concern. Core continues to
produce channel-neutral typed degradation projections; it does not decide
whether a Telegram identity may receive a notice.

An episode may become `active` only after all of these gates:

1. a signed Telegram envelope passes the fixed channel and private-chat
   boundary;
2. the event wins the durable inbound claim;
3. the exact configured Owner binding resolves;
4. the request reaches Core and returns a validated `CoreUnavailable`
   projection.

Startup, an absent episode, a replay, identity rejection, rate limiting,
content validation, and a plugin-to-runtime connection failure cannot create
or recover an episode.

The durable state is stored in a private SQLite file under the existing
Telegram Gateway state directory. Its scope key is a one-way hash of the fixed
channel kind, channel instance, binding, principal, and namespace. It stores
only a generated episode identifier, typed category/fingerprint, bounded
timestamps, count, state, and notice-claim flag. It stores no raw account ID,
message text, destination, response, secret, or payload.

Repeated Core failures while active update the typed metadata and count but
keep one episode. A later failure after recovery creates a new episode.

## Recovery transition and user-visible notice

A later successful Core reply for the same already-verified scope atomically
claims the active episode and changes it to `recovered`. The accepted gateway
response may then include exactly this fixed notice:

> 刚才的服务异常已经恢复，可以继续使用了。

The plugin validates the exact fixed text and appends it to the normal reply
inside one Telegram outbound result. The model reply committed to session
history does not include the operational notice.

The notice is durable at-most-once. Two runtime instances cannot both claim
it, and a restart cannot repeat it. The deliberate tradeoff is that a crash
after the durable claim but before Telegram delivery can lose the notice.
Avoiding that loss would require an idempotent external-delivery outbox and is
outside this minimal closure; repeating the notice is considered worse than a
rare lost notice.

## Generic degradation and typed projection boundary

The active failure remains the existing generic
`owner-runtime-unavailable` user-visible result. The typed category and
fingerprint continue to be content-free internal state and degradation-shadow
metadata. They are never copied into the Telegram failure or recovery text.

`gateway_degradation_visibility.py` remains the evidence-bound gate for typed
active degradation projection. This change does not activate typed
user-visible degradation categories and does not treat a recovered projection
as a category reply.

## Verification

Focused source verification must prove:

- invalid episode input mutates no episode;
- empty startup creates no recovered notification;
- active, repeat-active, recovered, reopen, new-episode, scope isolation, and
  two-store at-most-once transitions;
- exact replay is pre-Core and silent;
- distinct same-text events both reach Core;
- identity rejection, rate limit, and replay cannot open or recover an episode;
- the active user response contains no typed category/fingerprint;
- the recovery response accepts only the exact fixed notice;
- gateway release and runtime release contain the reviewed bytes.

Live acceptance requires one bounded Owner-private failure/recovery sequence:
one ordinary message while the target Core service is intentionally
unavailable, followed by one ordinary message after it is restored. It must
show one generic failure, one normal successful reply with the fixed recovery
notice, and no later repeated notice. Core `/healthz` and `/readyz` are not
used because they write audit records.

## Rollback

Rollback restores the previous immutable Telegram plugin release, previous
runtime release drop-in, and previous R5 config, then reconciles only the
Telegram Owner runtime/container chain. Existing releases, backups, receipts,
worktrees, and the content-free recovery database are retained.
