# ADR-021: QQ noiseless event filter

## Status

Proposed for digest-bound activation.

## Context

The first real owner QQ conversation reached Core and DeepSeek successfully.
Before that request, AstrBot emitted repeated local safety notices.  The adapter
was intercepting all AIOCQHTTP events and replying to every private event whose
message parts were not exclusively `Plain`.  OneBot synchronization events,
outbound echoes, notifications, or non-text private events can therefore cause
unwanted replies without reaching the model.

The provider audit confirmed that these notices did not call DeepSeek.  They
are nevertheless noisy and can form a local response loop.

## Decision

Keep the high-priority `stop_event()` and built-in AstrBot LLM suppression.
Before signing an envelope, admit an event only when all conditions hold:

1. `sender_id` and `self_id` are valid QQ account identifiers.
2. `sender_id` does not equal `self_id`.
3. The event is a private chat.
4. The message has at least one part and every part is `Plain`.

All other events are silently dropped.  They do not receive a denial message,
reach identity resolution, call Core, call a model, write memory, or invoke a
tool.

## Deployment boundary

The update installs an immutable plugin directory, changes only
`CHANNEL_PLUGIN_ROOT`, and force-recreates only the AstrBot container.  NapCat,
Core, the QQ runtime socket, the database, model configuration, memory, tools,
rate limits, and boot settings are unchanged.

Activation requires an exact plan digest.  The previous plugin files are
copied to WSL and C-drive backup locations with matching SHA-256 values.  On a
failed postcondition, the old plugin pointer is restored, the target Git commit
is compensated with `git revert`, and AstrBot is recreated with the old plugin.
