# Natural Degradation / Reply Tail Reliability v1

Status: isolated repository candidate; not wired to the QQ runtime

## Purpose

This module converts a confirmed, content-free runtime condition into a short,
truthful and category-specific Myuna explanation. It also detects reply tails
that reintroduce an unavailable capability after an otherwise correct refusal.

The candidate is based on the 2026-07-22 Owner QQ acceptance evidence:

- a short Scheduler request was denied for the wrong capability category;
- a memory-write refusal implied future recall of unstored information;
- a Vision refusal guessed an unverified placeholder mechanism;
- an explicit Scheduler refusal used a mechanical Markdown capability menu;
- external-data and external-action refusals were natural and correct.

## Modules and ownership

`FailureEnvelope`

- contains only safe identifiers, booleans, counts and timezone-aware times;
- cannot contain raw logs, messages, prompts, provider output, secrets or memory
  record identifiers;
- fingerprints an event by category, component and safe detail code.

Unavailable-capability request classifier

- classifies the final user request before a provider reply is trusted;
- covers Scheduler, memory write, Vision, external data and external action;
- excludes explicit architecture and implementation discussions;
- does not execute, write, route or enable a capability.

Deterministic natural narrator

- uses one short tested baseline per category;
- never asks the same provider that failed to explain its own failure;
- never invents a transport mechanism or promises future recall;
- remains usable when no local rewrite model exists.

Reply-tail validator

- reuses Runtime Capability Honesty v1;
- rejects cross-capability substitute suggestions;
- rejects future recall of content that was not stored;
- rejects unverified image transport details;
- flags mechanical Markdown capability menus.

Notification decision state machine

- emits on first observation, fingerprint changes, newly required Owner action,
  recovery transitions or an approved reminder interval;
- suppresses repeated copies of the same event;
- is pure and does not own persistent state or delivery.

## Candidate boundary

This R1 candidate is intentionally not imported by `conversation.py` or any
Gateway. It does not alter the current reply path, call DeepSeek, send QQ
messages, write memory, create a service or enable a capability.

Later wiring must be separately approved and should occur in small stages:

1. map existing structured Core failures into `FailureEnvelope` without changing
   delivery;
2. run the classifier and tail validator in metadata-only Shadow mode;
3. compare deterministic narration with current replies;
4. only then consider replacing a narrow fallback path.

Local-model rewriting, real QQ status delivery, cross-channel notification and
automatic recovery remain separate projects and approvals.
