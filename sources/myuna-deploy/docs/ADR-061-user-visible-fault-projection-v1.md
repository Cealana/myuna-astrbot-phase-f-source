# ADR-061: User-visible fault projection and incident correlation v1

Status: T1 source contract; inactive by default; T2 not authorized.

## Decision

The public schema is `myuna.user-visible-fault.v1`, codebook version `1`. Public codes match `MYU-<DOMAIN>-<NN>` and are allowlisted. A code identifies a safe failure domain; it never contains an exception, path, provider identifier or arbitrary internal code.

An incident reference identifies one incident and matches `inc1-[0-9a-f]{32}`. It is generated from 128 random bits. Allocation checks the retained bounded index and retries a collision; a later gateway must propagate the same ref only when it already knows the requests are the same correlated incident. Telegram and QQ use the same category/code/rendering for the same domain, but independent incidents receive independent refs.

If correlation is unavailable, `incident_ref` is JSON null and `incident_ref_status` is `unavailable`. Rendering says `事件号不可用`; no sentinel ref is fabricated.

The content-free index contract is `myuna.user-visible-fault-index-set.v1`, containing only bounded records with ref, public code/domain/category, channel, UTC observation time, retryability, recovery class and gate. It stores no raw message, Profile, DB row, secret, amount, reservation/ledger detail, provider/model payload, raw response, path, exception or internal fingerprint.

Normal 128-message capacity is an OK observation and has no public fault mapping. Typed session unavailability, corruption, write failure or capacity/projection failure are separate mappings. Profile reader failure, writer failure, duplicate candidate, conflict and boundary rejection are also separate. P08/P10-B inputs are accepted only through explicit typed-code allowlists.

## Source boundary

Core owns the frozen descriptor codebook and mappings from existing Core/P08/P10-B typed inputs. Deploy owns the channel-neutral renderer, random correlation, bounded serialized index and an explicit `myuna-diagnose --incident-index ... --incident-ref ...` lookup path.

No legacy Core HTTP, degradation bridge, incident receipt, Gateway protocol or collector imports the new modules. Existing generic fallbacks and existing `inc-...` receipts therefore remain unchanged. Wiring a user-visible reply, creating a durable index file, installing a release or granting an Owner wrapper is a separate T2 gate.

## Future activation contract

The Owner entry must be local-only, authenticated by existing OS identity, read only a fixed regular non-symlink content-free index with minimum permissions, enforce bounded input size and timeout, return a fixed schema, preserve correlation, and write only content-free audit metadata. Installation must preserve exact prestate, include an uninstall path and rollback to the previous selector/release. No channel, model, provider or health probe is part of incident lookup.
