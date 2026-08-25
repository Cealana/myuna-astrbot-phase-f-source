# ADR-029: Natural Degradation R2C metadata-only Shadow

## Status

Isolated two-repository source candidate. Not applied, installed, activated or
connected to the Owner QQ runtime.

## Purpose

R2C measures how the current broad `owner-runtime-unavailable` path would map
to the typed Natural Degradation contract without changing the QQ reply. It
must answer two questions before R2D can replace even one fallback:

1. Did Core produce a valid, canonical category/detail projection?
2. Can Gateway record that projection after the legacy response is complete,
   without exposing conversation content or affecting delivery?

## Split ownership

R2C-Core appends a private `myuna.safe-degradation.v1` projection to current
loopback HTTP operational errors. Core remains the sole owner of provider,
budget, reply-contract and runtime failure semantics.

R2C-Deploy independently validates the closed Core response and strips the
canonical reply before constructing a Shadow event. Gateway creates only three
local projections itself: Core unreachable, Core response invalid and verified
Owner rate-limited.

The legacy top-level `retryable` flag remains a compatibility field. The typed
projection is authoritative and may deliberately differ; for example, a
discarded invalid provider response can be non-retryable inside one provider
attempt while the Owner-facing degradation still permits a later retry.

The Core and Deploy repository applications require separate approvals. A
later immutable Core release and Gateway installation are also independent
transactions.

## Post-response ordering

The candidate generalizes the existing post-reply fanout seam:

```text
verified Owner request
  -> legacy accepted or unavailable response is written
  -> Unix reply connection closes
  -> enabled observers receive independent best-effort datagrams
```

Successful replies continue to fan out only to the existing Memory and
Turn/Route Shadow paths. Verified operational failures may fan out only to the
Natural Degradation Shadow. Security, identity, malformed-envelope and generic
rejection paths never create degradation observations.

A missing marker, missing socket, full queue, invalid projection, worker error
or trace error is a silent Shadow drop. It cannot change, delay, retry or
replace the legacy response.

## Metadata contract

The datagram and trace contain only:

- a fresh random observation UUID;
- the fixed legacy response code;
- `core` or `gateway` projection source;
- category, retryability and Owner-action flags;
- safe detail code, recovery state and content-free fingerprint;
- a monotonic enqueue timestamp, later reduced to a latency bucket;
- fixed `shadow_only=true` and `production_effect=none` markers.

They never contain user text, reply text, model output, prompt, provider body,
account or QQ identifiers, principal/namespace, conversation/event/message ID,
credentials, Secret, Token, Cookie, memory data, exception or raw log content.

## Isolation

The proposed worker uses a new unprivileged `myuna_degradation_shadow` account,
one local datagram socket, no credentials, no network access and one private
top-level JSONL log directory at `/var/log/myuna-natural-degradation-shadow`.
The directory is created by systemd for that identity and deliberately does not
reuse `/var/log/myuna`, whose existing `myuna:myuna 0750` boundary is not
traversable by the isolated worker. The worker is not added to the `myuna`
group and no existing log-directory mode is relaxed. The marker is deliberately
absent. No user, directory, unit, socket, marker, trace or retention job is
created by the repository stage.

## Activation gates

Before observation can begin, later plans must independently approve:

1. R2C-Core repository application;
2. R2C-Deploy repository application;
3. immutable Core and Gateway/worker builds;
4. disabled installation of the socket, worker and runtime source;
5. an offline and loopback no-body probe;
6. marker creation and narrowly scoped QQ Shadow activation.

R2D remains separate. It may replace only one verified legacy fallback and
must retain an immediate hot rollback to the current broad response.
