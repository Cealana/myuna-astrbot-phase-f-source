# ADR-058: Rapid Fault Diagnostics v1 source foundation

- Status: T2 activated 2026-08-02; metadata-only QQ/TG acceptance complete
- Program: P16 Rapid Fault Diagnosis & Incident Readiness
- Scope: Core, QQ/Telegram gateways, provider/local provider, budget, Owner Profile, session capacity, recovery, service/config/release drift

## Decision

P16 v1 uses one strict, content-free diagnostic contract. The source entry is
`myuna-diagnose`; it accepts an explicit sanitized snapshot or invokes the fixed
local metadata collector and returns one JSON report. The collector never calls
a channel/Core/model/provider, reads audit/private data, or executes recovery.
Its installation is the separately reviewed T2 activation described below.
`/healthz`, `/readyz`, `/v1/status`, chat requests, provider/model requests,
channel test messages, and any probe that writes audit or changes state are
forbidden.

## Owner entry contract

The installed form is one command:

```text
myuna-diagnose --channel all --timeout 2s
```

T2 activation must provide these controls before the command is Owner-ready:

- Authentication: local OS execution identity only; no bearer token and no
  network listener. Install root-owned mode `0750`, limited to the existing
  Owner operations principal/group resolved during activation.
- Least privilege: the collector may read only service `ActiveState` and
  restart count, listener presence, sanitized release/config digests, file
  mode/owner metadata, bounded receipt counters, and declared capacity values.
  It cannot read environment values, secrets, message text, DB rows, Profile
  content, provider payloads, raw model responses, journal bodies, or raw logs.
- Timeout: two seconds overall; each metadata source gets one bounded attempt.
  Timeout produces an `unknown_insufficient_safe_evidence` finding, never a
  retry loop.
- Input: the source-only engine accepts stdin or one regular, non-symlink file,
  bounded to 128 KiB and 64 observations.
- Correlation: `incident_ref` is `inc-` plus the first 12 hex characters of a
  domain-separated SHA-256 over an existing safe request ID. The request ID is
  not returned or copied into the diagnostic receipt.
- Audit: T0 execution writes no audit. Output contains a content-free
  `audit_projection` with namespace `fault_diagnosis_v1`, counts, outcome,
  correlation presence, and explicit false flags for private/raw/model/channel/
  provider/state access. Persisting that projection is a live write and remains
  T2.
- Uninstall: use the content-free activation receipt to verify the selected
  release and installed-file digests, restore the exact Core selector and ACLs,
  remove only the P16 QQ/TG selectors, tmpfiles rule, baseline and wrapper, then
  restart the same three target services. Releases, backups and receipts remain
  retained. Source rollback is a revert of the P16 candidate commits. No data
  migration is part of v1.

## T2 implementation contract

The T2 candidate adds one bounded runtime write: after an authenticated failure
response connection is closed, each Gateway atomically replaces its own
`/run/myuna-fault-diagnostics/<channel>/last.json`. The exact receipt contains
only channel, hashed `incident_ref`, typed degradation enums, UTC time, fixed
booleans and fingerprint; it contains no message, identity, Profile, DB,
provider/model payload, exception or raw log. QQ and Telegram use distinct
owner directories with setgid `sudo` read access and cannot write each other's
receipt.

The installed collector runs as the existing Owner operations (`sudo`) group.
It may execute only `systemctl show` for the fixed P16 unit allowlist; read fixed
unit digests, `/proc/net/tcp` listener metadata, the sanitized P16 baseline and
the two bounded receipts; and `lstat` the exact QQ/TG session DB paths. The
session directories receive traverse-only `sudo` ACLs; DB files remain `0600`
and are never opened. A listener is always accompanied by
`local_model_readiness_unverified`; no health/model request is used to infer
readiness.

Activation builds four overlays from the currently selected Core, QQ and
Telegram content-addressed releases plus a standalone diagnostics release.
The Core overlay is addressed by the existing Selector tree-digest algorithm;
activation derives a new approval-bound runtime binding with the byte-identical
installed Selector contract, then updates the binding and selector together.
QQ/TG receive a new highest-priority P16 drop-in. Exact Core binding/selector
bytes and ACLs are backed up before one restart of each target service. The
installed verifier must accept the candidate tree and runtime binding before
the first restart. Candidate releases and backups are retained. Rollback
restores the prior Core binding, selector and ACLs, removes only P16 selectors/
entry/config, then restarts the same three services and writes a second
content-free receipt.

## Fixed schemas

Snapshot fields are exactly:

```text
schema, observed_at, channel, incident_ref, observations
```

Each observation is exactly:

```text
target, code, evidence_class
```

The report fields are exactly:

```text
schema, observed_at, channel, incident_ref, overall, findings,
checks_prohibited, audit_projection
```

Every finding is a bounded enum projection:

```text
target, layer, code, state, evidence_class, retryable,
owner_action_required, recovery_gate
```

Unknown fields, free-form codes, duplicate observations, target/code mismatch,
invalid timestamps, unsafe correlation, oversized input, and non-regular input
fail closed. Invalid input returns only `invalid_snapshot` and access flags; it
does not echo rejected data.

## 128-message session boundary

The QQ and Telegram checks verify only that the declared policy is exactly 128
individual messages and that the session store has the expected owner/mode and
is available. They never count, select, sample, or output DB rows. A policy
mismatch is `session_capacity_mismatch` (T2 config/release correction). An
unavailable or suspect store is `session_unavailable`; repair, row inspection,
or data mutation is T3 and is not performed by diagnostics.

## Symptom to conclusion and recovery

| Symptom / code family | Safe check | Conclusion layer | Recovery boundary |
| --- | --- | --- | --- |
| ingress/identity rejected | sanitized gateway decision code | channel ingress or identity | no automatic recovery; T2 binding/config correction |
| service/socket inactive | service state and listener presence | service or socket | T2 bounded restart after exact prestate |
| Core unreachable/invalid/not-ready | gateway safe projection and service metadata | gateway/Core | T2 release/service rollback or restart |
| provider timeout/unavailable/auth | Core typed safe projection only | provider | timeout may wait; credential/config change is T2 |
| budget exceeded/rollover/accounting | sanitized budget state/code, no ledger rows | budget | rollover/config is T2; accounting repair is T3 |
| local model not ready/busy/timeout | typed local-provider safe code only | local provider | wait for transient; model/service correction is T2 |
| Profile read/write unavailable | typed reader/writer result only | Profile boundary | T2 service/config; content/store repair is T3 |
| duplicate/conflict/boundary reject | bounded decision code | dedupe/policy | no retry loop; Owner decision before any write |
| 128-message mismatch/store unavailable | policy value and file metadata only | session | config T2; store/data repair T3 |
| config/release/permission drift | sanitized digests and file metadata | drift/permission | T2 exact-prestate restore; broad permission repair may escalate |

Automatic action is limited to classification and fixed advice. V1 never
restarts, rewrites, retries channel/model/provider requests, edits config,
changes permissions, rolls budget, repairs Profile/session state, or switches a
release. Every T2 recovery records exact prestate, one target, a bounded attempt,
post-check, rollback result, and a content-free receipt. T3 always requires a new
impact-specific approval.

## T1 component and test gate

| Component | Dedicated worktree | Source unit | Test matrix |
| --- | --- | --- | --- |
| Core | `feat/p16-core-fault-correlation-v1` | typed local-provider/budget degradation mapping | every known provider code, golden projection, unknown fail-closed |
| Deploy | `feat/p16-rapid-fault-diagnostics-v1` | strict taxonomy, CLI, Gateway mapping, fixtures | all taxonomy layers, target mismatch, 128-message boundary, invalid/oversized input, protocol/shadow compatibility |

T1 is complete only after Official diff review and focused regression tests.
Merge, release build, install, service restart, live snapshot collection, and
acceptance are later gates. QQ and Telegram live acceptance remain separate.

## T2 acceptance note

The selected Core and QQ/Telegram releases, Owner entry, baseline and
content-free receipt directories were activated with exact prestate and a
superseding repair receipt. QQ and Telegram were accepted separately through
the metadata-only Owner entry: each reported service/socket, session metadata,
128-message policy and release state as `ok`. Local listener presence remains
`local_model_readiness_unverified` by design because channel, health, model and
provider probes are prohibited. No synthetic channel failure was triggered, so
the per-channel organic incident receipt path is installed and source-tested
but not yet observed from a live failure.
