# P10-B trusted-time acceptance matrix v1

All rows use synthetic observations and temporary private directories. No live time source,
Owner content, channel, model, release, config or service is used.

| ID | Synthetic stimulus | Required result and durable-state oracle |
| --- | --- | --- |
| TT-01 | first synchronized UTC observation | sample is UTC, source/class fixed, sequence 1; state row matches |
| TT-02 | timezone-aware `+08:00` observation | normalize to equivalent UTC before comparison/persistence |
| TT-03 | naive observation | fail closed; create no sample/state advance |
| TT-04 | synchronization false or evidence missing | `unsynchronized`/`unavailable`; no state advance and no fallback |
| TT-05 | uncertainty above one second | `uncertainty_exceeded`; no state advance |
| TT-06 | same boot, UTC and monotonic advance together | next sequence commits; continuity `same_boot` |
| TT-07 | same boot, monotonic decreases | `regression`; watermark unchanged |
| TT-08 | UTC moves behind provider or P08 floor | `regression`; watermark unchanged |
| TT-09 | same-boot UTC/monotonic drift exceeds two seconds | `drift_exceeded`; watermark unchanged |
| TT-10 | restart, synchronized UTC not behind floors | accept with sequence greater than provider and P08 watermarks |
| TT-11 | provider state restored behind intact P08 watermark | skip forward to P08 sequence + 1; never replay skipped values |
| TT-12 | stable source or authority class changes | `source_drift`; no implicit migration or fallback |
| TT-13 | eight concurrent provider instances | exactly eight unique increasing committed sequences |
| TT-14 | injected failure before commit | rollback; retry obtains the uncommitted next sequence |
| TT-15 | lost response after committed state | `persistence_ambiguous`; retry advances again, leaving only a safe gap |
| TT-16 | database busy past bounded timeout | typed retryable timeout; no sample or partial state |
| TT-17 | wrong application id/version/label or failed quick check | state corrupt; bytes untouched; no repair/migration |
| TT-18 | symlink, wrong type/owner/mode or oversize state | fail before use; no alternate path |
| TT-19 | audit success and failure | fixed content-free fields only; audit sink failure returns no sample |
| TT-20 | lifecycle stopped/ready/degraded/recovered | sample only in ready; failure degrades/fails; validated recovery required |
| TT-21 | static import/write scan | no P07/session/P15/content/channel/network/process/credential path |
| TT-22 | P08 guard with provider samples | port accepted; restart sample advances beyond P08 mutation watermark |
| TT-23 | P08 expiry comparison with UTC sample | existing P08 UTC expiry rules hold; no live scheduler is added |
| TT-24 | timeout/unavailable/corrupt/drift during P08 read/write/expiry | no trusted sample, so P08 fails closed and emits no stale context |

## Deterministic checks

- Core focused suite runs `tests.test_trusted_time_provider` with
  `PYTHONDONTWRITEBYTECODE=1` and explicit `PYTHONPATH=src`.
- Existing P08 and P10-A focused suites run unchanged to prove compatibility.
- Full Core discovery and Deploy discovery run with no external dependency or live side
  effect.
- Static source scan rejects network/process clients, environment credential reads and
  cross-layer store names in `myuna_core.trusted_time`.
- Git diff/check/status, file ownership, tree ids, commits and rollback refs are recorded
  after tests and independently reread by Official.

## Worker matrix disposition

The bounded Worker inventory was advisory only. Official retained provider-relevant cases:
UTC/timezone, monotonic sequence, restart, rollback/drift, timeout/unavailable, corrupt
state, ambiguous commit, audit and layer isolation. Worker rows about P08 proposal,
confirmation, rendering, Profile routing, QQ or live scheduling are outside P10-B and do not
define this implementation.
