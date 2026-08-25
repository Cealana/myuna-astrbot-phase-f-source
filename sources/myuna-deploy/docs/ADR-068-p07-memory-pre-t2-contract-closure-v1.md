# ADR-068: P07 memory pre-T2 contract closure v1

Status: accepted T1 source contract; inactive. This ADR authorizes no install, selector change, service restart, data migration, provider call, activation, or Owner E2E.

## Calendar-zone identity

The P07 memory selector v2 binds one IANA calendar-zone selection and its semantic digest. Supported v1 values are `Asia/Shanghai` and `America/Los_Angeles`; the default remains `Asia/Shanghai`. The selection reuses the one P10-B trusted-time sample already bound to a turn. Switching zones changes local calendar/date projection and future grouping only: it neither resamples time nor rewrites archived turns. Unknown, partial, stale, unsupported, or digest-drifted selection fails closed before provider egress.

## P08 lifecycle bridge

A P08 `temporary_plan` activated by an Owner confirmation is classified as `confirmed_started`, not merely `planned`. The bridge also preserves planned, observed, changed, ended, cancelled, and superseding revision semantics. Only a lifecycle transition whose source pointer resolves to a delivered, control-isolated raw turn may enter the derivative interval index. Gaps, conflicts, replay drift, missing source, unresolved time, and blocked transitions remain typed and fail closed.

## Stable Profile mutation

Only an authenticated Telegram Owner-private whole-message `/Benchmark` proposal, confirmation, or cancellation may enter the existing content-addressed Profile candidate protocol. `/Diary` is a diary control/archive turn only and has no Profile consent. Natural chat, `/temporal`, `/Check`, episodic recall, diary jobs, and P08 cannot create or commit stable Profile changes. Read-only Profile projection remains unchanged. P15 stays inactive; P07 remains the single temporary prompt owner and dual ownership is rejected.

The outer AstrBot envelope remains capability-free. The protected gateway derives the exact `/Benchmark` consent only after authenticated Owner-private admission. Both `/Diary` and `/Benchmark` remain single-turn control-history-isolated and are eligible for the existing delivered-ack raw archive path; neither duplicates ordinary history writes.

## Rollback and compatibility

The predecessor Core/Deploy/Definition refs remain the source rollback. Live Effective V6 plus compressed generation13, all attempts, receipts, epochs, services, and data are unchanged by this T1 phase. Automatic reflective-diary provider generation and diary egress remain outside this ADR.
