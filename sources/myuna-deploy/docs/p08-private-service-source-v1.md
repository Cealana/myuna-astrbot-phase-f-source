# P08 private service source contract v1

Status: T1 source/build candidate; not installed, selected or live

## Selected synchronization attestation

P08 selects `LinuxAdjtimexSynchronizationProbe` as the v1 host attestation for
`SystemUtcObservationSource`.  It reads the Linux kernel time-discipline state and
the kernel maximum/estimated error bounds through the native `adjtimex` call.  It
does not call a network client or subprocess, read a server/credential, accept a
caller timestamp, or use a filesystem marker/timestamp as time authority.

`STA_UNSYNC`, `TIME_ERROR`, malformed/negative error bounds, syscall failure and
timeout all fail closed.  The P10-B provider independently enforces synchronization,
the one-second uncertainty ceiling, durable sequence, source/authority continuity,
restart floor, regression and drift rules.

## Private service and state

- identity: `myuna_active_temporal`, with no login shell;
- state: `/var/lib/myuna-active-temporal-context-v1`, exact 0700;
- P08 and P10-B databases: fixed filenames, exact 0600, no symlink, independent
  schemas and transactions;
- socket: `/run/myuna-active-temporal-context-v1/temporal.sock`, 0660, readable
  only by the service and `myuna-gateway-telegram` group;
- the accepted connection must also present the exact Telegram runtime peer UID;
- service transport is AF_UNIX only and runs with a read-only host filesystem except
  the dedicated state directory;
- initialization creates only two new empty databases and refuses existing/partial
  state; it performs no repair, migration or fallback.

The worker binds the peer-verified transport to fixed client id
`telegram-owner-runtime-v1` and channel `astrbot_telegram`, then applies the strict
authenticated conversation context and P08 access policy before sampling trusted
time or opening Owner facts.

## Deterministic code release

`build_p08_active_temporal_release_v1.py` copies only the bounded P08, P10-B,
authenticated-context and identity dependencies plus the four systemd contracts.
It rejects symlinks, bytecode/cache files, unknown source commit formats and an
existing output path.  The manifest binds exact Core/Deploy commits and every file
size/digest.  Repeated synthetic builds must be byte-identical and import successfully
with runtime-only `PYTHONPATH` and bytecode disabled.

## Remaining before T2

This candidate does not install sysusers/tmpfiles/units, create live state, write a
selector, restart services or call Telegram.  A separate source phase must add the
Telegram client/proposal UX, exact selector/install/rollback activator and P16
service wiring.  Only after independent source review may a new T2 authority permit
private installation and bounded Owner E2E. QQ remains excluded.
