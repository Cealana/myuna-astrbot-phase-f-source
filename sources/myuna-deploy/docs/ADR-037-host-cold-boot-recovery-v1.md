# ADR-037: Host Cold-Boot Recovery v1

Status: candidate

## Decision

The Windows host receives one content-addressed, hidden, long-lived launcher for
`Server-Ubuntu`.  The launcher starts a fixed `sleep infinity` WSL client, runs
one fixed Linux no-audit readiness controller, records a sanitized Windows
receipt, and remains attached to the keepalive process.  If WSL is terminated,
the launcher exits non-zero and Task Scheduler retries it at one-minute
intervals, at most twelve times.

Every readiness receipt records the current Windows boot time.  The independent
post-boot verifier rejects a receipt written before the current boot or bound to
a different boot time.  It also revalidates the exact task action, Windows
release digest, root-owned Linux release, live physical-network default route
and CC Switch state, and
reruns the Linux no-audit readiness controller.  This prevents a stale receipt
from being accepted as cold-boot evidence.

The Linux controller does not start services.  systemd remains the only service
orchestration authority.  It waits up to six minutes for Docker, PostgreSQL,
Minecraft, its backup timer, Sakura FRP, Myuna Core, Telegram R5, Owner Runtime,
the expected sockets, and the fixed container contracts.  It performs only a
default-route check, DNS resolution, systemd/Docker inspection, and validation
of the existing Telegram R5 no-audit receipt.  It does not call Core HTTP
health endpoints, send messages, call a model, read private content, or invoke
tools.

The Windows launcher uses one shared 390-second startup budget for Linux
readiness and Windows prerequisites.  It requires at least one `Up` physical
network adapter that owns an active IPv4 default route and the existing
`cc-switch` process to be running.  This deliberately accepts either Ethernet
or the owner's current wireless adapter without accepting a virtual-only
adapter.  It does not connect to a wireless profile or launch CC Switch; those
remain Windows per-user startup responsibilities.  CC Switch has one separate
per-user `HKCU Run` entry; this controller requires that entry to point to the
installed executable and requires the matching process, but does not create a
second startup mechanism.

PandaFan retains one elevated per-user logon task as its only startup
mechanism.  The task is reconciled to a content-addressed launcher in this
release.  Before starting PandaFan, that launcher verifies the existing built-in
`auto_connect_on_start` intent and a remembered connection target, clears only
the stale `user_disconnected` boot blocker, and gives the application two
bounded 90-second attempts to establish its own connection.  It edits that one
boolean in place without serializing or logging proxy nodes, subscriptions,
credentials, or private routing content.  During those attempts it holds the
existing PandaFan watchdog mutex so the older periodic watchdog cannot race the
cold-start sequence.

The Host controller separately requires PandaFan's persisted application state
to be `connected` and freshly written during the current Windows boot, in
addition to requiring the loopback controller, enabled
TUN, and an `Up` reported TUN adapter.  A TUN adapter alone is not accepted as a
connection.  Only after the application reports `connected` may the controller
make one bounded local request to restore a disabled TUN.  This is an
intentional Windows network mutation and requires explicit T3 activation
authority.  If both application attempts fail, PandaFan remains visible for
manual recovery, Host readiness fails closed, and the workstation is not
locked as though recovery succeeded.

The existing `ChatGPT.lnk` Startup entry remains the only ChatGPT/Codex launch
mechanism.  Before locking the workstation, the controller requires the
AppsFolder shortcut shape, a visible ChatGPT main window, and a running Codex
process.  It does not launch another application instance.

The only accepted degraded-systemd exception is the exact
`user-runtime-dir@999.service` cleanup failure observed when WSL cannot remove
the non-login `myuna` account runtime directory after unmounting it.  Any other
failed unit rejects readiness.  All required application units must still be
active.

The task stays an interactive-logon task for the current Windows user.  This is
intentional: CC Switch is also a per-user interactive startup application, and
Task Scheduler S4U has no network or encrypted-file access.  Unattended Windows
logon is a separate owner decision and is never enabled by this release.
The release supports an optional `LockAfterReady` task flag.  It is disabled by
default and never enables automatic logon.  When explicitly activated together
with the owner's separate logon decision, the controller requests a Windows
workstation lock only after Linux and Windows prerequisites are ready, and
writes the current-boot readiness state only after that lock request succeeds.

The Autologon verifier is read-only and sanitized.  It checks only the Winlogon
enable flag, expected local user/domain shape, absence of a plaintext registry
password property or finite logon count, and alignment with the exact candidate
task and lock flag.  It never reads the LSA secret or validates a password.

## Installed boundaries

- Windows release root:
  `C:\Program Files\MyunaServer\HostColdBoot\releases\<digest>`
- Linux release root:
  `/opt/myuna/host-cold-boot/releases/<digest>`
- Tasks: `MyunaServer-Start-Server-Ubuntu` and the reconciled existing
  `PandaFan Elevated AutoStart`
- Sanitized log: `C:\ProgramData\MyunaServer\Logs\host-cold-boot-v1.log`
- Last readiness state:
  `C:\ProgramData\MyunaServer\State\host-cold-boot-v1.json`

The release installer independently validates the manifest digest, exact file
set, payload hashes, sizes, and allowed modes on both Windows and WSL before
activation.  Windows release ACLs grant full control only to `SYSTEM` and the
local Administrators group, and read/execute access to the built-in Users
group.  The scheduled task uses the exact content-addressed release paths,
`Interactive` logon, `Limited` run level, `IgnoreNew`, an unlimited execution
time, and a bounded restart policy.

The PowerShell controller records the exact `wscript.exe` launcher identity
and polls that launcher while waiting on Linux readiness and while holding the
long-lived WSL client.  If Task Scheduler stops or replaces the launcher, the
controller terminates its own keepalive and exits within five seconds.  This
prevents stopped or upgraded task instances from leaving duplicate controllers
or orphaned `sleep infinity` clients.
The launcher lease and Windows application prerequisites are sampled every
three seconds.  The five-second exit SLO includes Windows scheduling, process
termination, and sanitized event-write overhead.

Before replacement, installation backs up both prior task XML definitions and
the readiness state.  A started installation must produce a fresh no-audit readiness receipt
for the same release within seven minutes.  Otherwise the installer restores
the prior task, its running state, and the prior readiness state.  Immutable
Windows and Linux release directories are retained inactive for inspection;
rollback never deletes them.

The elevated invocation wrapper writes one atomic sanitized success or failure
receipt under the fixed Windows state root.  It creates that state directory
before invoking the release installer, so failures before task replacement are
still observable without exposing raw command output.

## Owner-only cold-boot decisions

For true plug-power-to-services operation, the owner must separately choose and
authorize all of the following:

1. ASUS UEFI `Advanced > APM Configuration > Restore AC Power Loss = Power On`.
2. Whether to enable Windows automatic logon for the local owner account.  The
   recommended practical option for this single-user home server is Microsoft
   Sysinternals Autologon followed by an automatic workstation lock after the
   readiness receipt.  It still creates a recoverable credential boundary and
   therefore remains a T3 owner decision.
3. Whether Fast Startup should be disabled for deterministic server boots.
4. A real Windows reboot test followed by a controlled AC-loss/power-restore
   test.  Abruptly cutting power is not a graceful Minecraft or PostgreSQL
   shutdown and must not be used as an ordinary restart mechanism.

## Rollback

Stop both new task instances, restore both backed-up task XML definitions,
restart the prior PandaFan and Host tasks as applicable, and leave the
content-addressed releases inactive.  Do not delete releases, logs, state,
backups, WSL distributions, containers, or service data during rollback.
