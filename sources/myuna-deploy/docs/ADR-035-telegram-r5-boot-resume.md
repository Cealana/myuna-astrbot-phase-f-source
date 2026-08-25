# ADR-035: Telegram R5 bounded boot resume

## Decision

The verified Telegram Owner private-text chain receives a dedicated root
oneshot controller.  It is enabled at `multi-user.target` and does exactly the
following after WSL/systemd starts:

1. verifies the persistent runtime marker, exact binding, fixed release paths,
   local secret metadata, and retired challenge chain;
2. recreates `/run/myuna-telegram-gateway` with the installed tmpfiles contract
   and validates the separately installed media-auth runtime root against its
   service-owned `0750` tmpfiles contract;
3. copies the authority channel-signing secret into a service-owned ephemeral
   file without printing, hashing, or recording it;
4. validates that any retained rollback container is stopped with restart
   policy `no`, and that the managed exact-name container belongs to the
   canonical `myuna-telegram-r5-v1` Compose project;
5. starts the already-installed Telegram Owner runtime socket and service
   without enabling either one;
6. starts the pinned Telegram AstrBot compose service under the canonical
   project;
7. requires the runtime socket/service, container health, and a loopback Core
   TCP connection to pass before recording a non-sensitive no-audit receipt.

It does not enable the runtime socket or runtime service.  They remain isolated
from QQ and can still be socket-activated outside the boot transaction.  The controller does not send Telegram
messages, call a model, read or write memory, or enable tools, vision,
scheduler, group messages, or unknown users.

Core `/healthz` and `/readyz` emit audit records and are therefore forbidden in
the boot controller.  Core readiness is limited to a TCP connect without
sending application bytes.  The receipt records that limitation explicitly
and does not claim an HTTP health result.

The controller unit sets `PYTHONDONTWRITEBYTECODE=1`.  A content-addressed
controller release contains only the manifest-declared source artifacts and
must not gain mutable Python cache files during boot.

The Compose service uses `on-failure:3`.  Docker may restart a process that
exits non-zero, but it does not start that container merely because the Docker
daemon restarted.  This reserves cold-boot ordering for R5 so the ephemeral
signing file exists before Docker evaluates the bind mount.  R5 still removes
an old placeholder only when it is the exact non-symlink, non-mountpoint,
empty `root:root 0755` directory and the managed container is not running.
Any other shape fails closed; there is no recursive or wildcard deletion.

Rollback containers use the exact prefix
`myuna-astrbot-telegram-dev.pre-`.  They may retain their historical Compose
labels, but must be stopped and have restart policy `no`.  A running archive,
an archive with an automatic restart policy, or a managed exact-name container
owned by a non-canonical Compose project blocks recovery.

## Failure behavior

One attempt may wait up to six minutes.  On failure it stops only the canonical
Telegram R5 Compose service and Telegram Owner runtime socket/service, deletes
only the ephemeral signing copy, and exits non-zero.  systemd permits at most
three attempts in fifteen minutes, separated by sixty seconds.  There is no
unbounded restart loop and no automatic login or identity challenge.

The persistent verified binding, Bot token, authority secrets, AstrBot data,
Core, QQ, databases, Definition, memory, network, and remote-control services
are not rolled back or modified by this controller.

## Recovery and upgrade

The controller reads a root-owned exact release binding from
`/etc/myuna-telegram-gateway/r5-resume-v1.json`.  A future Gateway release must
replace that binding through a separately verified transaction.  Disabling the
R5 controller affects only automatic boot recovery; it does not revoke the
Telegram identity binding or delete channel data.

Migration into this contract is a separate bounded activation: stop and rename
the currently working container, set every retained container to restart
policy `no`, create the canonical-project container, and preserve the renamed
working container until a later explicit cleanup decision.  Rollback removes
only the new canonical container without volumes and restores the retained
working container and its prior project.
