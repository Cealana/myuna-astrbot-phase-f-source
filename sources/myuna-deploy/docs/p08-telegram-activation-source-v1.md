# P08 Telegram client and activation source contract v1

Status: T1 source candidate; no installation or live authority

## Owner interaction

P08 uses an explicit `/temporal` grammar. Reads use `get`; writes use
proposal-first `add`, `supersede`, `refresh`, `restore` or `revoke`, followed by
the exact `confirm` command returned to the Owner. The Gateway admits the command
only after the normal signed Telegram Owner-private envelope, durable claim,
Owner binding and rate limit. Write consent is true only for explicit write or
confirmation commands.

The command is routed to the private P08 AF_UNIX service before Core chat. It
does not invoke a model, add a P07 external-epoch turn, write the 128-message
session, Profile, Writer, QQ or a legacy namespace. Invalid commands return a
fixed usage line. Service failures emit only a fixed temporal diagnostic and a
P16 `MYU-TEMPORAL-01` projection.

## Release and activation dependency

The P08 v2 code release binds the exact Core and Deploy commits, private-service
inventory and P08 Gateway client digest. The P08 activator does not select or
rewrite a Telegram runtime or AstrBot plugin. Its preflight requires a separately
prepared immutable Telegram runtime and plugin already containing the exact
bound client and command admission source. This prevents P08 from silently
invalidating the selected P07 release-set.

A future combined T2 coordinator must therefore select a P07-compatible
Core/runtime/plugin release first, then run the P08 activation, and roll the P07
selection back independently if P08 fails. This source candidate does not grant
that authority.

## P08 activation and rollback

The first activation requires absent selector, units and state. It installs one
immutable P08 release, creates the dedicated service identity and directories,
initializes exactly two empty private databases, installs the service/socket and
starts only those target units. Acceptance requires both units active, an exact
two-file 0600 service-owned state inventory, and a service-identity runtime
open/validation smoke. The selector binds the release, Gateway runtime, plugin
and client digests.

On failure, target units stop, exact file prestates are restored, and newly
created state is moved intact into the plan-addressed root-only backup. No P08
state is deleted. Installed code, plan and evidence remain. Existing state,
partial prestate, drift, unknown runtime/plugin, symlink, permission or digest
mismatch fails closed.

## Remaining T2 gate

Before live work, independently build the compatible P07 runtime/plugin and P08
release, rerun exact preflight twice, verify rollback under synthetic roots and
provide the Owner a decision-level T2 summary. Live acceptance remains bounded
to authenticated Telegram Owner-private and must cover empty retrieval,
proposal/confirmation, duplicate/conflict/refresh/expiry, failure projection and
rollback. QQ remains excluded.
