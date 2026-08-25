# ADR-090: P08 activation-engine v1 production adapter

Status: source-only implementation complete; production authorization remains
false pending an independent full-chain review and separately sequenced T2.

## Decision boundary

The production adapter is part of `myuna.p08-activation-engine.v1`; it is not a
new versioned activation strategy and does not reset the sixteen counted legacy
failures.  ADR-089 remains the architecture-reset record.  This ADR supplies
the concrete adapter, supervisor, installed-target shadow and crash recovery
needed to decide whether that architecture is executable.

The generated contract remains the only role, phase, schema, source identity,
budget and compatibility authority.  Production code may refer to generated
contract values but may not restate independent digest or schema allowlists.
The contract binds the complete Deploy engine source inventory and the exact
Core runtime closure used by the launcher before any child is created.

## Source-owned orchestration

`p08_activation_supervisor_v1.py` is the only plan-construction and orchestration
entrypoint.  It generates the sequence identity and single invocation nonce,
derives the predecessor from the strict current selector projection, builds one
plan digest, creates one private O_EXCL sequence namespace and writes the plan
with mode 0600 and fsync.  A second plan for the architecture is rejected.

Every role then uses `p08_activation_launcher_v1.py`.  Before child creation the
launcher verifies the interpreter, full bound Core and Deploy inventories,
contract bytes, plan bytes, cwd, uid/gid/groups, minimal environment, closed
stdin, umask, role deadline and liveness policy.  The supervisor persists a
source-bound O_EXCL role-intent containing the complete content-free invocation
projection before creating the child.  Captures retain only canonical result,
sizes, hashes, exit class and allowlisted progress; raw stdout/stderr is never
retained.  A canonical ready or rejected result is valid only for a normal
process exit with no surviving process-group member; timeout, signal, invalid
progress, oversized pipes and any observed orphan remain indeterminate.

The plan binds the target directory's digest-shaped identity, exact release
manifest, complete regular-file inventory and complete directory inventory.
The installed closure is read back with exact path, type, mode, uid/gid, link
count, size and digest before selection; neither Deploy nor Core source roots
are accepted as a runtime import fallback.

## Phase and ownership order

Readiness is strictly metadata-only:

`construct -> prepare -> formal1 -> formal2 -> exact_two -> drift`

Mutation ownership and activation are:

`claim -> backup -> stage -> stop_socket -> stop_service -> install -> select`

Continuity is evaluated before either unit is restarted.  A normal
`no_transition_required` result proceeds directly to `start_service`; a
required transition is attempted once.  `transition_ambiguous`, including a
missing result after an authorized child creation, must execute the same-action
read-only `continuity_reconcile` before acceptance or convergence is chosen.
Only after a resolved continuity state may the engine run:

`start_service -> start_socket -> accept_status -> postflight`

The acceptance helper is executed from the installed target closure only.  The
single supervisor-generated nonce crosses helper request, server echo, helper
projection and parent validation without replacement.  The target cannot use
the Deploy or Core source roots as an import fallback.

## Backups and convergence

Public and opaque backups exist only after O_EXCL action ownership.  Each file
uses no-follow source and destination descriptors, exact stat-before/read/stat-
after identity, non-overwriting staging/finalization, explicit mode and owner,
streaming digest/read-back, file fsync and directory fsync.  Unexpected files,
directories, links, hardlinks, modes, owners, sizes or hashes fail closed before
the first unit stop.

Before a committed transition, bounded convergence restores exact predecessor
code/public selection and the action-owned P08 opaque backup.  After a committed
or reconciled-committed transition, old trusted-time bytes/history are never
restored; convergence restores only predecessor code/public selection while
retaining forward state.  Service starts before socket; socket stops before
service.  Unit state, restart count, active-enter counters and FragmentPath are
read back through the fixed systemctl identity.

## Crash and replay behavior

Role intent is durable before child creation.  Intent without capture consumes
that call as indeterminate; it is never replayed.  The source-owned recovery
entrypoint reconstructs the engine from the exact ordered intent/capture prefix.
A pre-mutation interruption closes without ceremonial rollback.  A mutated
product converges exactly once.  Ordinary supervisor failures enter the same
source-owned recovery path; simulated process death remains an explicit later
recovery invocation.  An ambiguous transition first reconciles in the same
action.  If that read-only reconcile itself cannot resolve the commit state,
recovery conservatively retains possible forward state and converges code and
public selection only; it never restores old trusted-time history.  Interrupted
convergence cannot be retried under a successor name.
Mixed intent/capture/failure evidence, missing predecessors, replay, source
drift and terminal receipt substitution fail closed.

## Verification and remaining gate

The installed-target shadow calls the same supervisor, launcher, adapter and
contract used by production.  It uses protected temp roots, synthetic units and
network-denied acceptance; it never touches the live selector, state, socket or
systemd.  Fault injection covers phase rejection, child/capture crash windows,
timeout, stale/mixed evidence, both continuity reconcile outcomes, acceptance
failure, convergence failure and interrupted recovery.

The release may declare `live_execute_implemented=true` only after these tests,
deterministic build and final source/provenance review pass.  Its canonical
contract still declares `production_live_authorized=false`: neither this ADR nor
the inactive build authorizes prepare, preflight, namespace creation, service
mutation, protocol acceptance or recovery on the real host.
