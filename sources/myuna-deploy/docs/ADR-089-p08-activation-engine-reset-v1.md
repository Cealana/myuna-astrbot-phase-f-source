# ADR-089: P08 activation engine architecture reset v1

Status: source-only architecture accepted for implementation; production live remains closed.

## Context

The retired P08 current-selected architecture accumulated sixteen material
failures.  The mandatory full-chain audit proved that repeated source identity
constants, independently assembled result schemas, divergent plan digests and
different invocation paths allowed individually green gates to disagree about
one activation.  Renaming a strategy or namespace does not reset that history.

## Decision

`myuna.p08-activation-engine.v1` is a replacement boundary, not a successor
patch to v13.  It has four authorities:

1. `p08_activation_contract_v1.py` generates one canonical contract containing
   the complete phase DAG, role inputs, exact schemas, source identities, one
   plan digest, deadlines/liveness, result classes, compatibility bindings and
   the immutable legacy-lineage aggregate.
2. `p08_activation_launcher_v1.py` supplies one invocation/capture envelope for
   every role.  It binds interpreter, source roots, cwd, uid/gid/groups, minimal
   environment, closed stdin, umask, hard/no-progress deadlines, strict progress
   messages and raw-free O_EXCL evidence.
3. `p08_activation_engine_v1.py` consumes the exact generated contract and plan.
   It owns phase ordering, max-one action semantics, continuity state and
   pre/postcommit convergence behavior.
4. `p08_activation_shadow_v1.py` runs a synthetic installed-target full chain
   using those same contract and engine bytes.  It is not an alternate product
   executor and cannot grant live authority.

No consumer may repeat a hand-authored source SHA, schema key allowlist, role
budget or phase transition.  Legacy controllers remain packaged only for the
currently selected release compatibility boundary and are explicitly marked
non-authoritative for the reset engine.

## Phase and state map

Readiness is `construct -> prepare -> formal1 -> formal2 -> exact_two -> drift`.
It is metadata-only and cannot read opaque state or mutate the product.

Mutation begins only after `claim`, then `backup -> stage -> stop_socket ->
stop_service -> install -> select -> start_service -> start_socket`.  The
continuity assessment then chooses one of these explicit states:

- `no_transition_required`: normal success path directly to acceptance;
- `transition_required`: one forward transition may be attempted;
- `transition_committed`: proceed to acceptance;
- `transition_ambiguous`: reconcile read-only inside the same action;
- `reconciled_committed`: proceed to acceptance with forward history;
- `reconciled_not_committed`: converge code/public selection and hard-stop,
  without replaying the transition.

Precommit convergence may restore the action-owned P08 opaque backup and exact
predecessor code/public selection.  After a committed or reconciled-committed
trusted-time transition, old trusted-time bytes/history are never restored;
only predecessor code/public selection may be recovered and the retained
forward state is recorded in a typed receipt.  Any unaccepted mutated target
still receives exactly one bounded convergence attempt.

## Evidence and failure behavior

Unknown, extra, missing, stale, mixed, replayed, substituted or raw-tainted
contract, plan, result, progress or capture data fails closed.  Invalid progress
cannot extend the no-progress deadline.  Hard deadlines cannot be extended by
liveness.  Timeout cleanup is TERM/KILL/wait/drain bounded and records only
fixed categories, sizes, hashes and phases.

The shadow injects each phase boundary, crash, timeout, identity drift,
permission/mode/inventory failure, both ambiguity outcomes, acceptance failure
and convergence/recovery failure.  Synthetic bytes never represent Owner data.

## T1 and future gate

T1 builds the generated contract and engine into a deterministic inactive
release and proves the full-chain shadow.  The current release manifest marks
`live_execute_implemented=false`: a reviewed production mutating role adapter
driven by this same contract is still required before any T2 can be `GO`.
Consequently this checkpoint may be source-mainline complete while remaining
`NO-GO` for live activation.  It does not authorize production prepare,
namespace creation, preflight, action, status, service mutation or rollback.
