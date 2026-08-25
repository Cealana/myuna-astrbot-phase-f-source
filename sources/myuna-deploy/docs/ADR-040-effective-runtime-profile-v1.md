# ADR-040: Effective Runtime Profile v1

Status: R1 repository-only / inactive / not installed / not selected

## Decision

Myuna will represent one explainable runtime composition with a single canonical
Effective Runtime Profile.  The profile binds immutable or repository-backed
identities for:

- Core Release;
- Definition Release;
- channel-neutral capability profile;
- memory adapter;
- reply contract;
- provider policy;
- prompt budget;
- optional metadata-only Shadow observers.

This solves configuration ownership, not service activation.  R1 cannot install,
select, activate, restart, reload, or grant any capability.

## Safety properties

- Every component has an opaque ID, source kind, canonical approved source path,
  and lowercase SHA-256 digest.
- `/etc`, `/run`, Secret, credential, and arbitrary filesystem paths are rejected.
- The component set is exact and component IDs are unique.
- The profile state is fixed to `inactive_candidate`.
- Automatic activation, selected state, and installed state are all false.
- Any later install or activation requires a new plan digest and a live preflight.
- Canonical JSON bytes produce a deterministic profile digest.

## Provisional ownership evidence

The R1 example intentionally records two pieces of present technical debt:

- the reply contract is still provisionally represented by `conversation.py`;
- current runtime selection still uses multiple drop-ins rather than this profile.

Later Conversation Pipeline extraction will replace the provisional reply
contract reference with a dedicated module identity.  The profile must not hide
that transition.

## Non-effects

R1 adds only a strict parser, tests, an inactive example, and this ADR.  It does
not modify live bindings, current Definition registry, capability manifests,
systemd, services, credentials, QQ, Telegram, providers, memory, tools, vision,
networking, Minecraft, or backups.

## Follow-up

Shared Gateway Runtime Kernel v1 will consume the authenticated-context and
channel-neutral capability contracts.  A later inactive installer may package an
Effective Runtime Profile, but installation and live selection remain separate,
content-addressed approvals.
