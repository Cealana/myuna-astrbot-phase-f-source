from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json
import re
from types import MappingProxyType
from typing import Mapping

from .contracts import (
    PROFILE_CURRENT_STATES,
    PROFILE_ORDINARY_DELTA_LIMIT,
    ProfileCurrentValue,
    ProfileModuleManifest,
    ProfileStateEvent,
    ProfileStateIntent,
    ProfileStateReceipt,
    OwnerProfile,
    OwnerProfileError,
    profile_v2_manifests,
    profile_state_digest,
)


SCHEMA_VERSION = 1
AUDIT_NAMESPACE = "owner_profile_write_lifecycle_v1"
GENESIS_DIGEST = "0" * 64
MAX_EVENT_BYTES = 8_192
MAX_EVENTS = 4_096
EVENT_TYPES = frozenset(
    {
        "baseline_registered",
        "candidate_prepared",
        "owner_confirmed",
        "published",
        "revoked",
        "restored",
        "deletion_requested",
        "deletion_cancelled",
        "purged",
    }
)
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVENT_KEYS = {
    "schema_version",
    "event_type",
    "event_id",
    "sequence",
    "previous_event_sha256",
    "profile_id",
    "base_revision",
    "base_sha256",
    "target_revision",
    "target_sha256",
    "confirmation_sha256",
    "reason_category",
}
_EVENT_REASONS = {
    "baseline_registered": frozenset({"initial_registration"}),
    "candidate_prepared": frozenset(
        {"owner_authored_revision", "myuna_analyzed_candidate"}
    ),
    "owner_confirmed": frozenset({"owner_confirmed"}),
    "published": frozenset({"owner_confirmed"}),
    "revoked": frozenset({"owner_requested", "rollback"}),
    "restored": frozenset({"owner_requested", "rollback"}),
    "deletion_requested": frozenset({"privacy_removal"}),
    "deletion_cancelled": frozenset({"owner_requested", "rollback"}),
    "purged": frozenset({"privacy_removal"}),
}
_AUDIT_ERRORS = frozenset(
    {
        "invalid_event",
        "event_chain_rejected",
        "state_transition_rejected",
        "revision_comparison_rejected",
        "lifecycle_unavailable",
        "lifecycle_path_rejected",
        "lifecycle_permission_drift",
        "lifecycle_recovery_required",
    }
)


class OwnerProfileLifecycleError(OwnerProfileError):
    pass


def _reject(code: str) -> OwnerProfileLifecycleError:
    return OwnerProfileLifecycleError(code)


def _safe_label(value: object) -> str:
    if not isinstance(value, str) or _SAFE_LABEL.fullmatch(value) is None:
        raise _reject("invalid_event")
    return value


def _digest(value: object, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject("invalid_event")
    return value


def _revision(value: object, *, optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _reject("invalid_event")
    return value


@dataclass(frozen=True, slots=True)
class LifecycleEvent:
    event_type: str
    event_id: str
    sequence: int
    previous_event_sha256: str
    profile_id: str
    base_revision: int | None
    base_sha256: str | None
    target_revision: int
    target_sha256: str
    confirmation_sha256: str | None
    reason_category: str
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or self.schema_version != SCHEMA_VERSION
            or self.event_type not in EVENT_TYPES
        ):
            raise _reject("invalid_event")
        _safe_label(self.event_id)
        _safe_label(self.profile_id)
        if self.reason_category not in _EVENT_REASONS[self.event_type]:
            raise _reject("invalid_event")
        if isinstance(self.sequence, bool) or not 1 <= self.sequence <= MAX_EVENTS:
            raise _reject("invalid_event")
        _digest(self.previous_event_sha256)
        _revision(self.base_revision, optional=True)
        _digest(self.base_sha256, optional=True)
        _revision(self.target_revision)
        _digest(self.target_sha256)
        _digest(self.confirmation_sha256, optional=True)
        if (self.base_revision is None) != (self.base_sha256 is None):
            raise _reject("invalid_event")
        base_required = self.event_type in {
            "candidate_prepared",
            "owner_confirmed",
            "published",
        }
        if base_required != (self.base_revision is not None):
            raise _reject("invalid_event")
        confirmation_required = self.event_type != "candidate_prepared"
        if confirmation_required != (self.confirmation_sha256 is not None):
            raise _reject("invalid_event")

    def as_payload(self) -> dict[str, object]:
        return {
            "base_revision": self.base_revision,
            "base_sha256": self.base_sha256,
            "confirmation_sha256": self.confirmation_sha256,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "previous_event_sha256": self.previous_event_sha256,
            "profile_id": self.profile_id,
            "reason_category": self.reason_category,
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "target_revision": self.target_revision,
            "target_sha256": self.target_sha256,
        }

    def canonical_bytes(self) -> bytes:
        encoded = json.dumps(
            self.as_payload(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii") + b"\n"
        if len(encoded) > MAX_EVENT_BYTES:
            raise _reject("invalid_event")
        return encoded

    @property
    def sha256(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_bytes(cls, payload: bytes) -> LifecycleEvent:
        if not payload or len(payload) > MAX_EVENT_BYTES:
            raise _reject("invalid_event")
        try:
            parsed = json.loads(payload.decode("ascii"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise _reject("invalid_event") from exc
        if not isinstance(parsed, dict) or set(parsed) != _EVENT_KEYS:
            raise _reject("invalid_event")
        return cls(
            schema_version=parsed["schema_version"],
            event_type=parsed["event_type"],
            event_id=parsed["event_id"],
            sequence=parsed["sequence"],
            previous_event_sha256=parsed["previous_event_sha256"],
            profile_id=parsed["profile_id"],
            base_revision=parsed["base_revision"],
            base_sha256=parsed["base_sha256"],
            target_revision=parsed["target_revision"],
            target_sha256=parsed["target_sha256"],
            confirmation_sha256=parsed["confirmation_sha256"],
            reason_category=parsed["reason_category"],
        )


@dataclass(frozen=True, slots=True)
class RevisionState:
    revision: int
    profile_sha256: str
    status: str
    confirmation_sha256: str | None = None
    status_before_deletion: str | None = None


@dataclass(frozen=True, slots=True)
class LifecycleState:
    profile_id: str
    last_sequence: int
    last_event_sha256: str
    active_revision: int | None
    revisions: Mapping[int, RevisionState]
    event_ids: frozenset[str]

    @classmethod
    def empty(cls, profile_id: str) -> LifecycleState:
        return cls(
            profile_id=_safe_label(profile_id),
            last_sequence=0,
            last_event_sha256=GENESIS_DIGEST,
            active_revision=None,
            revisions=MappingProxyType({}),
            event_ids=frozenset(),
        )


@dataclass(frozen=True, slots=True)
class ProfileChangeSummary:
    base_revision: int
    target_revision: int
    added_sections: int
    updated_sections: int
    removed_sections: int


def compare_profile_revisions(
    base: OwnerProfile,
    candidate: OwnerProfile,
) -> ProfileChangeSummary:
    if (
        base.profile_id != candidate.profile_id
        or candidate.profile_revision != base.profile_revision + 1
        or base.sha256 == candidate.sha256
    ):
        raise _reject("revision_comparison_rejected")
    base_sections = {item.topic_key: item for item in base.sections}
    candidate_sections = {item.topic_key: item for item in candidate.sections}
    common = set(base_sections) & set(candidate_sections)
    summary = ProfileChangeSummary(
        base_revision=base.profile_revision,
        target_revision=candidate.profile_revision,
        added_sections=len(set(candidate_sections) - set(base_sections)),
        updated_sections=sum(
            base_sections[key] != candidate_sections[key] for key in common
        ),
        removed_sections=len(set(base_sections) - set(candidate_sections)),
    )
    if not (
        summary.added_sections
        or summary.updated_sections
        or summary.removed_sections
    ):
        raise _reject("revision_comparison_rejected")
    return summary


def _matching_revision(event: LifecycleEvent, record: RevisionState) -> None:
    if (
        event.target_revision != record.revision
        or event.target_sha256 != record.profile_sha256
    ):
        raise _reject("state_transition_rejected")


def _matching_base(event: LifecycleEvent, state: LifecycleState) -> None:
    if state.active_revision is None:
        raise _reject("state_transition_rejected")
    active = state.revisions[state.active_revision]
    if (
        event.base_revision != active.revision
        or event.base_sha256 != active.profile_sha256
    ):
        raise _reject("state_transition_rejected")


def apply_lifecycle_event(
    state: LifecycleState,
    event: LifecycleEvent,
) -> LifecycleState:
    if (
        event.profile_id != state.profile_id
        or event.sequence != state.last_sequence + 1
        or event.previous_event_sha256 != state.last_event_sha256
        or event.event_id in state.event_ids
    ):
        raise _reject("event_chain_rejected")
    revisions = dict(state.revisions)
    active_revision = state.active_revision

    if event.event_type == "baseline_registered":
        if state.last_sequence != 0 or event.base_revision is not None:
            raise _reject("state_transition_rejected")
        revisions[event.target_revision] = RevisionState(
            event.target_revision,
            event.target_sha256,
            "published",
            confirmation_sha256=event.confirmation_sha256,
        )
        active_revision = event.target_revision
    elif event.event_type == "candidate_prepared":
        _matching_base(event, state)
        if (
            event.target_revision != event.base_revision + 1
            or event.target_sha256 == event.base_sha256
            or event.target_revision in revisions
        ):
            raise _reject("state_transition_rejected")
        revisions[event.target_revision] = RevisionState(
            event.target_revision,
            event.target_sha256,
            "prepared",
        )
    else:
        record = revisions.get(event.target_revision)
        if record is None:
            raise _reject("state_transition_rejected")
        _matching_revision(event, record)
        if event.event_type in {"owner_confirmed", "published"}:
            _matching_base(event, state)
        if event.event_type == "owner_confirmed":
            if record.status != "prepared":
                raise _reject("state_transition_rejected")
            revisions[record.revision] = replace(
                record,
                status="confirmed",
                confirmation_sha256=event.confirmation_sha256,
            )
        elif event.event_type == "published":
            if (
                record.status != "confirmed"
                or event.confirmation_sha256 != record.confirmation_sha256
            ):
                raise _reject("state_transition_rejected")
            assert active_revision is not None
            previous = revisions[active_revision]
            revisions[active_revision] = replace(previous, status="superseded")
            revisions[record.revision] = replace(record, status="published")
            active_revision = record.revision
        elif event.event_type == "revoked":
            if record.status not in {"published", "superseded"}:
                raise _reject("state_transition_rejected")
            revisions[record.revision] = replace(record, status="revoked")
            if active_revision == record.revision:
                active_revision = None
        elif event.event_type == "restored":
            if (
                active_revision == record.revision
                or record.status not in {"published", "superseded", "revoked"}
            ):
                raise _reject("state_transition_rejected")
            if active_revision is not None and active_revision != record.revision:
                previous = revisions[active_revision]
                revisions[active_revision] = replace(previous, status="superseded")
            revisions[record.revision] = replace(record, status="published")
            active_revision = record.revision
        elif event.event_type == "deletion_requested":
            if active_revision == record.revision or record.status not in {
                "superseded",
                "revoked",
            }:
                raise _reject("state_transition_rejected")
            revisions[record.revision] = replace(
                record,
                status="deletion_requested",
                status_before_deletion=record.status,
            )
        elif event.event_type == "deletion_cancelled":
            if (
                record.status != "deletion_requested"
                or record.status_before_deletion not in {"superseded", "revoked"}
            ):
                raise _reject("state_transition_rejected")
            revisions[record.revision] = replace(
                record,
                status=record.status_before_deletion,
                status_before_deletion=None,
            )
        elif event.event_type == "purged":
            if record.status != "deletion_requested":
                raise _reject("state_transition_rejected")
            revisions[record.revision] = replace(
                record,
                status="purged",
                status_before_deletion=None,
            )
        else:
            raise _reject("state_transition_rejected")

    return LifecycleState(
        profile_id=state.profile_id,
        last_sequence=event.sequence,
        last_event_sha256=event.sha256,
        active_revision=active_revision,
        revisions=MappingProxyType(revisions),
        event_ids=state.event_ids | {event.event_id},
    )


def replay_lifecycle(
    profile_id: str,
    event_payloads: tuple[bytes, ...],
) -> LifecycleState:
    if len(event_payloads) > MAX_EVENTS:
        raise _reject("event_chain_rejected")
    state = LifecycleState.empty(profile_id)
    for payload in event_payloads:
        state = apply_lifecycle_event(state, LifecycleEvent.from_bytes(payload))
    return state


def lifecycle_audit_projection(
    event: LifecycleEvent | None,
    *,
    outcome: str,
    error_category: str | None = None,
) -> dict[str, object]:
    if outcome not in {"accepted", "rejected", "failed"}:
        raise ValueError("unsupported lifecycle audit outcome")
    if error_category is not None and error_category not in _AUDIT_ERRORS:
        raise ValueError("unsupported lifecycle audit error category")
    release_effect = {
        "published": "publish",
        "purged": "purge",
    }.get(event.event_type if event is not None else "", "none")
    return {
        "event_namespace": AUDIT_NAMESPACE,
        "outcome": outcome,
        "operation_category": event.event_type if event is not None else "unknown",
        "sequence": event.sequence if event is not None else 0,
        "target_revision": event.target_revision if event is not None else 0,
        "confirmation_present": bool(
            event is not None and event.confirmation_sha256 is not None
        ),
        "release_effect_category": release_effect,
        "raw_content_recorded": False,
        "legacy_namespace_written": False,
        "error_category": error_category,
    }


PROFILE_STATE_GENESIS_DIGEST = "0" * 64


def _profile_current(
    manifest: ProfileModuleManifest,
    *,
    state: str,
    scaled_value: int | None,
    last_sequence: int,
    last_event_id: str | None,
    last_event_digest: str,
) -> ProfileCurrentValue:
    payload = {
        "field_id": manifest.field_id,
        "last_event_digest": last_event_digest,
        "last_event_id": last_event_id,
        "last_sequence": last_sequence,
        "manifest_digest": manifest.manifest_digest,
        "module_id": manifest.module_id,
        "scaled_value": scaled_value,
        "state": state,
    }
    return ProfileCurrentValue(
        module_id=manifest.module_id,
        field_id=manifest.field_id,
        state=state,
        scaled_value=scaled_value,
        last_sequence=last_sequence,
        last_event_id=last_event_id,
        last_event_digest=last_event_digest,
        manifest_digest=manifest.manifest_digest,
        projection_digest=profile_state_digest(
            "myuna-profile-current-projection-v2", payload
        ),
    )


def initial_profile_current(manifest: ProfileModuleManifest) -> ProfileCurrentValue:
    return _profile_current(
        manifest,
        state="uninitialized",
        scaled_value=None,
        last_sequence=0,
        last_event_id=None,
        last_event_digest=PROFILE_STATE_GENESIS_DIGEST,
    )


def evaluate_profile_state_transition(
    manifest: ProfileModuleManifest,
    current: ProfileCurrentValue,
    intent: ProfileStateIntent,
    *,
    prior_event: ProfileStateEvent | None = None,
    rollback_target: ProfileStateEvent | None = None,
) -> tuple[ProfileStateEvent | None, ProfileCurrentValue, ProfileStateReceipt]:
    catalog_manifest = next(
        (item for item in profile_v2_manifests() if item.field_id == manifest.field_id),
        None,
    )
    if (
        catalog_manifest is None
        or manifest != catalog_manifest
        or current.module_id != manifest.module_id
        or current.field_id != manifest.field_id
        or current.manifest_digest != manifest.manifest_digest
        or intent.module_id != manifest.module_id
        or intent.field_id != manifest.field_id
        or current.state not in PROFILE_CURRENT_STATES
    ):
        raise OwnerProfileLifecycleError("profile_state_binding_rejected")
    manifest.require_action_policy(
        actor=intent.actor,
        action=intent.action,
        reason_category=intent.reason_category,
    )
    if (
        intent.expected_event_digest is not None
        and intent.expected_event_digest != current.last_event_digest
    ):
        raise OwnerProfileLifecycleError("profile_state_head_stale")
    if intent.action == "no_change":
        return (
            None,
            current,
            ProfileStateReceipt(
                outcome="no_change",
                replayed=False,
                mutated=False,
                event_id=None,
                event_digest=current.last_event_digest,
                projection_digest=current.projection_digest,
                reason_category="no_change",
            ),
        )
    if manifest.value_kind != "fixed_point":
        raise OwnerProfileLifecycleError("profile_state_module_uninitialized")
    assert manifest.minimum is not None and manifest.maximum is not None

    prior_state = current.state
    prior_value = current.scaled_value
    target_state = prior_state
    target_value = prior_value
    if intent.action == "propose_manifest":
        if (
            intent.proposal_manifest_head != current.last_event_digest
            or intent.proposal_expires_at_utc is None
            or intent.delivered_at_utc > intent.proposal_expires_at_utc
            or intent.requested_value is None
            or intent.requested_value < manifest.minimum
            or intent.requested_value > manifest.maximum
        ):
            raise OwnerProfileLifecycleError("profile_state_proposal_head_rejected")
    elif intent.action in {"confirm_manifest", "cancel_manifest"}:
        if (
            intent.actor != "owner"
            or prior_event is None
            or prior_event.event_digest != current.last_event_digest
            or prior_event.action != "propose_manifest"
            or prior_event.proposal_id != intent.proposal_id
            or prior_event.proposal_version != intent.proposal_version
            or prior_event.proposal_manifest_head != intent.proposal_manifest_head
            or prior_event.proposal_change_digest != intent.proposal_change_digest
            or prior_event.proposal_expires_at_utc != intent.proposal_expires_at_utc
            or (
                intent.action == "confirm_manifest"
                and prior_event.proposal_value != intent.requested_value
            )
            or intent.delivered_at_utc > intent.proposal_expires_at_utc
        ):
            raise OwnerProfileLifecycleError("profile_state_confirmation_rejected")
        if intent.action == "confirm_manifest":
            if prior_state == "frozen":
                raise OwnerProfileLifecycleError("profile_state_confirmation_rejected")
            target_state = "current"
            target_value = intent.requested_value
    elif intent.action == "initialize":
        if prior_state != "uninitialized" or intent.actor != "owner":
            raise OwnerProfileLifecycleError("profile_state_initialization_rejected")
        target_state = "current"
        target_value = intent.requested_value
    elif intent.action == "delta":
        if prior_state != "current" or prior_value is None:
            raise OwnerProfileLifecycleError("profile_state_delta_rejected")
        assert intent.requested_delta is not None
        if (
            intent.actor == "myuna"
            and abs(intent.requested_delta) > PROFILE_ORDINARY_DELTA_LIMIT
        ):
            raise OwnerProfileLifecycleError("profile_state_delta_limit_rejected")
        target_value = max(
            manifest.minimum,
            min(manifest.maximum, prior_value + intent.requested_delta),
        )
    elif intent.action == "correct":
        if intent.actor != "owner" or prior_state == "uninitialized":
            raise OwnerProfileLifecycleError("profile_state_correction_rejected")
        target_value = intent.requested_value
    elif intent.action == "freeze":
        if intent.actor != "owner" or prior_state != "current":
            raise OwnerProfileLifecycleError("profile_state_freeze_rejected")
        target_state = "frozen"
    elif intent.action == "unfreeze":
        if intent.actor != "owner" or prior_state != "frozen":
            raise OwnerProfileLifecycleError("profile_state_unfreeze_rejected")
        target_state = "current"
    elif intent.action == "rollback":
        if (
            intent.actor != "owner"
            or prior_state == "uninitialized"
            or rollback_target is None
            or rollback_target.event_id != intent.rollback_target_event_id
            or rollback_target.event_digest != intent.rollback_target_event_digest
            or rollback_target.field_id != intent.field_id
            or rollback_target.sequence >= current.last_sequence
            or rollback_target.current_value != intent.requested_value
        ):
            raise OwnerProfileLifecycleError("profile_state_rollback_rejected")
        target_value = intent.requested_value
    else:
        raise OwnerProfileLifecycleError("profile_state_transition_rejected")

    if target_state == "uninitialized":
        if target_value is not None:
            raise OwnerProfileLifecycleError("profile_state_value_rejected")
    elif (
        target_value is None
        or target_value < manifest.minimum
        or target_value > manifest.maximum
    ):
        raise OwnerProfileLifecycleError("profile_state_value_rejected")
    event = ProfileStateEvent(
        sequence=current.last_sequence + 1,
        event_id=intent.intent_id,
        previous_event_digest=current.last_event_digest,
        intent_digest=intent.intent_digest,
        manifest_digest=manifest.manifest_digest,
        module_id=manifest.module_id,
        field_id=manifest.field_id,
        action=intent.action,
        reason_category=intent.reason_category,
        prior_state=prior_state,
        prior_value=prior_value,
        current_state=target_state,
        current_value=target_value,
        requested_delta=intent.requested_delta,
        applied_delta=(
            target_value - prior_value
            if intent.action == "delta"
            and target_value is not None
            and prior_value is not None
            else None
        ),
        raw_source_digest=intent.raw_source_digest,
        p08_source_digest=intent.p08_source_digest,
        trusted_time_digest=intent.trusted_time_digest,
        delivered_turn_id=intent.delivered_turn_id,
        delivery_ack_digest=intent.delivery_ack_digest,
        delivered_source_reference_digest=intent.delivered_source_reference_digest,
        delivered_at_utc=intent.delivered_at_utc,
        episode_revision_id=intent.episode_revision_id,
        p08_episode_id=intent.p08_episode_id,
        p08_interval_id=intent.p08_interval_id,
        p08_terminal_revision=intent.p08_terminal_revision,
        p08_terminal_revision_digest=intent.p08_terminal_revision_digest,
        p08_terminal_event_sequence=intent.p08_terminal_event_sequence,
        p08_terminal_event_kind=intent.p08_terminal_event_kind,
        p08_source_reference_digest=intent.p08_source_reference_digest,
        rollback_target_event_id=intent.rollback_target_event_id,
        rollback_target_event_digest=intent.rollback_target_event_digest,
        proposal_id=intent.proposal_id,
        proposal_version=intent.proposal_version,
        proposal_manifest_head=intent.proposal_manifest_head,
        proposal_change_digest=intent.proposal_change_digest,
        proposal_expires_at_utc=intent.proposal_expires_at_utc,
        proposal_value=(
            intent.requested_value
            if intent.action in {"propose_manifest", "confirm_manifest"}
            else None
        ),
    )
    updated = _profile_current(
        manifest,
        state=target_state,
        scaled_value=target_value,
        last_sequence=event.sequence,
        last_event_id=event.event_id,
        last_event_digest=event.event_digest,
    )
    return (
        event,
        updated,
        ProfileStateReceipt(
            outcome="committed",
            replayed=False,
            mutated=True,
            event_id=event.event_id,
            event_digest=event.event_digest,
            projection_digest=updated.projection_digest,
            reason_category=intent.reason_category,
        ),
    )


def apply_profile_state_event(
    manifest: ProfileModuleManifest,
    current: ProfileCurrentValue,
    event: ProfileStateEvent,
) -> ProfileCurrentValue:
    if (
        event.module_id != manifest.module_id
        or event.field_id != manifest.field_id
        or event.manifest_digest != manifest.manifest_digest
        or event.sequence != current.last_sequence + 1
        or event.previous_event_digest != current.last_event_digest
        or event.prior_state != current.state
        or event.prior_value != current.scaled_value
    ):
        raise OwnerProfileLifecycleError("profile_state_event_chain_rejected")
    return _profile_current(
        manifest,
        state=event.current_state,
        scaled_value=event.current_value,
        last_sequence=event.sequence,
        last_event_id=event.event_id,
        last_event_digest=event.event_digest,
    )


def rebuild_profile_current(
    manifest: ProfileModuleManifest,
    events: tuple[ProfileStateEvent, ...],
) -> ProfileCurrentValue:
    current = initial_profile_current(manifest)
    seen: set[str] = set()
    for event in events:
        if event.event_id in seen:
            raise OwnerProfileLifecycleError("profile_state_event_duplicate")
        current = apply_profile_state_event(manifest, current, event)
        seen.add(event.event_id)
    return current
