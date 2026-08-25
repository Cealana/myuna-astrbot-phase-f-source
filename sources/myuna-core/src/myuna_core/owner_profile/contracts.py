from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Mapping


SCHEMA_VERSION = 1
DOCUMENT_TYPE = "owner_profile_baseline"
RECEIPT_TYPE = "owner_profile_approval_v1"
AUDIT_NAMESPACE = "owner_profile_read_v1"

PROFILE_CATEGORIES = (
    "self_introduction",
    "long_term_preference",
    "long_term_goal",
    "ongoing_project",
)

PROFILE_FILENAME = "profile.toml"
RECEIPT_FILENAME = "receipt.json"
MAX_PROFILE_BYTES = 65_536
MAX_RECEIPT_BYTES = 16_384
MAX_SECTIONS = 32
MAX_TITLE_CHARACTERS = 120
MAX_BODY_CHARACTERS = 4_000
MAX_TOTAL_BODY_CHARACTERS = 32_000
MAX_KEYWORDS = 12
MAX_KEYWORD_CHARACTERS = 64
MAX_QUERY_CHARACTERS = 256
MAX_RESULTS = 3
MAX_CONTEXT_CHARACTERS = 6_000

PROFILE_STATE_SCHEMA = "myuna.owner-profile-state.v2"
PROFILE_STATE_SCALE = 10_000
PROFILE_STATE_MINIMUM = -1_000_000
PROFILE_STATE_MAXIMUM = 1_500_000
PROFILE_ORDINARY_DELTA_LIMIT = 20_000
PROFILE_MODULE_IDS = (
    "relationship_state",
    "owner_facts",
    "owner_preferences",
    "interaction_adaptation",
    "shared_landmarks",
    "myuna_self_state",
    "owner_boundaries_and_consent",
    "module_registry",
)
PROFILE_STATE_ACTIONS = frozenset(
    {
        "initialize",
        "delta",
        "no_change",
        "freeze",
        "unfreeze",
        "correct",
        "rollback",
        "propose_manifest",
        "confirm_manifest",
        "cancel_manifest",
    }
)
PROFILE_STATE_ACTORS = frozenset({"owner", "myuna"})
PROFILE_STATE_REASONS = frozenset(
    {
        "owner_confirmed",
        "owner_correction",
        "owner_freeze",
        "owner_rollback",
        "delivered_turn",
        "episode_end",
        "no_change",
    }
)
PROFILE_CURRENT_STATES = frozenset({"uninitialized", "current", "frozen"})
_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_PROFILE_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class OwnerProfileError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _state_reject(code: str = "profile_state_contract_rejected") -> None:
    raise OwnerProfileError(code)


def _state_text(value: object, *, maximum: int = 128) -> str:
    if type(value) is not str or not value or len(value) > maximum or "\x00" in value:
        _state_reject()
    return value


def _state_id(value: object) -> str:
    if type(value) is not str or _PROFILE_ID.fullmatch(value) is None:
        _state_reject()
    return value


def _state_digest(value: object, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or _PROFILE_DIGEST.fullmatch(value) is None:
        _state_reject()
    return value


def _state_int(
    value: object,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    optional: bool = False,
) -> int | None:
    if optional and value is None:
        return None
    if type(value) is not int:
        _state_reject()
    if minimum is not None and value < minimum:
        _state_reject()
    if maximum is not None and value > maximum:
        _state_reject()
    return value


def _state_utc(value: object) -> str:
    if type(value) is not str or not value.endswith("Z"):
        _state_reject()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _state_reject()
    if parsed.tzinfo != timezone.utc or parsed.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    ) != value:
        _state_reject()
    return value


def profile_state_canonical_bytes(payload: Mapping[str, object]) -> bytes:
    if type(payload) is not dict or any(type(key) is not str for key in payload):
        _state_reject("profile_state_payload_rejected")
    try:
        return json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _state_reject("profile_state_payload_rejected")


def profile_state_digest(namespace: str, payload: Mapping[str, object]) -> str:
    _state_id(namespace)
    return sha256(namespace.encode("ascii") + b"\x00" + profile_state_canonical_bytes(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class ProfileModuleManifest:
    module_id: str
    field_id: str
    display_name: str
    value_kind: str
    authority: str
    sensitivity: str
    scale: int | None
    minimum: int | None
    maximum: int | None
    ordinary_delta_limit: int | None
    autonomous_enabled: bool
    schema: str = PROFILE_STATE_SCHEMA

    def __post_init__(self) -> None:
        if (
            type(self.schema) is not str
            or self.schema != PROFILE_STATE_SCHEMA
            or self.module_id not in PROFILE_MODULE_IDS
            or not self.field_id.startswith(self.module_id + ".")
            or self.value_kind not in {"fixed_point", "uninitialized"}
            or self.authority not in {"owner", "owner_and_bounded_myuna"}
            or self.sensitivity not in {"private", "owner_private"}
            or type(self.autonomous_enabled) is not bool
        ):
            _state_reject("profile_manifest_rejected")
        _state_id(self.module_id)
        _state_id(self.field_id)
        _state_text(self.display_name)
        if self.value_kind == "fixed_point":
            if (
                _state_int(self.scale, minimum=1) != PROFILE_STATE_SCALE
                or _state_int(self.minimum) != PROFILE_STATE_MINIMUM
                or _state_int(self.maximum) != PROFILE_STATE_MAXIMUM
                or _state_int(self.ordinary_delta_limit, minimum=1)
                != PROFILE_ORDINARY_DELTA_LIMIT
                or self.autonomous_enabled
                is not (self.authority == "owner_and_bounded_myuna")
            ):
                _state_reject("profile_manifest_rejected")
        elif any(
            value is not None
            for value in (
                self.scale,
                self.minimum,
                self.maximum,
                self.ordinary_delta_limit,
            )
        ) or self.autonomous_enabled:
            _state_reject("profile_manifest_rejected")

    def require_action_policy(
        self,
        *,
        actor: str,
        action: str,
        reason_category: str,
    ) -> None:
        if action == "no_change" and reason_category == "no_change":
            if actor not in PROFILE_STATE_ACTORS:
                _state_reject("profile_manifest_authority_rejected")
            return
        if actor == "myuna":
            if (
                self.authority != "owner_and_bounded_myuna"
                or not self.autonomous_enabled
                or self.sensitivity != "owner_private"
                or action != "delta"
                or reason_category not in {"delivered_turn", "episode_end"}
            ):
                _state_reject("profile_manifest_authority_rejected")
        elif actor == "owner":
            allowed_owner_reasons = {
                "initialize": {"owner_confirmed"},
                "delta": {"owner_confirmed"},
                "freeze": {"owner_freeze"},
                "unfreeze": {"owner_confirmed"},
                "correct": {"owner_correction"},
                "rollback": {"owner_rollback"},
                "propose_manifest": {"delivered_turn"},
                "confirm_manifest": {"owner_confirmed"},
                "cancel_manifest": {"owner_confirmed"},
            }
            if reason_category not in allowed_owner_reasons.get(action, set()):
                _state_reject("profile_manifest_authority_rejected")
        else:
            _state_reject("profile_manifest_authority_rejected")

    def payload(self) -> dict[str, object]:
        return {
            "authority": self.authority,
            "autonomous_enabled": self.autonomous_enabled,
            "display_name": self.display_name,
            "field_id": self.field_id,
            "maximum": self.maximum,
            "minimum": self.minimum,
            "module_id": self.module_id,
            "ordinary_delta_limit": self.ordinary_delta_limit,
            "scale": self.scale,
            "schema": self.schema,
            "sensitivity": self.sensitivity,
            "value_kind": self.value_kind,
        }

    @property
    def manifest_digest(self) -> str:
        return profile_state_digest("myuna-profile-module-manifest-v2", self.payload())


@dataclass(frozen=True, slots=True)
class ProfileStateIntent:
    intent_id: str
    action: str
    module_id: str
    field_id: str
    actor: str
    reason_category: str
    requested_value: int | None
    requested_delta: int | None
    expected_event_digest: str | None
    raw_source_digest: str
    p08_source_digest: str
    trusted_time_digest: str
    delivered_turn_id: str
    delivery_ack_digest: str
    delivered_source_reference_digest: str
    delivered_at_utc: str
    episode_revision_id: str | None = None
    p08_episode_id: str | None = None
    p08_interval_id: str | None = None
    p08_terminal_revision: int | None = None
    p08_terminal_revision_digest: str | None = None
    p08_terminal_event_sequence: int | None = None
    p08_terminal_event_kind: str | None = None
    p08_source_reference_digest: str | None = None
    rollback_target_event_id: str | None = None
    rollback_target_event_digest: str | None = None
    proposal_id: str | None = None
    proposal_version: int | None = None
    proposal_manifest_head: str | None = None
    proposal_change_digest: str | None = None
    proposal_expires_at_utc: str | None = None

    def __post_init__(self) -> None:
        _state_id(self.intent_id)
        _state_id(self.module_id)
        _state_id(self.field_id)
        if (
            self.action not in PROFILE_STATE_ACTIONS
            or self.actor not in PROFILE_STATE_ACTORS
            or self.reason_category not in PROFILE_STATE_REASONS
            or not self.field_id.startswith(self.module_id + ".")
        ):
            _state_reject("profile_intent_rejected")
        _state_int(self.requested_value, optional=True)
        _state_int(self.requested_delta, optional=True)
        _state_digest(self.expected_event_digest, optional=True)
        _state_digest(self.raw_source_digest)
        _state_digest(self.p08_source_digest)
        _state_digest(self.trusted_time_digest)
        _state_id(self.delivered_turn_id)
        _state_digest(self.delivery_ack_digest)
        _state_digest(self.delivered_source_reference_digest)
        _state_utc(self.delivered_at_utc)
        if self.episode_revision_id is not None:
            _state_id(self.episode_revision_id)
        if self.reason_category == "episode_end":
            if (
                self.action != "delta"
                or self.actor != "myuna"
                or self.episode_revision_id is None
                or self.p08_episode_id is None
                or self.p08_interval_id is None
                or self.p08_terminal_revision is None
                or self.p08_terminal_revision_digest is None
                or self.p08_terminal_event_sequence is None
                or type(self.p08_terminal_event_kind) is not str
                or self.p08_terminal_event_kind not in {"expire", "revoke"}
                or self.p08_source_reference_digest is None
            ):
                _state_reject("profile_intent_rejected")
            _state_digest(self.p08_episode_id)
            _state_id(self.p08_interval_id)
            _state_int(self.p08_terminal_revision, minimum=1)
            _state_digest(self.p08_terminal_revision_digest)
            _state_int(self.p08_terminal_event_sequence, minimum=1)
            _state_digest(self.p08_source_reference_digest)
        elif any(
            value is not None
            for value in (
                self.episode_revision_id,
                self.p08_episode_id,
                self.p08_interval_id,
                self.p08_terminal_revision,
                self.p08_terminal_revision_digest,
                self.p08_terminal_event_sequence,
                self.p08_terminal_event_kind,
                self.p08_source_reference_digest,
            )
        ):
            _state_reject("profile_intent_rejected")
        if self.action == "rollback":
            if (
                self.rollback_target_event_id is None
                or self.rollback_target_event_digest is None
            ):
                _state_reject("profile_intent_rejected")
            _state_id(self.rollback_target_event_id)
            _state_digest(self.rollback_target_event_digest)
        elif (
            self.rollback_target_event_id is not None
            or self.rollback_target_event_digest is not None
        ):
            _state_reject("profile_intent_rejected")
        if self.proposal_id is not None:
            _state_id(self.proposal_id)
        _state_int(self.proposal_version, minimum=1, optional=True)
        _state_digest(self.proposal_manifest_head, optional=True)
        _state_digest(self.proposal_change_digest, optional=True)
        if self.proposal_expires_at_utc is not None:
            _state_utc(self.proposal_expires_at_utc)
        proposal_fields = (
            self.proposal_id,
            self.proposal_version,
            self.proposal_manifest_head,
            self.proposal_change_digest,
            self.proposal_expires_at_utc,
        )
        if self.action in {
            "propose_manifest",
            "confirm_manifest",
            "cancel_manifest",
        }:
            if any(item is None for item in proposal_fields):
                _state_reject("profile_intent_rejected")
        elif any(item is not None for item in proposal_fields):
            _state_reject("profile_intent_rejected")
        if self.action in {
            "initialize",
            "correct",
            "rollback",
            "propose_manifest",
            "confirm_manifest",
        }:
            if self.requested_value is None or self.requested_delta is not None:
                _state_reject("profile_intent_rejected")
        elif self.action == "delta":
            if self.requested_value is not None or self.requested_delta is None:
                _state_reject("profile_intent_rejected")
        elif self.requested_value is not None or self.requested_delta is not None:
            _state_reject("profile_intent_rejected")

    def payload(self) -> dict[str, object]:
        return {
            "action": self.action,
            "actor": self.actor,
            "delivered_source_reference_digest": self.delivered_source_reference_digest,
            "delivered_at_utc": self.delivered_at_utc,
            "delivered_turn_id": self.delivered_turn_id,
            "delivery_ack_digest": self.delivery_ack_digest,
            "episode_revision_id": self.episode_revision_id,
            "expected_event_digest": self.expected_event_digest,
            "field_id": self.field_id,
            "intent_id": self.intent_id,
            "module_id": self.module_id,
            "p08_source_digest": self.p08_source_digest,
            "p08_episode_id": self.p08_episode_id,
            "p08_interval_id": self.p08_interval_id,
            "p08_source_reference_digest": self.p08_source_reference_digest,
            "p08_terminal_event_kind": self.p08_terminal_event_kind,
            "p08_terminal_event_sequence": self.p08_terminal_event_sequence,
            "p08_terminal_revision": self.p08_terminal_revision,
            "p08_terminal_revision_digest": self.p08_terminal_revision_digest,
            "proposal_change_digest": self.proposal_change_digest,
            "proposal_expires_at_utc": self.proposal_expires_at_utc,
            "proposal_id": self.proposal_id,
            "proposal_manifest_head": self.proposal_manifest_head,
            "proposal_version": self.proposal_version,
            "raw_source_digest": self.raw_source_digest,
            "reason_category": self.reason_category,
            "requested_delta": self.requested_delta,
            "requested_value": self.requested_value,
            "rollback_target_event_digest": self.rollback_target_event_digest,
            "rollback_target_event_id": self.rollback_target_event_id,
            "trusted_time_digest": self.trusted_time_digest,
        }

    @property
    def intent_digest(self) -> str:
        return profile_state_digest("myuna-profile-state-intent-v2", self.payload())


@dataclass(frozen=True, slots=True)
class ProfileStateEvent:
    sequence: int
    event_id: str
    previous_event_digest: str
    intent_digest: str
    manifest_digest: str
    module_id: str
    field_id: str
    action: str
    reason_category: str
    prior_state: str
    prior_value: int | None
    current_state: str
    current_value: int | None
    requested_delta: int | None
    applied_delta: int | None
    raw_source_digest: str
    p08_source_digest: str
    trusted_time_digest: str
    delivered_turn_id: str
    delivery_ack_digest: str
    delivered_source_reference_digest: str
    delivered_at_utc: str
    episode_revision_id: str | None
    p08_episode_id: str | None = None
    p08_interval_id: str | None = None
    p08_terminal_revision: int | None = None
    p08_terminal_revision_digest: str | None = None
    p08_terminal_event_sequence: int | None = None
    p08_terminal_event_kind: str | None = None
    p08_source_reference_digest: str | None = None
    rollback_target_event_id: str | None = None
    rollback_target_event_digest: str | None = None
    proposal_id: str | None = None
    proposal_version: int | None = None
    proposal_manifest_head: str | None = None
    proposal_change_digest: str | None = None
    proposal_expires_at_utc: str | None = None
    proposal_value: int | None = None

    def __post_init__(self) -> None:
        _state_int(self.sequence, minimum=1)
        _state_id(self.event_id)
        for digest in (
            self.previous_event_digest,
            self.intent_digest,
            self.manifest_digest,
            self.raw_source_digest,
            self.p08_source_digest,
            self.trusted_time_digest,
            self.delivery_ack_digest,
            self.delivered_source_reference_digest,
        ):
            _state_digest(digest)
        _state_id(self.module_id)
        _state_id(self.field_id)
        _state_id(self.delivered_turn_id)
        if (
            self.action not in PROFILE_STATE_ACTIONS
            or self.reason_category not in PROFILE_STATE_REASONS
            or self.prior_state not in PROFILE_CURRENT_STATES
            or self.current_state not in PROFILE_CURRENT_STATES
            or not self.field_id.startswith(self.module_id + ".")
        ):
            _state_reject("profile_event_rejected")
        _state_int(self.prior_value, optional=True)
        _state_int(self.current_value, optional=True)
        _state_int(self.requested_delta, optional=True)
        _state_int(self.applied_delta, optional=True)
        if self.action == "delta":
            if self.requested_delta is None or self.applied_delta is None:
                _state_reject("profile_event_rejected")
        elif self.requested_delta is not None or self.applied_delta is not None:
            _state_reject("profile_event_rejected")
        _state_utc(self.delivered_at_utc)
        if self.episode_revision_id is not None:
            _state_id(self.episode_revision_id)
        if self.reason_category == "episode_end":
            if (
                self.action != "delta"
                or self.episode_revision_id is None
                or self.p08_episode_id is None
                or self.p08_interval_id is None
                or self.p08_terminal_revision is None
                or self.p08_terminal_revision_digest is None
                or self.p08_terminal_event_sequence is None
                or type(self.p08_terminal_event_kind) is not str
                or self.p08_terminal_event_kind not in {"expire", "revoke"}
                or self.p08_source_reference_digest is None
            ):
                _state_reject("profile_event_rejected")
            _state_digest(self.p08_episode_id)
            _state_id(self.p08_interval_id)
            _state_int(self.p08_terminal_revision, minimum=1)
            _state_digest(self.p08_terminal_revision_digest)
            _state_int(self.p08_terminal_event_sequence, minimum=1)
            _state_digest(self.p08_source_reference_digest)
        elif any(
            value is not None
            for value in (
                self.episode_revision_id,
                self.p08_episode_id,
                self.p08_interval_id,
                self.p08_terminal_revision,
                self.p08_terminal_revision_digest,
                self.p08_terminal_event_sequence,
                self.p08_terminal_event_kind,
                self.p08_source_reference_digest,
            )
        ):
            _state_reject("profile_event_rejected")
        if self.action == "rollback":
            if (
                self.rollback_target_event_id is None
                or self.rollback_target_event_digest is None
            ):
                _state_reject("profile_event_rejected")
            _state_id(self.rollback_target_event_id)
            _state_digest(self.rollback_target_event_digest)
        elif (
            self.rollback_target_event_id is not None
            or self.rollback_target_event_digest is not None
        ):
            _state_reject("profile_event_rejected")
        if self.proposal_id is not None:
            _state_id(self.proposal_id)
        _state_int(self.proposal_version, minimum=1, optional=True)
        _state_digest(self.proposal_manifest_head, optional=True)
        _state_digest(self.proposal_change_digest, optional=True)
        if self.proposal_expires_at_utc is not None:
            _state_utc(self.proposal_expires_at_utc)
        _state_int(self.proposal_value, optional=True)
        proposal_fields = (
            self.proposal_id,
            self.proposal_version,
            self.proposal_manifest_head,
            self.proposal_change_digest,
            self.proposal_expires_at_utc,
        )
        if self.action in {
            "propose_manifest",
            "confirm_manifest",
            "cancel_manifest",
        }:
            if any(item is None for item in proposal_fields):
                _state_reject("profile_event_rejected")
            if self.action != "cancel_manifest" and self.proposal_value is None:
                _state_reject("profile_event_rejected")
        elif any(item is not None for item in proposal_fields):
            _state_reject("profile_event_rejected")
        elif self.proposal_value is not None:
            _state_reject("profile_event_rejected")
        if (self.prior_state == "uninitialized") != (self.prior_value is None):
            _state_reject("profile_event_rejected")
        if (self.current_state == "uninitialized") != (self.current_value is None):
            _state_reject("profile_event_rejected")

    def payload(self) -> dict[str, object]:
        return {
            "action": self.action,
            "applied_delta": self.applied_delta,
            "current_state": self.current_state,
            "current_value": self.current_value,
            "delivered_source_reference_digest": self.delivered_source_reference_digest,
            "delivered_at_utc": self.delivered_at_utc,
            "delivered_turn_id": self.delivered_turn_id,
            "delivery_ack_digest": self.delivery_ack_digest,
            "episode_revision_id": self.episode_revision_id,
            "event_id": self.event_id,
            "field_id": self.field_id,
            "intent_digest": self.intent_digest,
            "manifest_digest": self.manifest_digest,
            "module_id": self.module_id,
            "p08_source_digest": self.p08_source_digest,
            "p08_episode_id": self.p08_episode_id,
            "p08_interval_id": self.p08_interval_id,
            "p08_source_reference_digest": self.p08_source_reference_digest,
            "p08_terminal_event_kind": self.p08_terminal_event_kind,
            "p08_terminal_event_sequence": self.p08_terminal_event_sequence,
            "p08_terminal_revision": self.p08_terminal_revision,
            "p08_terminal_revision_digest": self.p08_terminal_revision_digest,
            "proposal_change_digest": self.proposal_change_digest,
            "proposal_expires_at_utc": self.proposal_expires_at_utc,
            "proposal_id": self.proposal_id,
            "proposal_manifest_head": self.proposal_manifest_head,
            "proposal_version": self.proposal_version,
            "proposal_value": self.proposal_value,
            "previous_event_digest": self.previous_event_digest,
            "prior_state": self.prior_state,
            "prior_value": self.prior_value,
            "raw_source_digest": self.raw_source_digest,
            "reason_category": self.reason_category,
            "requested_delta": self.requested_delta,
            "rollback_target_event_digest": self.rollback_target_event_digest,
            "rollback_target_event_id": self.rollback_target_event_id,
            "sequence": self.sequence,
            "trusted_time_digest": self.trusted_time_digest,
        }

    @property
    def event_digest(self) -> str:
        return profile_state_digest("myuna-profile-state-event-v2", self.payload())


@dataclass(frozen=True, slots=True)
class ProfileCurrentValue:
    module_id: str
    field_id: str
    state: str
    scaled_value: int | None
    last_sequence: int
    last_event_id: str | None
    last_event_digest: str
    manifest_digest: str
    projection_digest: str

    def __post_init__(self) -> None:
        _state_id(self.module_id)
        _state_id(self.field_id)
        if self.state not in PROFILE_CURRENT_STATES:
            _state_reject("profile_current_rejected")
        _state_int(self.scaled_value, optional=True)
        _state_int(self.last_sequence, minimum=0)
        if self.last_event_id is not None:
            _state_id(self.last_event_id)
        _state_digest(self.last_event_digest)
        _state_digest(self.manifest_digest)
        _state_digest(self.projection_digest)
        if (self.state == "uninitialized") != (self.scaled_value is None):
            _state_reject("profile_current_rejected")
        if (self.last_sequence == 0) != (self.last_event_id is None):
            _state_reject("profile_current_rejected")

    def payload(self, *, include_projection_digest: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "field_id": self.field_id,
            "last_event_digest": self.last_event_digest,
            "last_event_id": self.last_event_id,
            "last_sequence": self.last_sequence,
            "manifest_digest": self.manifest_digest,
            "module_id": self.module_id,
            "scaled_value": self.scaled_value,
            "state": self.state,
        }
        if include_projection_digest:
            result["projection_digest"] = self.projection_digest
        return result


@dataclass(frozen=True, slots=True)
class ProfileStateReceipt:
    outcome: str
    replayed: bool
    mutated: bool
    event_id: str | None
    event_digest: str
    projection_digest: str
    reason_category: str

    def __post_init__(self) -> None:
        if self.outcome not in {"committed", "no_change"}:
            _state_reject("profile_receipt_rejected")
        if type(self.replayed) is not bool or type(self.mutated) is not bool:
            _state_reject("profile_receipt_rejected")
        if self.event_id is not None:
            _state_id(self.event_id)
        _state_digest(self.event_digest)
        _state_digest(self.projection_digest)
        if self.reason_category not in PROFILE_STATE_REASONS:
            _state_reject("profile_receipt_rejected")
        if self.outcome == "no_change" and self.mutated:
            _state_reject("profile_receipt_rejected")


def profile_v2_manifests() -> tuple[ProfileModuleManifest, ...]:
    manifests = [
        ProfileModuleManifest(
            module_id="relationship_state",
            field_id="relationship_state.intimacy_headline",
            display_name="亲密度",
            value_kind="fixed_point",
            authority="owner_and_bounded_myuna",
            sensitivity="owner_private",
            scale=PROFILE_STATE_SCALE,
            minimum=PROFILE_STATE_MINIMUM,
            maximum=PROFILE_STATE_MAXIMUM,
            ordinary_delta_limit=PROFILE_ORDINARY_DELTA_LIMIT,
            autonomous_enabled=True,
        )
    ]
    for module_id in PROFILE_MODULE_IDS[1:]:
        manifests.append(
            ProfileModuleManifest(
                module_id=module_id,
                field_id=f"{module_id}.state",
                display_name=module_id.replace("_", " "),
                value_kind="uninitialized",
                authority="owner",
                sensitivity="owner_private",
                scale=None,
                minimum=None,
                maximum=None,
                ordinary_delta_limit=None,
                autonomous_enabled=False,
            )
        )
    return tuple(manifests)


@dataclass(frozen=True, slots=True)
class OwnerProfileSection:
    section_id: str
    topic_key: str
    category: str
    title: str
    body: str
    keywords: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OwnerProfile:
    profile_id: str
    profile_revision: int
    sections: tuple[OwnerProfileSection, ...]
    sha256: str
    byte_count: int

    @property
    def category_counts(self) -> tuple[tuple[str, int], ...]:
        return tuple(
            (category, sum(item.category == category for item in self.sections))
            for category in PROFILE_CATEGORIES
            if any(item.category == category for item in self.sections)
        )


@dataclass(frozen=True, slots=True)
class ProfileReceipt:
    profile_sha256: str
    profile_bytes: int
    profile_schema_version: int
    profile_id: str
    profile_revision: int
    section_count: int
    category_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class RetrievedProfileSection:
    rank: int
    category: str
    title: str
    body: str
    source_ref: str


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    state: str
    profile_revision: int
    profile_sha256: str
    query_characters: int
    sections: tuple[RetrievedProfileSection, ...]
    context: str | None

    @property
    def selected_categories(self) -> tuple[str, ...]:
        return tuple(item.category for item in self.sections)
