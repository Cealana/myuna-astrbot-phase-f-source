#!/usr/bin/env python3
"""Owner-day diary v2 selector and pure append-only revision semantics.

No provider client or background scheduler lives here.  The gateway may load
this contract only when the independent v2 selector is exact.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from hashlib import sha256
import json
import fcntl
from pathlib import Path
import re
import stat
from typing import Mapping

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.episodic_memory.contracts import (
    EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1,
    HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
    OWNER_DAY_DIARY_STYLE_V2_DIGEST,
    OWNER_DAY_PREVIEW_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
    EpisodicMemoryError,
    calendar_zone_selection_digest,
    require_digest,
    require_id,
    semantic_digest,
)
from myuna_core.episodic_memory.owner_day import (
    OWNER_DAY_ADDENDUM_PURPOSE,
    OWNER_DAY_DIARY_MODEL,
    OWNER_DAY_DIARY_MODEL_ROLE,
    OWNER_DAY_FINAL_PURPOSE,
    OWNER_DAY_POLICY_SCHEMA,
    OWNER_DAY_PREVIEW_PURPOSE,
    OWNER_DAY_SOFT_CLOSE_PURPOSE,
    OwnerDayPolicy,
    owner_day_interval,
    owner_day_label,
)
from myuna_core.episodic_memory.runtime_context import P15_HANDOFF_SCHEMA, TEMPORARY_PROMPT_OWNER
from telegram_runtime_config import CHANNEL_KIND, CORE_CLIENT_ID


MEMORY_SELECTOR_V4_SCHEMA = "myuna.p07-owner-private-memory-selector.v4"
MEMORY_SELECTOR_V4_PATH = Path(
    "/etc/myuna-telegram-gateway/p07-owner-private-memory-selector-v4.json"
)
DIARY_SELECTOR_V2_SCHEMA = "myuna.p07-owner-day-diary-selector.v2"
DIARY_SELECTOR_V2_PATH = Path(
    "/etc/myuna-telegram-gateway/p07-owner-day-diary-selector-v2.json"
)
OWNER_DAY_ACTION_SCHEMA = "myuna.p07-owner-day-diary-action.v2"
OWNER_DAY_STATE_SCHEMA = "myuna.p07-owner-day-diary-state.v2"
OWNER_DAY_EVENT_SCHEMA = "myuna.p07-owner-day-diary-event.v2"
OWNER_DAY_FINALIZATION_SCHEMA = "myuna.p07-owner-day-finalization-requirement.v2"
OWNER_DAY_EGRESS_PURPOSE = "p07-owner-day-diary-egress-v2"
OPEN_DAY_PREVIEW_EGRESS_PURPOSE = "p07-owner-day-as-of-preview-egress-v1"
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,159}$")
_BEDTIME = frozenset({"goodnight", "晚安", "晚安啦", "睡觉了"})
_PREVIEW = frozenset({"/diary today", "/diary preview", "看看你今天的日记"})
_MEMORY_V4_FIELDS = frozenset(
    {
        "archive_id",
        "calendar_zone",
        "calendar_zone_config_digest",
        "channel_kind",
        "client_id",
        "diary_coupled",
        "egress_policy_digest",
        "egress_policy_mode",
        "expected_gid",
        "expected_uid",
        "memory_release_set_id",
        "no_old_data_migration",
        "p15_handoff_schema",
        "p15_projection_active",
        "p08_lifecycle_start_watermark",
        "parent_epoch_id",
        "parent_epoch_revision",
        "parent_manifest_digest",
        "parent_release_set_id",
        "parent_selector_digest",
        "policy_overlay_id",
        "prompt_owner",
        "runtime_root",
        "schema",
        "status",
        "summary_used",
    }
)
_DIARY_V2_FIELDS = frozenset(
    {
        "archive_id",
        "channel_kind",
        "client_id",
        "closed_day_egress_purpose",
        "closed_day_egress_policy_digest",
        "expected_gid",
        "expected_uid",
        "memory_release_set_id",
        "model",
        "model_role",
        "no_old_data_migration",
        "open_day_preview_egress_purpose",
        "open_day_preview_egress_policy_digest",
        "owner_day_policy",
        "owner_day_policy_schema",
        "parent_release_set_id",
        "persona_digest",
        "policy_overlay_id",
        "proactive_out_of_band_message",
        "rollback_mode",
        "schema",
        "status",
        "style_contract_digest",
    }
)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii") + b"\n"


def _contains_private_key(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str):
                normalized = key.casefold()
                if normalized in {
                    "content",
                    "credential",
                    "diary",
                    "message",
                    "payload",
                    "profile",
                    "query",
                    "reply",
                    "secret",
                    "summary",
                    "text",
                } or normalized.endswith(
                    (
                        "_content",
                        "_credential",
                        "_message",
                        "_payload",
                        "_profile",
                        "_query",
                        "_reply",
                        "_secret",
                        "_summary",
                        "_text",
                    )
                ):
                    return True
            if _contains_private_key(nested):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_private_key(item) for item in value)
    return False


def _require_utc(value: datetime, code: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise EpisodicMemoryError(code)
    return value


@dataclass(frozen=True, slots=True)
class OwnerPrivateMemorySelectionV4:
    memory_release_set_id: str
    parent_release_set_id: str
    parent_manifest_digest: str
    parent_selector_digest: str
    parent_epoch_id: str
    parent_epoch_revision: int
    policy_overlay_id: str
    archive_id: str
    runtime_root: Path
    expected_uid: int
    expected_gid: int
    egress_policy_digest: str
    p08_lifecycle_start_watermark: int
    calendar_zone: str
    calendar_zone_config_digest: str
    status: str = "active"
    schema: str = MEMORY_SELECTOR_V4_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != MEMORY_SELECTOR_V4_SCHEMA or self.status != "active":
            raise EpisodicMemoryError("memory_v4_selector_state_rejected")
        for value, label in (
            (self.memory_release_set_id, "memory_release_set"),
            (self.parent_release_set_id, "memory_parent_release_set"),
            (self.parent_manifest_digest, "memory_parent_manifest"),
            (self.parent_selector_digest, "memory_parent_selector"),
            (self.policy_overlay_id, "memory_policy_overlay"),
            (self.egress_policy_digest, "memory_egress_policy"),
            (self.calendar_zone_config_digest, "memory_calendar_zone"),
        ):
            require_digest(value, label)
        require_id(self.parent_epoch_id, "memory_parent_epoch")
        require_id(self.archive_id, "memory_archive_id")
        if self.egress_policy_digest != HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST:
            raise EpisodicMemoryError("memory_egress_policy_drifted")
        if self.calendar_zone_config_digest != calendar_zone_selection_digest(
            self.calendar_zone
        ):
            raise EpisodicMemoryError("memory_calendar_zone_selection_drifted")
        if not self.runtime_root.is_absolute() or self.runtime_root.name != self.archive_id:
            raise EpisodicMemoryError("memory_runtime_root_rejected")
        for value in (
            self.parent_epoch_revision,
            self.expected_uid,
            self.expected_gid,
            self.p08_lifecycle_start_watermark,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EpisodicMemoryError("memory_v4_selector_identity_rejected")

    def payload(self) -> dict[str, object]:
        return {
            "archive_id": self.archive_id,
            "calendar_zone": self.calendar_zone,
            "calendar_zone_config_digest": self.calendar_zone_config_digest,
            "channel_kind": CHANNEL_KIND,
            "client_id": CORE_CLIENT_ID,
            "diary_coupled": False,
            "egress_policy_digest": self.egress_policy_digest,
            "egress_policy_mode": EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1,
            "expected_gid": self.expected_gid,
            "expected_uid": self.expected_uid,
            "memory_release_set_id": self.memory_release_set_id,
            "no_old_data_migration": True,
            "p15_handoff_schema": P15_HANDOFF_SCHEMA,
            "p15_projection_active": False,
            "p08_lifecycle_start_watermark": self.p08_lifecycle_start_watermark,
            "parent_epoch_id": self.parent_epoch_id,
            "parent_epoch_revision": self.parent_epoch_revision,
            "parent_manifest_digest": self.parent_manifest_digest,
            "parent_release_set_id": self.parent_release_set_id,
            "parent_selector_digest": self.parent_selector_digest,
            "policy_overlay_id": self.policy_overlay_id,
            "prompt_owner": TEMPORARY_PROMPT_OWNER,
            "runtime_root": self.runtime_root.as_posix(),
            "schema": self.schema,
            "status": self.status,
            "summary_used": False,
        }

    def audit_projection(self) -> dict[str, object]:
        return {
            "archive_id": self.archive_id,
            "calendar_zone": self.calendar_zone,
            "calendar_zone_config_digest": self.calendar_zone_config_digest,
            "diary_coupled": False,
            "egress_policy_digest": self.egress_policy_digest,
            "memory_release_set_id": self.memory_release_set_id,
            "p08_lifecycle_start_watermark": self.p08_lifecycle_start_watermark,
            "parent_epoch_id": self.parent_epoch_id,
            "parent_epoch_revision": self.parent_epoch_revision,
            "parent_release_set_id": self.parent_release_set_id,
            "policy_overlay_id": self.policy_overlay_id,
            "schema": self.schema,
            "status": self.status,
        }

    @classmethod
    def from_payload(cls, payload: object) -> "OwnerPrivateMemorySelectionV4":
        if not isinstance(payload, Mapping):
            raise EpisodicMemoryError("memory_v4_selector_fields_rejected")
        fixed = {
            "channel_kind": CHANNEL_KIND,
            "client_id": CORE_CLIENT_ID,
            "diary_coupled": False,
            "egress_policy_mode": EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1,
            "no_old_data_migration": True,
            "p15_handoff_schema": P15_HANDOFF_SCHEMA,
            "p15_projection_active": False,
            "prompt_owner": TEMPORARY_PROMPT_OWNER,
            "summary_used": False,
        }
        if set(payload) != _MEMORY_V4_FIELDS or any(
            payload.get(k) != v for k, v in fixed.items()
        ):
            raise EpisodicMemoryError("memory_v4_selector_fields_rejected")
        return cls(
            memory_release_set_id=payload["memory_release_set_id"],  # type: ignore[arg-type]
            parent_release_set_id=payload["parent_release_set_id"],  # type: ignore[arg-type]
            parent_manifest_digest=payload["parent_manifest_digest"],  # type: ignore[arg-type]
            parent_selector_digest=payload["parent_selector_digest"],  # type: ignore[arg-type]
            parent_epoch_id=payload["parent_epoch_id"],  # type: ignore[arg-type]
            parent_epoch_revision=payload["parent_epoch_revision"],  # type: ignore[arg-type]
            policy_overlay_id=payload["policy_overlay_id"],  # type: ignore[arg-type]
            archive_id=payload["archive_id"],  # type: ignore[arg-type]
            runtime_root=Path(payload["runtime_root"]),  # type: ignore[arg-type]
            expected_uid=payload["expected_uid"],  # type: ignore[arg-type]
            expected_gid=payload["expected_gid"],  # type: ignore[arg-type]
            egress_policy_digest=payload["egress_policy_digest"],  # type: ignore[arg-type]
            p08_lifecycle_start_watermark=payload["p08_lifecycle_start_watermark"],  # type: ignore[arg-type]
            calendar_zone=payload["calendar_zone"],  # type: ignore[arg-type]
            calendar_zone_config_digest=payload["calendar_zone_config_digest"],  # type: ignore[arg-type]
            status=payload["status"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class OwnerDayDiarySelectionV2:
    memory_release_set_id: str
    parent_release_set_id: str
    policy_overlay_id: str
    archive_id: str
    expected_uid: int
    expected_gid: int
    owner_day_policy: OwnerDayPolicy
    persona_digest: str
    closed_day_egress_policy_digest: str = REFLECTIVE_DIARY_EGRESS_V1_DIGEST
    open_day_preview_egress_policy_digest: str = OWNER_DAY_PREVIEW_EGRESS_V1_DIGEST
    style_contract_digest: str = OWNER_DAY_DIARY_STYLE_V2_DIGEST
    model: str = OWNER_DAY_DIARY_MODEL
    model_role: str = OWNER_DAY_DIARY_MODEL_ROLE
    status: str = "active"
    schema: str = DIARY_SELECTOR_V2_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != DIARY_SELECTOR_V2_SCHEMA or self.status != "active":
            raise EpisodicMemoryError("owner_day_diary_selector_state_rejected")
        for value, label in (
            (self.memory_release_set_id, "owner_day_memory_release"),
            (self.parent_release_set_id, "owner_day_parent_release"),
            (self.policy_overlay_id, "owner_day_policy_overlay"),
            (self.persona_digest, "owner_day_persona"),
            (self.closed_day_egress_policy_digest, "owner_day_closed_egress_policy"),
            (self.open_day_preview_egress_policy_digest, "owner_day_preview_egress_policy"),
            (self.style_contract_digest, "owner_day_style_contract"),
        ):
            require_digest(value, label)
        require_id(self.archive_id, "owner_day_archive")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.expected_uid, self.expected_gid)
        ):
            raise EpisodicMemoryError("owner_day_diary_selector_identity_rejected")
        if (
            self.closed_day_egress_policy_digest != REFLECTIVE_DIARY_EGRESS_V1_DIGEST
            or self.open_day_preview_egress_policy_digest
            != OWNER_DAY_PREVIEW_EGRESS_V1_DIGEST
            or self.style_contract_digest != OWNER_DAY_DIARY_STYLE_V2_DIGEST
            or self.model != OWNER_DAY_DIARY_MODEL
            or self.model_role != OWNER_DAY_DIARY_MODEL_ROLE
        ):
            raise EpisodicMemoryError("owner_day_diary_selector_contract_drifted")

    def validate_for(self, memory: OwnerPrivateMemorySelectionV4) -> None:
        if (
            self.memory_release_set_id != memory.memory_release_set_id
            or self.parent_release_set_id != memory.parent_release_set_id
            or self.policy_overlay_id != memory.policy_overlay_id
            or self.archive_id != memory.archive_id
            or self.expected_uid != memory.expected_uid
            or self.expected_gid != memory.expected_gid
            or self.owner_day_policy.calendar_zone != memory.calendar_zone
        ):
            raise EpisodicMemoryError("owner_day_diary_selector_binding_drifted")

    @property
    def selector_digest(self) -> str:
        return semantic_digest("myuna-p07-owner-day-diary-selector-v2", self.payload())

    def _egress_binding(self, egress_policy_digest: str) -> str:
        return semantic_digest(
            "myuna-p07-owner-day-diary-egress-binding-v2",
            {
                "archive_id": self.archive_id,
                "egress_policy_digest": egress_policy_digest,
                "memory_release_set_id": self.memory_release_set_id,
                "model": self.model,
                "model_role": self.model_role,
                "parent_release_set_id": self.parent_release_set_id,
                "persona_digest": self.persona_digest,
                "policy_digest": self.owner_day_policy.policy_digest,
                "policy_overlay_id": self.policy_overlay_id,
                "style_contract_digest": self.style_contract_digest,
            },
        )

    @property
    def closed_egress_binding_digest(self) -> str:
        return self._egress_binding(self.closed_day_egress_policy_digest)

    @property
    def preview_egress_binding_digest(self) -> str:
        return self._egress_binding(self.open_day_preview_egress_policy_digest)

    def payload(self) -> dict[str, object]:
        return {
            "archive_id": self.archive_id,
            "channel_kind": CHANNEL_KIND,
            "client_id": CORE_CLIENT_ID,
            "closed_day_egress_purpose": OWNER_DAY_EGRESS_PURPOSE,
            "closed_day_egress_policy_digest": self.closed_day_egress_policy_digest,
            "expected_gid": self.expected_gid,
            "expected_uid": self.expected_uid,
            "memory_release_set_id": self.memory_release_set_id,
            "model": self.model,
            "model_role": self.model_role,
            "no_old_data_migration": True,
            "open_day_preview_egress_purpose": OPEN_DAY_PREVIEW_EGRESS_PURPOSE,
            "open_day_preview_egress_policy_digest": (
                self.open_day_preview_egress_policy_digest
            ),
            "owner_day_policy": self.owner_day_policy.as_payload(),
            "owner_day_policy_schema": OWNER_DAY_POLICY_SCHEMA,
            "parent_release_set_id": self.parent_release_set_id,
            "persona_digest": self.persona_digest,
            "policy_overlay_id": self.policy_overlay_id,
            "proactive_out_of_band_message": False,
            "rollback_mode": "local-only-disabled",
            "schema": self.schema,
            "status": self.status,
            "style_contract_digest": self.style_contract_digest,
        }

    @classmethod
    def from_payload(cls, payload: object) -> "OwnerDayDiarySelectionV2":
        if not isinstance(payload, Mapping) or set(payload) != _DIARY_V2_FIELDS:
            raise EpisodicMemoryError("owner_day_diary_selector_fields_rejected")
        fixed = {
            "channel_kind": CHANNEL_KIND,
            "client_id": CORE_CLIENT_ID,
            "closed_day_egress_purpose": OWNER_DAY_EGRESS_PURPOSE,
            "no_old_data_migration": True,
            "open_day_preview_egress_purpose": OPEN_DAY_PREVIEW_EGRESS_PURPOSE,
            "owner_day_policy_schema": OWNER_DAY_POLICY_SCHEMA,
            "proactive_out_of_band_message": False,
            "rollback_mode": "local-only-disabled",
        }
        if any(payload.get(key) != value for key, value in fixed.items()):
            raise EpisodicMemoryError("owner_day_diary_selector_contract_drifted")
        return cls(
            memory_release_set_id=payload["memory_release_set_id"],  # type: ignore[arg-type]
            parent_release_set_id=payload["parent_release_set_id"],  # type: ignore[arg-type]
            policy_overlay_id=payload["policy_overlay_id"],  # type: ignore[arg-type]
            archive_id=payload["archive_id"],  # type: ignore[arg-type]
            expected_uid=payload["expected_uid"],  # type: ignore[arg-type]
            expected_gid=payload["expected_gid"],  # type: ignore[arg-type]
            owner_day_policy=OwnerDayPolicy.from_payload(payload["owner_day_policy"]),
            persona_digest=payload["persona_digest"],  # type: ignore[arg-type]
            closed_day_egress_policy_digest=payload[
                "closed_day_egress_policy_digest"
            ],  # type: ignore[arg-type]
            open_day_preview_egress_policy_digest=payload[
                "open_day_preview_egress_policy_digest"
            ],  # type: ignore[arg-type]
            style_contract_digest=payload["style_contract_digest"],  # type: ignore[arg-type]
            model=payload["model"],  # type: ignore[arg-type]
            model_role=payload["model_role"],  # type: ignore[arg-type]
            status=payload["status"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class OwnerDayAction:
    action: str
    request_id: str
    conversation_id: str
    turn_sequence: int
    turn_digest: str
    issued_at_utc: datetime
    schema: str = OWNER_DAY_ACTION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != OWNER_DAY_ACTION_SCHEMA or self.action not in {"bedtime", "preview"}:
            raise EpisodicMemoryError("owner_day_action_rejected")
        require_id(self.request_id, "owner_day_action_request")
        require_id(self.conversation_id, "owner_day_action_conversation")
        require_digest(self.turn_digest, "owner_day_action_turn")
        if isinstance(self.turn_sequence, bool) or self.turn_sequence < 1:
            raise EpisodicMemoryError("owner_day_action_turn_rejected")
        _require_utc(self.issued_at_utc, "owner_day_action_time_rejected")

    @property
    def action_digest(self) -> str:
        return semantic_digest(
            "myuna-p07-owner-day-action-v2",
            {
                "action": self.action,
                "conversation_id": self.conversation_id,
                "issued_at_utc": self.issued_at_utc.isoformat(timespec="microseconds"),
                "request_id": self.request_id,
                "schema": self.schema,
                "turn_digest": self.turn_digest,
                "turn_sequence": self.turn_sequence,
            },
        )


def admit_owner_day_action(
    context: AuthenticatedConversationContext,
    text: object,
    *,
    turn_sequence: int,
    turn_digest: str,
    issued_at_utc: datetime,
) -> OwnerDayAction | None:
    if (
        context.authority_level != "owner"
        or context.channel_kind != CHANNEL_KIND
        or context.conversation_kind != "private"
        or context.client_id != CORE_CLIENT_ID
    ):
        raise EpisodicMemoryError("owner_day_action_identity_rejected")
    if not isinstance(text, str):
        return None
    normalized = " ".join(text.strip().casefold().split())
    action = "bedtime" if normalized in _BEDTIME else "preview" if normalized in _PREVIEW else None
    if action is None:
        return None
    return OwnerDayAction(
        action=action,
        request_id=context.request_id,
        conversation_id=context.conversation_id,
        turn_sequence=turn_sequence,
        turn_digest=turn_digest,
        issued_at_utc=issued_at_utc,
    )


def admit_archived_owner_day_action(
    owner_text: object,
    *,
    conversation_id: str,
    turn_sequence: int,
    turn_digest: str,
    delivered_at_utc: datetime,
) -> OwnerDayAction | None:
    """Classify only an already delivered Owner-private complete turn."""

    require_id(conversation_id, "owner_day_action_conversation")
    if not isinstance(owner_text, str):
        return None
    normalized = " ".join(owner_text.strip().casefold().split())
    action = "bedtime" if normalized in _BEDTIME else "preview" if normalized in _PREVIEW else None
    if action is None:
        return None
    return OwnerDayAction(
        action=action,
        request_id=f"owner-day-action-{turn_sequence}",
        conversation_id=conversation_id,
        turn_sequence=turn_sequence,
        turn_digest=turn_digest,
        issued_at_utc=delivered_at_utc,
    )


@dataclass(frozen=True, slots=True)
class OwnerDayFinalizationRequirement:
    owner_day: date
    policy_digest: str
    interval_start_utc: datetime
    interval_end_utc: datetime
    source_start_sequence: int
    source_watermark: int
    terminal_turn_digest: str
    target_revision: int
    supersedes_revision: int | None
    schema: str = OWNER_DAY_FINALIZATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != OWNER_DAY_FINALIZATION_SCHEMA:
            raise EpisodicMemoryError("owner_day_finalization_schema_rejected")
        require_digest(self.policy_digest, "owner_day_finalization_policy")
        require_digest(self.terminal_turn_digest, "owner_day_finalization_turn")
        _require_utc(
            self.interval_start_utc, "owner_day_finalization_interval_rejected"
        )
        _require_utc(self.interval_end_utc, "owner_day_finalization_interval_rejected")
        if self.interval_end_utc <= self.interval_start_utc:
            raise EpisodicMemoryError("owner_day_finalization_interval_rejected")
        values = (
            self.source_start_sequence,
            self.source_watermark,
            self.target_revision,
        )
        if (
            any(
                isinstance(value, bool) or not isinstance(value, int) or value < 1
                for value in values
            )
            or self.source_start_sequence > self.source_watermark
        ):
            raise EpisodicMemoryError("owner_day_finalization_watermark_rejected")
        if self.target_revision == 1:
            if self.supersedes_revision is not None:
                raise EpisodicMemoryError("owner_day_finalization_revision_rejected")
        elif self.supersedes_revision != self.target_revision - 1:
            raise EpisodicMemoryError("owner_day_finalization_revision_rejected")

    def payload(self) -> dict[str, object]:
        return {
            "interval_end_utc": self.interval_end_utc.isoformat(timespec="microseconds"),
            "interval_start_utc": self.interval_start_utc.isoformat(
                timespec="microseconds"
            ),
            "owner_day": self.owner_day.isoformat(),
            "policy_digest": self.policy_digest,
            "schema": self.schema,
            "source_start_sequence": self.source_start_sequence,
            "source_watermark": self.source_watermark,
            "supersedes_revision": self.supersedes_revision,
            "target_revision": self.target_revision,
            "terminal_turn_digest": self.terminal_turn_digest,
        }

    @property
    def requirement_digest(self) -> str:
        return semantic_digest(
            "myuna-p07-owner-day-finalization-requirement-v2", self.payload()
        )

    @classmethod
    def from_payload(cls, payload: object) -> "OwnerDayFinalizationRequirement":
        required = {
            "interval_end_utc",
            "interval_start_utc",
            "owner_day",
            "policy_digest",
            "schema",
            "source_start_sequence",
            "source_watermark",
            "supersedes_revision",
            "target_revision",
            "terminal_turn_digest",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EpisodicMemoryError("owner_day_finalization_fields_rejected")
        try:
            parsed_day = date.fromisoformat(payload["owner_day"])  # type: ignore[arg-type]
            start = datetime.fromisoformat(payload["interval_start_utc"])  # type: ignore[arg-type]
            end = datetime.fromisoformat(payload["interval_end_utc"])  # type: ignore[arg-type]
        except (TypeError, ValueError):
            raise EpisodicMemoryError("owner_day_finalization_fields_rejected") from None
        return cls(
            owner_day=parsed_day,
            policy_digest=payload["policy_digest"],  # type: ignore[arg-type]
            interval_start_utc=start,
            interval_end_utc=end,
            source_start_sequence=payload["source_start_sequence"],  # type: ignore[arg-type]
            source_watermark=payload["source_watermark"],  # type: ignore[arg-type]
            terminal_turn_digest=payload["terminal_turn_digest"],  # type: ignore[arg-type]
            target_revision=payload["target_revision"],  # type: ignore[arg-type]
            supersedes_revision=payload["supersedes_revision"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class OwnerDayState:
    owner_day: date
    policy_digest: str
    owner_day_start_utc: datetime
    owner_day_end_utc: datetime
    first_complete_turn: int
    latest_complete_turn: int
    latest_turn_digest: str
    soft_close_generation: int = 0
    soft_close_watermark: int | None = None
    soft_close_deadline_utc: datetime | None = None
    preview_pending_watermark: int | None = None
    preview_request_digest: str | None = None
    latest_diary_revision: int = 0
    latest_diary_watermark: int = 0
    latest_preview_revision: int = 0
    final_watermark: int | None = None
    pending_finalizations: tuple[OwnerDayFinalizationRequirement, ...] = ()
    schema: str = OWNER_DAY_STATE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != OWNER_DAY_STATE_SCHEMA:
            raise EpisodicMemoryError("owner_day_state_schema_rejected")
        require_digest(self.policy_digest, "owner_day_state_policy")
        require_digest(self.latest_turn_digest, "owner_day_state_turn")
        _require_utc(self.owner_day_start_utc, "owner_day_state_interval_rejected")
        _require_utc(self.owner_day_end_utc, "owner_day_state_interval_rejected")
        integers = (
            self.first_complete_turn,
            self.latest_complete_turn,
            self.soft_close_generation,
            self.latest_diary_revision,
            self.latest_diary_watermark,
            self.latest_preview_revision,
        )
        if (
            any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in integers)
            or self.latest_complete_turn < 1
            or self.first_complete_turn < 1
            or self.first_complete_turn > self.latest_complete_turn
            or self.owner_day_end_utc <= self.owner_day_start_utc
            or self.latest_diary_watermark > self.latest_complete_turn
            or (
                self.final_watermark is not None
                and (
                    isinstance(self.final_watermark, bool)
                    or not isinstance(self.final_watermark, int)
                    or self.final_watermark < 1
                    or self.final_watermark > self.latest_complete_turn
                )
            )
        ):
            raise EpisodicMemoryError("owner_day_state_watermark_rejected")
        if (self.soft_close_watermark is None) != (self.soft_close_deadline_utc is None):
            raise EpisodicMemoryError("owner_day_soft_close_partial")
        if (self.preview_pending_watermark is None) != (self.preview_request_digest is None):
            raise EpisodicMemoryError("owner_day_preview_partial")
        if self.soft_close_deadline_utc is not None:
            _require_utc(self.soft_close_deadline_utc, "owner_day_soft_close_time_rejected")
        if self.soft_close_watermark is not None and (
            isinstance(self.soft_close_watermark, bool)
            or not isinstance(self.soft_close_watermark, int)
            or self.soft_close_watermark < 1
            or self.soft_close_watermark > self.latest_complete_turn
        ):
            raise EpisodicMemoryError("owner_day_soft_close_watermark_rejected")
        if self.preview_pending_watermark is not None and (
            isinstance(self.preview_pending_watermark, bool)
            or not isinstance(self.preview_pending_watermark, int)
            or self.preview_pending_watermark < 1
            or self.preview_pending_watermark > self.latest_complete_turn
        ):
            raise EpisodicMemoryError("owner_day_preview_watermark_rejected")
        if self.preview_request_digest is not None:
            require_digest(self.preview_request_digest, "owner_day_preview_request")
        if (self.latest_diary_revision == 0) != (self.latest_diary_watermark == 0):
            raise EpisodicMemoryError("owner_day_revision_state_partial")
        if self.final_watermark is not None and self.final_watermark > self.latest_diary_watermark:
            raise EpisodicMemoryError("owner_day_final_state_drifted")
        previous_day: date | None = None
        previous_watermark = 0
        for requirement in self.pending_finalizations:
            if (
                not isinstance(requirement, OwnerDayFinalizationRequirement)
                or requirement.owner_day >= self.owner_day
                or (previous_day is not None and requirement.owner_day <= previous_day)
                or requirement.source_start_sequence <= previous_watermark
            ):
                raise EpisodicMemoryError("owner_day_finalization_queue_rejected")
            previous_day = requirement.owner_day
            previous_watermark = requirement.source_watermark

    def audit_projection(self) -> dict[str, object]:
        return {
            "finalized": self.final_watermark is not None,
            "first_complete_turn": self.first_complete_turn,
            "latest_complete_turn": self.latest_complete_turn,
            "latest_diary_revision": self.latest_diary_revision,
            "latest_diary_watermark": self.latest_diary_watermark,
            "latest_preview_revision": self.latest_preview_revision,
            "owner_day": self.owner_day.isoformat(),
            "policy_digest": self.policy_digest,
            "pending_finalization_count": len(self.pending_finalizations),
            "pending_finalization_digest": semantic_digest(
                "myuna-p07-owner-day-finalization-queue-v2",
                [item.payload() for item in self.pending_finalizations],
            ),
            "soft_close_generation": self.soft_close_generation,
            "soft_close_pending": self.soft_close_watermark is not None,
            "preview_pending": self.preview_pending_watermark is not None,
        }

    def payload(self) -> dict[str, object]:
        return {
            "final_watermark": self.final_watermark,
            "first_complete_turn": self.first_complete_turn,
            "latest_complete_turn": self.latest_complete_turn,
            "latest_diary_revision": self.latest_diary_revision,
            "latest_diary_watermark": self.latest_diary_watermark,
            "latest_preview_revision": self.latest_preview_revision,
            "latest_turn_digest": self.latest_turn_digest,
            "owner_day": self.owner_day.isoformat(),
            "owner_day_end_utc": self.owner_day_end_utc.isoformat(
                timespec="microseconds"
            ),
            "owner_day_start_utc": self.owner_day_start_utc.isoformat(
                timespec="microseconds"
            ),
            "pending_finalizations": [
                item.payload() for item in self.pending_finalizations
            ],
            "policy_digest": self.policy_digest,
            "preview_pending_watermark": self.preview_pending_watermark,
            "preview_request_digest": self.preview_request_digest,
            "schema": self.schema,
            "soft_close_deadline_utc": (
                None
                if self.soft_close_deadline_utc is None
                else self.soft_close_deadline_utc.isoformat(timespec="microseconds")
            ),
            "soft_close_generation": self.soft_close_generation,
            "soft_close_watermark": self.soft_close_watermark,
        }

    @property
    def state_digest(self) -> str:
        return semantic_digest("myuna-p07-owner-day-state-v2", self.payload())

    @classmethod
    def from_payload(cls, payload: object) -> "OwnerDayState":
        required = {
            "final_watermark",
            "first_complete_turn",
            "latest_complete_turn",
            "latest_diary_revision",
            "latest_diary_watermark",
            "latest_preview_revision",
            "latest_turn_digest",
            "owner_day",
            "owner_day_end_utc",
            "owner_day_start_utc",
            "pending_finalizations",
            "policy_digest",
            "preview_pending_watermark",
            "preview_request_digest",
            "schema",
            "soft_close_deadline_utc",
            "soft_close_generation",
            "soft_close_watermark",
        }
        if (
            not isinstance(payload, Mapping)
            or set(payload) != required
            or not isinstance(payload["pending_finalizations"], list)
        ):
            raise EpisodicMemoryError("owner_day_state_fields_rejected")
        try:
            parsed_day = date.fromisoformat(payload["owner_day"])  # type: ignore[arg-type]
            interval_start = datetime.fromisoformat(payload["owner_day_start_utc"])  # type: ignore[arg-type]
            interval_end = datetime.fromisoformat(payload["owner_day_end_utc"])  # type: ignore[arg-type]
            deadline = (
                None
                if payload["soft_close_deadline_utc"] is None
                else datetime.fromisoformat(payload["soft_close_deadline_utc"])  # type: ignore[arg-type]
            )
            pending = tuple(
                OwnerDayFinalizationRequirement.from_payload(item)
                for item in payload["pending_finalizations"]
            )
        except (TypeError, ValueError, EpisodicMemoryError):
            raise EpisodicMemoryError("owner_day_state_fields_rejected") from None
        return cls(
            owner_day=parsed_day,
            policy_digest=payload["policy_digest"],  # type: ignore[arg-type]
            owner_day_start_utc=interval_start,
            owner_day_end_utc=interval_end,
            first_complete_turn=payload["first_complete_turn"],  # type: ignore[arg-type]
            latest_complete_turn=payload["latest_complete_turn"],  # type: ignore[arg-type]
            latest_turn_digest=payload["latest_turn_digest"],  # type: ignore[arg-type]
            soft_close_generation=payload["soft_close_generation"],  # type: ignore[arg-type]
            soft_close_watermark=payload["soft_close_watermark"],  # type: ignore[arg-type]
            soft_close_deadline_utc=deadline,
            preview_pending_watermark=payload["preview_pending_watermark"],  # type: ignore[arg-type]
            preview_request_digest=payload["preview_request_digest"],  # type: ignore[arg-type]
            latest_diary_revision=payload["latest_diary_revision"],  # type: ignore[arg-type]
            latest_diary_watermark=payload["latest_diary_watermark"],  # type: ignore[arg-type]
            latest_preview_revision=payload["latest_preview_revision"],  # type: ignore[arg-type]
            final_watermark=payload["final_watermark"],  # type: ignore[arg-type]
            pending_finalizations=pending,
            schema=payload["schema"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class OwnerDayAdvance:
    current: OwnerDayState
    closed_owner_day: date | None
    closed_owner_day_watermark: int | None


def advance_owner_day_state(
    prior: OwnerDayState | None,
    *,
    owner_day: date,
    policy: OwnerDayPolicy,
    turn_sequence: int,
    turn_digest: str,
) -> OwnerDayAdvance:
    if prior is None or owner_day > prior.owner_day:
        if prior is not None and turn_sequence != prior.latest_complete_turn + 1:
            raise EpisodicMemoryError("owner_day_complete_turn_replayed_or_gapped")
        interval = owner_day_interval(owner_day, policy)
        pending = () if prior is None else prior.pending_finalizations + (
            OwnerDayFinalizationRequirement(
                owner_day=prior.owner_day,
                policy_digest=prior.policy_digest,
                interval_start_utc=prior.owner_day_start_utc,
                interval_end_utc=prior.owner_day_end_utc,
                source_start_sequence=prior.first_complete_turn,
                source_watermark=prior.latest_complete_turn,
                terminal_turn_digest=prior.latest_turn_digest,
                target_revision=prior.latest_diary_revision + 1,
                supersedes_revision=(
                    None
                    if prior.latest_diary_revision == 0
                    else prior.latest_diary_revision
                ),
            ),
        )
        current = OwnerDayState(
            owner_day=owner_day,
            policy_digest=policy.policy_digest,
            owner_day_start_utc=interval.start_utc,
            owner_day_end_utc=interval.end_utc,
            first_complete_turn=turn_sequence,
            latest_complete_turn=turn_sequence,
            latest_turn_digest=turn_digest,
            pending_finalizations=pending,
        )
        return OwnerDayAdvance(
            current=current,
            closed_owner_day=None if prior is None else prior.owner_day,
            closed_owner_day_watermark=(
                None if prior is None else prior.latest_complete_turn
            ),
        )
    if owner_day < prior.owner_day:
        raise EpisodicMemoryError("owner_day_time_regressed")
    return OwnerDayAdvance(
        current=after_complete_turn(
            prior,
            owner_day=owner_day,
            policy=policy,
            turn_sequence=turn_sequence,
            turn_digest=turn_digest,
        ),
        closed_owner_day=None,
        closed_owner_day_watermark=None,
    )


def after_complete_turn(
    prior: OwnerDayState | None,
    *,
    owner_day: date,
    policy: OwnerDayPolicy,
    turn_sequence: int,
    turn_digest: str,
) -> OwnerDayState:
    require_digest(turn_digest, "owner_day_complete_turn")
    if prior is None:
        interval = owner_day_interval(owner_day, policy)
        return OwnerDayState(
            owner_day=owner_day,
            policy_digest=policy.policy_digest,
            owner_day_start_utc=interval.start_utc,
            owner_day_end_utc=interval.end_utc,
            first_complete_turn=turn_sequence,
            latest_complete_turn=turn_sequence,
            latest_turn_digest=turn_digest,
        )
    if prior.policy_digest != policy.policy_digest or owner_day != prior.owner_day:
        raise EpisodicMemoryError("owner_day_state_identity_drifted")
    if turn_sequence == prior.latest_complete_turn and turn_digest == prior.latest_turn_digest:
        return prior
    if turn_sequence != prior.latest_complete_turn + 1:
        raise EpisodicMemoryError("owner_day_complete_turn_replayed_or_gapped")
    return OwnerDayState(
        owner_day=prior.owner_day,
        policy_digest=prior.policy_digest,
        owner_day_start_utc=prior.owner_day_start_utc,
        owner_day_end_utc=prior.owner_day_end_utc,
        first_complete_turn=prior.first_complete_turn,
        latest_complete_turn=turn_sequence,
        latest_turn_digest=turn_digest,
        soft_close_generation=prior.soft_close_generation,
        latest_diary_revision=prior.latest_diary_revision,
        latest_diary_watermark=prior.latest_diary_watermark,
        latest_preview_revision=prior.latest_preview_revision,
        final_watermark=prior.final_watermark,
        pending_finalizations=prior.pending_finalizations,
    )


def apply_bedtime_action(
    state: OwnerDayState,
    action: OwnerDayAction,
    policy: OwnerDayPolicy,
) -> OwnerDayState:
    if action.action != "bedtime" or action.turn_sequence != state.latest_complete_turn or action.turn_digest != state.latest_turn_digest:
        raise EpisodicMemoryError("owner_day_bedtime_binding_rejected")
    if state.policy_digest != policy.policy_digest:
        raise EpisodicMemoryError("owner_day_state_identity_drifted")
    if owner_day_label(action.issued_at_utc, policy) != state.owner_day:
        raise EpisodicMemoryError("owner_day_bedtime_time_rejected")
    deadline = min(
        action.issued_at_utc + timedelta(seconds=policy.soft_close_grace_seconds),
        owner_day_interval(state.owner_day, policy).end_utc,
    )
    return OwnerDayState(
        owner_day=state.owner_day,
        policy_digest=state.policy_digest,
        owner_day_start_utc=state.owner_day_start_utc,
        owner_day_end_utc=state.owner_day_end_utc,
        first_complete_turn=state.first_complete_turn,
        latest_complete_turn=state.latest_complete_turn,
        latest_turn_digest=state.latest_turn_digest,
        soft_close_generation=state.soft_close_generation + 1,
        soft_close_watermark=state.latest_complete_turn,
        soft_close_deadline_utc=deadline,
        preview_pending_watermark=state.preview_pending_watermark,
        preview_request_digest=state.preview_request_digest,
        latest_diary_revision=state.latest_diary_revision,
        latest_diary_watermark=state.latest_diary_watermark,
        latest_preview_revision=state.latest_preview_revision,
        final_watermark=state.final_watermark,
        pending_finalizations=state.pending_finalizations,
    )


def soft_close_ready(state: OwnerDayState, now_utc: datetime) -> bool:
    _require_utc(now_utc, "owner_day_timer_time_rejected")
    return (
        state.soft_close_watermark == state.latest_complete_turn
        and state.soft_close_deadline_utc is not None
        and now_utc >= state.soft_close_deadline_utc
    )


def request_preview(state: OwnerDayState, action: OwnerDayAction) -> OwnerDayState:
    if action.action != "preview" or action.turn_sequence != state.latest_complete_turn or action.turn_digest != state.latest_turn_digest:
        raise EpisodicMemoryError("owner_day_preview_binding_rejected")
    return OwnerDayState(
        owner_day=state.owner_day,
        policy_digest=state.policy_digest,
        owner_day_start_utc=state.owner_day_start_utc,
        owner_day_end_utc=state.owner_day_end_utc,
        first_complete_turn=state.first_complete_turn,
        latest_complete_turn=state.latest_complete_turn,
        latest_turn_digest=state.latest_turn_digest,
        soft_close_generation=state.soft_close_generation,
        soft_close_watermark=state.soft_close_watermark,
        soft_close_deadline_utc=state.soft_close_deadline_utc,
        preview_pending_watermark=state.latest_complete_turn,
        preview_request_digest=action.action_digest,
        latest_diary_revision=state.latest_diary_revision,
        latest_diary_watermark=state.latest_diary_watermark,
        latest_preview_revision=state.latest_preview_revision,
        final_watermark=state.final_watermark,
        pending_finalizations=state.pending_finalizations,
    )


def record_diary_revision(
    state: OwnerDayState,
    *,
    purpose: str,
    source_watermark: int,
    target_revision: int,
    supersedes_revision: int | None,
) -> OwnerDayState:
    if source_watermark < 1 or source_watermark > state.latest_complete_turn:
        raise EpisodicMemoryError("owner_day_revision_watermark_rejected")
    if source_watermark != state.latest_complete_turn:
        raise EpisodicMemoryError("owner_day_revision_coverage_incomplete")
    if purpose == OWNER_DAY_PREVIEW_PURPOSE:
        if (
            target_revision != state.latest_preview_revision + 1
            or supersedes_revision is not None
            or state.preview_pending_watermark != source_watermark
            or state.preview_request_digest is None
        ):
            raise EpisodicMemoryError("owner_day_preview_revision_rejected")
        return OwnerDayState(
            owner_day=state.owner_day,
            policy_digest=state.policy_digest,
            owner_day_start_utc=state.owner_day_start_utc,
            owner_day_end_utc=state.owner_day_end_utc,
            first_complete_turn=state.first_complete_turn,
            latest_complete_turn=state.latest_complete_turn,
            latest_turn_digest=state.latest_turn_digest,
            soft_close_generation=state.soft_close_generation,
            soft_close_watermark=state.soft_close_watermark,
            soft_close_deadline_utc=state.soft_close_deadline_utc,
            preview_pending_watermark=None,
            preview_request_digest=None,
            latest_diary_revision=state.latest_diary_revision,
            latest_diary_watermark=state.latest_diary_watermark,
            latest_preview_revision=target_revision,
            final_watermark=state.final_watermark,
            pending_finalizations=state.pending_finalizations,
        )
    if purpose not in {
        OWNER_DAY_SOFT_CLOSE_PURPOSE,
        OWNER_DAY_ADDENDUM_PURPOSE,
        OWNER_DAY_FINAL_PURPOSE,
    }:
        raise EpisodicMemoryError("owner_day_revision_purpose_rejected")
    if target_revision != state.latest_diary_revision + 1 or (
        target_revision == 1 and supersedes_revision is not None
    ) or (
        target_revision > 1 and supersedes_revision != target_revision - 1
    ):
        raise EpisodicMemoryError("owner_day_revision_sequence_rejected")
    return OwnerDayState(
        owner_day=state.owner_day,
        policy_digest=state.policy_digest,
        owner_day_start_utc=state.owner_day_start_utc,
        owner_day_end_utc=state.owner_day_end_utc,
        first_complete_turn=state.first_complete_turn,
        latest_complete_turn=state.latest_complete_turn,
        latest_turn_digest=state.latest_turn_digest,
        soft_close_generation=state.soft_close_generation,
        preview_pending_watermark=state.preview_pending_watermark,
        preview_request_digest=state.preview_request_digest,
        latest_diary_revision=target_revision,
        latest_diary_watermark=source_watermark,
        latest_preview_revision=state.latest_preview_revision,
        final_watermark=(
            source_watermark
            if purpose == OWNER_DAY_FINAL_PURPOSE
            else state.final_watermark
        ),
        pending_finalizations=state.pending_finalizations,
    )


def load_protected_selector(path: Path, *, uid: int, gid: int) -> Mapping[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    status = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(status.st_mode) or status.st_uid != uid or status.st_gid != gid or stat.S_IMODE(status.st_mode) != 0o640:
        raise EpisodicMemoryError("owner_day_selector_permissions_rejected")
    try:
        payload = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EpisodicMemoryError("owner_day_selector_unavailable") from exc
    if not isinstance(payload, Mapping):
        raise EpisodicMemoryError("owner_day_selector_fields_rejected")
    return payload


def state_for_delivered_turn(
    prior: OwnerDayState | None,
    *,
    policy: OwnerDayPolicy,
    delivered_at_utc: datetime,
    turn_sequence: int,
    turn_digest: str,
) -> OwnerDayState:
    return advance_owner_day_state(
        prior,
        owner_day=owner_day_label(delivered_at_utc, policy),
        policy=policy,
        turn_sequence=turn_sequence,
        turn_digest=turn_digest,
    ).current
