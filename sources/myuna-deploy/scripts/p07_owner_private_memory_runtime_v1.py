"""P07 Owner-private lossless archive runtime, inactive unless its selector exists."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import stat
from typing import Mapping, Sequence

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.active_temporal_context.protocol import ActiveSnapshotReceipt
from myuna_core.external_context.contracts import (
    EgressSafetySignals,
    VisualEvidence,
    current_message_digest,
)
from myuna_core.episodic_memory.contracts import (
    CONTROL_ISOLATED_CATEGORY,
    CONTEXT_POLICY_RAW_FIRST,
    SUPPORTED_CALENDAR_ZONES,
    EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1,
    HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_EGRESS_V1_DIGEST,
    REFLECTIVE_DIARY_STYLE_V1_DIGEST,
    ArchivedContent,
    CompleteTurn,
    EpisodicMemoryError,
    LifecycleRecord,
    PrefixCapsule,
    RecallEgressPolicy,
    calendar_zone_selection_digest,
    require_digest,
    require_id,
    reflective_diary_egress_binding_digest,
    semantic_digest,
)
from myuna_core.episodic_memory.diary_generation import (
    DIARY_MODEL,
    DIARY_MODEL_ROLE,
)
from myuna_core.episodic_memory.calendar import resolve_relative_date
from myuna_core.episodic_memory.delivery import (
    DeliveryJournal,
    DeliveryPreparation,
    DeliveryResolution,
    FactualDeliveryEpisodeV1,
    response_digest,
)
from myuna_core.episodic_memory.diary import ReflectiveDiaryStore
from myuna_core.episodic_memory.index import (
    EpisodicIndexSnapshot,
    derive_snapshot,
    read_snapshot,
    recover_or_write_snapshot,
    verify_snapshot,
    write_snapshot,
)
from myuna_core.episodic_memory.owner_day import OwnerDayPolicy
from myuna_core.episodic_memory.retrieval import (
    EpisodicQuery,
    content_free_retrieval_failure,
    fetch_relevant_raw,
    search_relevant_sources,
)
from myuna_core.episodic_memory.runtime_context import (
    EpisodicRuntimeContext,
    EpisodicTurnProvenance,
    MAX_TEMPORAL_CONTEXT_CHARACTERS,
    P15_HANDOFF_SCHEMA,
    TEMPORARY_PROMPT_OWNER,
)
from myuna_core.episodic_memory.store import LosslessArchiveStore
from myuna_core.episodic_memory.trusted_time import (
    bind_prompt_time_sample,
    finalize_prompt_time_binding,
    unresolved_turn_time,
)
from myuna_core.episodic_memory.temporal_bridge import (
    TemporalIntervalIndexSnapshot,
    TemporalIntervalIndexStore,
    advance_temporal_interval_index,
    rebind_temporal_interval_archive_head,
)
from myuna_core.episodic_memory.temporal_validity import (
    content_free_temporal_projection,
    project_resident_temporal_items,
)
from myuna_core.active_temporal_context.time import TrustedTimeSample
from myuna_core.memory_aware_turn_protocol import ServerIntentProposal
from myuna_core.owner_profile.contracts import (
    OwnerProfileError,
    ProfileStateIntent,
    profile_state_digest,
    profile_v2_manifests,
)
from myuna_core.owner_profile.projection import render_profile_v2_current_context
from myuna_core.owner_profile.write_intent import parse_profile_v2_structural_request
from telegram_runtime_config import CHANNEL_KIND, CORE_CLIENT_ID
from p07_owner_day_diary_v2 import (
    DIARY_SELECTOR_V2_PATH,
    MEMORY_SELECTOR_V4_PATH,
    OwnerDayDiarySelectionV2,
    OwnerPrivateMemorySelectionV4,
    load_protected_selector,
)


SELECTOR_SCHEMA = "myuna.p07-owner-private-memory-selector.v3"
SELECTOR_PATH = Path("/etc/myuna-telegram-gateway/p07-owner-private-memory-selector-v3.json")
DIARY_EGRESS_SELECTOR_SCHEMA = "myuna.p07-reflective-diary-egress-selector.v1"
DIARY_EGRESS_SELECTOR_PATH = Path(
    "/etc/myuna-telegram-gateway/p07-reflective-diary-egress-selector-v1.json"
)
RUNTIME_ROOT = Path("/var/lib/myuna-telegram-gateway/owner-private-memory-v1")
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,159}$")
_RELATIVE_DATE = re.compile(
    r"(?i)(?<![A-Za-z])(today|yesterday|tomorrow)(?![A-Za-z])|今天|昨天|明天"
)
_CONTROL_KINDS = frozenset({"benchmark", "check", "diary", "profile_v2", "temporal"})
MAX_TEMPORAL_CONTEXT_SERIALIZED_BYTES = 48_128
MAX_TEMPORAL_CONTEXT_TOKENS = 48_128


def _resident_token_upper_bound(fragments: tuple[str, ...]) -> int:
    return sum(len(item.encode("utf-8")) for item in fragments) + 32 * len(fragments)


def _strict_digest(value: object, code: str) -> str:
    try:
        return require_digest(value, code)  # type: ignore[arg-type]
    except EpisodicMemoryError:
        raise EpisodicMemoryError(code) from None


@dataclass(frozen=True, slots=True)
class OwnerPrivateMemorySelection:
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
    diary_egress_policy_digest: str
    diary_style_contract_digest: str
    diary_persona_digest: str
    diary_model: str
    diary_model_role: str
    p08_lifecycle_start_watermark: int
    calendar_zone: str
    calendar_zone_config_digest: str
    status: str = "active"
    schema: str = SELECTOR_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SELECTOR_SCHEMA or self.status != "active":
            raise EpisodicMemoryError("memory_selector_state_rejected")
        for value, label in (
            (self.memory_release_set_id, "memory_release_set"),
            (self.parent_release_set_id, "memory_parent_release_set"),
            (self.parent_manifest_digest, "memory_parent_manifest"),
            (self.parent_selector_digest, "memory_parent_selector"),
            (self.policy_overlay_id, "memory_policy_overlay"),
            (self.egress_policy_digest, "memory_egress_policy"),
            (self.diary_egress_policy_digest, "memory_diary_egress_policy"),
            (self.diary_style_contract_digest, "memory_diary_style_contract"),
            (self.diary_persona_digest, "memory_diary_persona"),
        ):
            require_digest(value, label)
        require_id(self.parent_epoch_id, "memory_parent_epoch")
        require_id(self.archive_id, "memory_archive_id")
        if self.egress_policy_digest != HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST:
            raise EpisodicMemoryError("memory_egress_policy_drifted")
        if (
            self.diary_egress_policy_digest != REFLECTIVE_DIARY_EGRESS_V1_DIGEST
            or self.diary_style_contract_digest != REFLECTIVE_DIARY_STYLE_V1_DIGEST
            or self.diary_model != DIARY_MODEL
            or self.diary_model_role != DIARY_MODEL_ROLE
        ):
            raise EpisodicMemoryError("memory_diary_contract_drifted")
        if self.calendar_zone not in SUPPORTED_CALENDAR_ZONES:
            raise EpisodicMemoryError("calendar_zone_selection_unsupported")
        if self.calendar_zone_config_digest != calendar_zone_selection_digest(
            self.calendar_zone
        ):
            raise EpisodicMemoryError("calendar_zone_selection_drifted")
        if (
            isinstance(self.parent_epoch_revision, bool)
            or not isinstance(self.parent_epoch_revision, int)
            or self.parent_epoch_revision < 0
            or isinstance(self.expected_uid, bool)
            or not isinstance(self.expected_uid, int)
            or self.expected_uid < 0
            or isinstance(self.expected_gid, bool)
            or not isinstance(self.expected_gid, int)
            or self.expected_gid < 0
            or isinstance(self.p08_lifecycle_start_watermark, bool)
            or not isinstance(self.p08_lifecycle_start_watermark, int)
            or self.p08_lifecycle_start_watermark < 0
        ):
            raise EpisodicMemoryError("memory_selector_identity_rejected")
        expected_root = RUNTIME_ROOT / self.archive_id
        if self.runtime_root != expected_root or not self.runtime_root.is_absolute():
            raise EpisodicMemoryError("memory_runtime_root_rejected")

    @classmethod
    def from_payload(cls, payload: object) -> OwnerPrivateMemorySelection:
        required = {
            "archive_id",
            "calendar_zone",
            "calendar_zone_config_digest",
            "channel_kind",
            "client_id",
            "diary_egress_policy_digest",
            "diary_model",
            "diary_model_role",
            "diary_persona_digest",
            "diary_rollback_mode",
            "diary_style_contract_digest",
            "egress_policy_digest",
            "egress_policy_mode",
            "expected_gid",
            "expected_uid",
            "memory_release_set_id",
            "no_old_data_migration",
            "p15_handoff_schema",
            "p15_projection_active",
            "parent_epoch_id",
            "parent_epoch_revision",
            "parent_manifest_digest",
            "parent_release_set_id",
            "parent_selector_digest",
            "p08_lifecycle_start_watermark",
            "policy_overlay_id",
            "prompt_owner",
            "runtime_root",
            "schema",
            "status",
            "summary_used",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EpisodicMemoryError("memory_selector_fields_rejected")
        if (
            payload["channel_kind"] != CHANNEL_KIND
            or payload["client_id"] != CORE_CLIENT_ID
            or payload["egress_policy_mode"] != EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1
            or payload["diary_rollback_mode"] != "local-only"
            or payload["no_old_data_migration"] is not True
            or payload["summary_used"] is not False
            or payload["prompt_owner"] != TEMPORARY_PROMPT_OWNER
            or payload["p15_projection_active"] is not False
            or payload["p15_handoff_schema"] != P15_HANDOFF_SCHEMA
            or not isinstance(payload["runtime_root"], str)
        ):
            raise EpisodicMemoryError("memory_selector_contract_rejected")
        return cls(
            memory_release_set_id=payload["memory_release_set_id"],  # type: ignore[arg-type]
            parent_release_set_id=payload["parent_release_set_id"],  # type: ignore[arg-type]
            parent_manifest_digest=payload["parent_manifest_digest"],  # type: ignore[arg-type]
            parent_selector_digest=payload["parent_selector_digest"],  # type: ignore[arg-type]
            parent_epoch_id=payload["parent_epoch_id"],  # type: ignore[arg-type]
            parent_epoch_revision=payload["parent_epoch_revision"],  # type: ignore[arg-type]
            policy_overlay_id=payload["policy_overlay_id"],  # type: ignore[arg-type]
            archive_id=payload["archive_id"],  # type: ignore[arg-type]
            runtime_root=Path(payload["runtime_root"]),
            expected_uid=payload["expected_uid"],  # type: ignore[arg-type]
            expected_gid=payload["expected_gid"],  # type: ignore[arg-type]
            egress_policy_digest=payload["egress_policy_digest"],  # type: ignore[arg-type]
            diary_egress_policy_digest=payload[
                "diary_egress_policy_digest"
            ],  # type: ignore[arg-type]
            diary_style_contract_digest=payload[
                "diary_style_contract_digest"
            ],  # type: ignore[arg-type]
            diary_persona_digest=payload["diary_persona_digest"],  # type: ignore[arg-type]
            diary_model=payload["diary_model"],  # type: ignore[arg-type]
            diary_model_role=payload["diary_model_role"],  # type: ignore[arg-type]
            p08_lifecycle_start_watermark=payload[
                "p08_lifecycle_start_watermark"
            ],  # type: ignore[arg-type]
            calendar_zone=payload["calendar_zone"],  # type: ignore[arg-type]
            calendar_zone_config_digest=payload[
                "calendar_zone_config_digest"
            ],  # type: ignore[arg-type]
            status=payload["status"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    def audit_projection(self) -> dict[str, object]:
        return {
            "archive_id": self.archive_id,
            "calendar_zone": self.calendar_zone,
            "calendar_zone_config_digest": self.calendar_zone_config_digest,
            "diary_egress_policy_digest": self.diary_egress_policy_digest,
            "diary_model": self.diary_model,
            "diary_model_role": self.diary_model_role,
            "diary_persona_digest": self.diary_persona_digest,
            "diary_style_contract_digest": self.diary_style_contract_digest,
            "egress_policy_digest": self.egress_policy_digest,
            "memory_release_set_id": self.memory_release_set_id,
            "parent_epoch_id": self.parent_epoch_id,
            "parent_epoch_revision": self.parent_epoch_revision,
            "parent_release_set_id": self.parent_release_set_id,
            "policy_overlay_id": self.policy_overlay_id,
            "p08_lifecycle_start_watermark": self.p08_lifecycle_start_watermark,
            "schema": self.schema,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class DiaryEgressSelection:
    memory_release_set_id: str
    parent_release_set_id: str
    policy_overlay_id: str
    archive_id: str
    expected_uid: int
    expected_gid: int
    egress_policy_digest: str
    style_contract_digest: str
    persona_digest: str
    model: str
    model_role: str
    status: str = "active"
    schema: str = DIARY_EGRESS_SELECTOR_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != DIARY_EGRESS_SELECTOR_SCHEMA or self.status != "active":
            raise EpisodicMemoryError("diary_egress_selector_state_rejected")
        for value, label in (
            (self.memory_release_set_id, "diary_selector_memory_release_set"),
            (self.parent_release_set_id, "diary_selector_parent_release_set"),
            (self.policy_overlay_id, "diary_selector_policy_overlay"),
            (self.egress_policy_digest, "diary_selector_egress_policy"),
            (self.style_contract_digest, "diary_selector_style_contract"),
            (self.persona_digest, "diary_selector_persona"),
        ):
            require_digest(value, label)
        require_id(self.archive_id, "diary_selector_archive")
        if (
            self.egress_policy_digest != REFLECTIVE_DIARY_EGRESS_V1_DIGEST
            or self.style_contract_digest != REFLECTIVE_DIARY_STYLE_V1_DIGEST
            or self.model != DIARY_MODEL
            or self.model_role != DIARY_MODEL_ROLE
        ):
            raise EpisodicMemoryError("diary_egress_selector_contract_drifted")
        if (
            isinstance(self.expected_uid, bool)
            or not isinstance(self.expected_uid, int)
            or self.expected_uid < 0
            or isinstance(self.expected_gid, bool)
            or not isinstance(self.expected_gid, int)
            or self.expected_gid < 0
        ):
            raise EpisodicMemoryError("diary_egress_selector_identity_rejected")

    @classmethod
    def from_payload(cls, payload: object) -> DiaryEgressSelection:
        required = {
            "archive_id",
            "channel_kind",
            "client_id",
            "complete_closed_day_required",
            "egress_policy_digest",
            "expected_gid",
            "expected_uid",
            "memory_release_set_id",
            "model",
            "model_role",
            "no_old_data_migration",
            "parent_release_set_id",
            "partial_day_provider_call",
            "persona_digest",
            "policy_overlay_id",
            "rollback_mode",
            "schema",
            "status",
            "style_contract_digest",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EpisodicMemoryError("diary_egress_selector_fields_rejected")
        if (
            payload["channel_kind"] != CHANNEL_KIND
            or payload["client_id"] != CORE_CLIENT_ID
            or payload["complete_closed_day_required"] is not True
            or payload["partial_day_provider_call"] is not False
            or payload["no_old_data_migration"] is not True
            or payload["rollback_mode"] != "local-only-disabled"
        ):
            raise EpisodicMemoryError("diary_egress_selector_contract_rejected")
        return cls(
            memory_release_set_id=payload["memory_release_set_id"],  # type: ignore[arg-type]
            parent_release_set_id=payload["parent_release_set_id"],  # type: ignore[arg-type]
            policy_overlay_id=payload["policy_overlay_id"],  # type: ignore[arg-type]
            archive_id=payload["archive_id"],  # type: ignore[arg-type]
            expected_uid=payload["expected_uid"],  # type: ignore[arg-type]
            expected_gid=payload["expected_gid"],  # type: ignore[arg-type]
            egress_policy_digest=payload["egress_policy_digest"],  # type: ignore[arg-type]
            style_contract_digest=payload["style_contract_digest"],  # type: ignore[arg-type]
            persona_digest=payload["persona_digest"],  # type: ignore[arg-type]
            model=payload["model"],  # type: ignore[arg-type]
            model_role=payload["model_role"],  # type: ignore[arg-type]
            status=payload["status"],  # type: ignore[arg-type]
            schema=payload["schema"],  # type: ignore[arg-type]
        )

    def validate_for(self, memory: OwnerPrivateMemorySelection) -> None:
        if (
            self.memory_release_set_id != memory.memory_release_set_id
            or self.parent_release_set_id != memory.parent_release_set_id
            or self.policy_overlay_id != memory.policy_overlay_id
            or self.archive_id != memory.archive_id
            or self.expected_uid != memory.expected_uid
            or self.expected_gid != memory.expected_gid
            or self.egress_policy_digest != memory.diary_egress_policy_digest
            or self.style_contract_digest != memory.diary_style_contract_digest
            or self.persona_digest != memory.diary_persona_digest
            or self.model != memory.diary_model
            or self.model_role != memory.diary_model_role
        ):
            raise EpisodicMemoryError("diary_egress_selector_binding_drifted")

    @property
    def core_egress_binding_digest(self) -> str:
        return reflective_diary_egress_binding_digest(
            memory_release_set_id=self.memory_release_set_id,
            parent_release_set_id=self.parent_release_set_id,
            policy_overlay_id=self.policy_overlay_id,
            archive_id=self.archive_id,
            egress_policy_digest=self.egress_policy_digest,
            style_contract_digest=self.style_contract_digest,
            persona_digest=self.persona_digest,
            model=self.model,
            model_role=self.model_role,
        )

    def audit_projection(self) -> dict[str, object]:
        return {
            "archive_id": self.archive_id,
            "core_egress_binding_digest": self.core_egress_binding_digest,
            "egress_policy_digest": self.egress_policy_digest,
            "memory_release_set_id": self.memory_release_set_id,
            "model": self.model,
            "model_role": self.model_role,
            "parent_release_set_id": self.parent_release_set_id,
            "persona_digest": self.persona_digest,
            "policy_overlay_id": self.policy_overlay_id,
            "schema": self.schema,
            "status": self.status,
            "style_contract_digest": self.style_contract_digest,
        }


def load_selected_memory_runtime(
    path: Path = SELECTOR_PATH,
    *,
    expected_selector_uid: int = 0,
    expected_selector_gid: int,
) -> OwnerPrivateMemorySelection | None:
    if not path.exists() and not path.is_symlink():
        return None
    try:
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_selector_uid
            or metadata.st_gid != expected_selector_gid
            or mode != 0o640
        ):
            raise EpisodicMemoryError("memory_selector_permissions_rejected")
        payload = json.loads(path.read_text("utf-8"))
    except EpisodicMemoryError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EpisodicMemoryError("memory_selector_unavailable") from exc
    return OwnerPrivateMemorySelection.from_payload(payload)


def load_selected_diary_egress(
    path: Path = DIARY_EGRESS_SELECTOR_PATH,
    *,
    expected_selector_uid: int = 0,
    expected_selector_gid: int,
) -> DiaryEgressSelection | None:
    if not path.exists() and not path.is_symlink():
        return None
    try:
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_selector_uid
            or metadata.st_gid != expected_selector_gid
            or mode != 0o640
        ):
            raise EpisodicMemoryError("diary_egress_selector_permissions_rejected")
        payload = json.loads(path.read_text("utf-8"))
    except EpisodicMemoryError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EpisodicMemoryError("diary_egress_selector_unavailable") from exc
    return DiaryEgressSelection.from_payload(payload)


def load_selected_memory_runtime_v4(
    path: Path = MEMORY_SELECTOR_V4_PATH,
    *,
    expected_selector_uid: int = 0,
    expected_selector_gid: int,
) -> OwnerPrivateMemorySelectionV4 | None:
    payload = load_protected_selector(
        path, uid=expected_selector_uid, gid=expected_selector_gid
    )
    return None if payload is None else OwnerPrivateMemorySelectionV4.from_payload(payload)


def load_selected_owner_day_diary_v2(
    path: Path = DIARY_SELECTOR_V2_PATH,
    *,
    expected_selector_uid: int = 0,
    expected_selector_gid: int,
) -> OwnerDayDiarySelectionV2 | None:
    payload = load_protected_selector(
        path, uid=expected_selector_uid, gid=expected_selector_gid
    )
    if payload is None:
        return None
    return OwnerDayDiarySelectionV2.from_payload(payload)


def load_selected_memory_configuration(
    *,
    expected_selector_gid: int,
) -> tuple[OwnerPrivateMemorySelection | OwnerPrivateMemorySelectionV4 | None, OwnerDayDiarySelectionV2 | None]:
    legacy = load_selected_memory_runtime(expected_selector_gid=expected_selector_gid)
    successor = load_selected_memory_runtime_v4(
        expected_selector_gid=expected_selector_gid
    )
    legacy_diary = load_selected_diary_egress(
        expected_selector_gid=expected_selector_gid
    )
    successor_diary = load_selected_owner_day_diary_v2(
        expected_selector_gid=expected_selector_gid
    )
    if legacy is not None and successor is not None:
        raise EpisodicMemoryError("memory_selector_mixed_generation_rejected")
    if legacy_diary is not None and successor_diary is not None:
        raise EpisodicMemoryError("diary_selector_mixed_generation_rejected")
    if legacy is not None:
        if successor_diary is not None:
            raise EpisodicMemoryError("diary_selector_generation_mismatch")
        return legacy, None
    if successor is None:
        if legacy_diary is not None or successor_diary is not None:
            raise EpisodicMemoryError("diary_selector_without_memory_rejected")
        return None, None
    if legacy_diary is not None:
        raise EpisodicMemoryError("diary_selector_generation_mismatch")
    if successor_diary is not None:
        successor_diary.validate_for(successor)
    return successor, successor_diary


@dataclass(frozen=True, slots=True)
class PreparedMemoryTurn:
    delivery_token: str
    replayed: bool
    episode: FactualDeliveryEpisodeV1


@dataclass(frozen=True, slots=True)
class MemoryDeliveryOutcome:
    outcome: str
    replayed: bool
    delivered_monotonic_ns: int | None
    delivered_boot_id: str | None
    delivery_ack_digest: str | None
    archive_written: bool
    index_current: bool
    diary_pending: bool
    derivative_gap_code: str | None
    episode: FactualDeliveryEpisodeV1

    def audit_projection(self) -> dict[str, object]:
        return {
            "archive_written": self.archive_written,
            "derivative_gap_code": self.derivative_gap_code,
            "diary_pending": self.diary_pending,
            "index_current": self.index_current,
            "outcome": self.outcome,
            "replayed": self.replayed,
            "episode": self.episode.audit_projection(),
        }


def require_precreated_runtime_root(
    selection: OwnerPrivateMemorySelection | OwnerPrivateMemorySelectionV4,
) -> None:
    """Fail closed unless the selected active-route root already exists exactly."""

    root = selection.runtime_root
    if not root.exists() and not root.is_symlink():
        raise EpisodicMemoryError("memory_runtime_root_precreation_required")
    status = root.lstat()
    if (
        root.is_symlink()
        or not stat.S_ISDIR(status.st_mode)
        or status.st_uid != selection.expected_uid
        or status.st_gid != selection.expected_gid
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        raise EpisodicMemoryError("memory_runtime_root_permissions_rejected")


class OwnerPrivateMemoryRuntime:
    """Single writer for newly delivered turns; it never imports old history."""

    def __init__(
        self,
        selection: OwnerPrivateMemorySelection | OwnerPrivateMemorySelectionV4,
        *,
        owner_day_diary: OwnerDayDiarySelectionV2 | None = None,
    ) -> None:
        self.selection = selection
        if owner_day_diary is not None:
            if not isinstance(selection, OwnerPrivateMemorySelectionV4):
                raise EpisodicMemoryError("owner_day_diary_memory_generation_rejected")
            owner_day_diary.validate_for(selection)
        self.owner_day_diary = owner_day_diary
        self.archive = LosslessArchiveStore(
            selection.runtime_root / "raw-archive.sqlite3",
            expected_uid=selection.expected_uid,
            expected_gid=selection.expected_gid,
        )
        self.journal = DeliveryJournal(self.archive)
        self.index_path = selection.runtime_root / "episodic-index.json"
        self.temporal_index = TemporalIntervalIndexStore(
            selection.runtime_root / "temporal-interval-index.json"
        )
        self.diary = ReflectiveDiaryStore(
            selection.runtime_root / "reflective-diary.sqlite3",
            current_source_snapshot_loader=self._load_current_source_authority,
        )
        self._pending_profile_requests: dict[str, dict[str, object]] = {}
        self._initialized = False

    @property
    def _owner_day_policy(self) -> OwnerDayPolicy:
        return (
            self.owner_day_diary.owner_day_policy
            if self.owner_day_diary is not None
            else OwnerDayPolicy()
        )

    def _load_current_source_authority(
        self,
    ) -> tuple[
        EpisodicIndexSnapshot,
        tuple[CompleteTurn, ...],
        TemporalIntervalIndexSnapshot,
    ]:
        """Load and independently verify the exact current raw/P08 closure."""

        self._verify_permissions()
        turns = tuple(self.archive.turns())
        corrections = self.archive.time_corrections()
        metadata = self.archive.metadata()
        temporal_snapshot = self.temporal_index.read(
            archive_head_digest=str(metadata["head_digest"]),
            initial_event_sequence=self.selection.p08_lifecycle_start_watermark,
        )
        return (
            derive_snapshot(
                turns,
                archive_id=self.selection.archive_id,
                corrections=corrections,
                temporal_snapshot=temporal_snapshot,
                owner_day_policy=self._owner_day_policy,
            ),
            turns,
            temporal_snapshot,
        )

    def _load_current_source_snapshot(self) -> EpisodicIndexSnapshot:
        return self._load_current_source_authority()[0]

    def _stage_profile_request(self, delivery_token: str, owner_message: str) -> None:
        request = parse_profile_v2_structural_request(owner_message)
        if request is None:
            return
        if delivery_token in self._pending_profile_requests:
            raise EpisodicMemoryError("profile_state_staging_conflict")
        self._pending_profile_requests[delivery_token] = dict(request)

    def stage_profile_server_intents(
        self,
        delivery_token: str,
        server_intents: tuple[ServerIntentProposal, ...],
    ) -> None:
        self._verify_permissions()
        try:
            delivery_bound = self.journal.close_evidence_required(delivery_token)
        except EpisodicMemoryError:
            delivery_bound = False
        if not delivery_bound:
            raise EpisodicMemoryError("profile_state_delivery_token_unbound")
        selected = tuple(
            item for item in server_intents if item.kind == "profile_state_proposal"
        )
        if len(selected) > 1 or delivery_token in self._pending_profile_requests:
            raise EpisodicMemoryError("profile_state_staging_conflict")
        if not selected:
            return
        intent = selected[0]
        if (
            intent.action != "delta"
            or intent.field_id != "relationship_state.intimacy_headline"
            or type(intent.requested_delta) is not int
            or intent.reason_category not in {"delivered_turn", "episode_end"}
            or (
                intent.reason_category == "episode_end"
                and intent.source_interval_id is None
            )
            or (
                intent.reason_category == "delivered_turn"
                and intent.source_interval_id is not None
            )
        ):
            raise EpisodicMemoryError("profile_state_server_intent_rejected")
        self._pending_profile_requests[delivery_token] = {
            "action": intent.action,
            "actor": "myuna",
            "field_id": intent.field_id,
            "intent_id": intent.intent_id,
            "proposal_digest": intent.proposal_digest,
            "reason_category": intent.reason_category,
            "requested_delta": intent.requested_delta,
            "source_interval_id": intent.source_interval_id,
        }

    def _commit_staged_profile_request(
        self,
        delivery_token: str,
        turn: CompleteTurn,
    ) -> None:
        request = self._pending_profile_requests.pop(delivery_token, None)
        if request is None:
            return
        snapshot, _turns, temporal_snapshot = self._load_current_source_authority()
        manifest = profile_v2_manifests()[0]
        current = self.diary.current_profile_values()[0]
        action = str(request["action"])
        actor = str(request.get("actor", "owner"))
        proposal_id = None
        proposal_version = None
        proposal_manifest_head = None
        proposal_change_digest = None
        proposal_expires_at_utc = None
        requested_value = request.get("requested_value")
        requested_delta = request.get("requested_delta")
        rollback_target_event_id = None
        rollback_target_event_digest = None
        if action == "rollback" and type(requested_value) is int:
            rollback_target = self.diary.profile_rollback_target(
                manifest.field_id,
                requested_value,
            )
            rollback_target_event_id = rollback_target.event_id
            rollback_target_event_digest = rollback_target.event_digest
        if action == "propose_manifest":
            proposal_id = "profile-" + delivery_token[:24]
            proposal_version = 1
            proposal_manifest_head = current.last_event_digest
            proposal_change_digest = profile_state_digest(
                "myuna-profile-v2-proposal-change",
                {
                    "field_id": manifest.field_id,
                    "requested_value": requested_value,
                },
            )
            proposal_expires_at_utc = (
                turn.draft.time_binding.delivered_at_utc + timedelta(days=7)
            ).astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            )
        elif action in {"confirm_manifest", "cancel_manifest"}:
            proposal = self.diary.current_profile_proposal(
                str(request["proposal_id"]), int(request["proposal_version"])
            )
            proposal_id = proposal.proposal_id
            proposal_version = proposal.proposal_version
            proposal_manifest_head = proposal.proposal_manifest_head
            proposal_change_digest = proposal.proposal_change_digest
            proposal_expires_at_utc = proposal.proposal_expires_at_utc
            requested_value = (
                proposal.proposal_value if action == "confirm_manifest" else None
            )
        reason = str(request.get("reason_category") or {
            "propose_manifest": "delivered_turn",
            "confirm_manifest": "owner_confirmed",
            "cancel_manifest": "owner_confirmed",
            "freeze": "owner_freeze",
            "unfreeze": "owner_confirmed",
            "correct": "owner_correction",
            "rollback": "owner_rollback",
        }[action])
        delivered_reference = snapshot.source_references[turn.draft.sequence - 1]
        p08_values: dict[str, object | None] = {
            "episode_revision_id": None,
            "p08_episode_id": None,
            "p08_interval_id": None,
            "p08_terminal_revision": None,
            "p08_terminal_revision_digest": None,
            "p08_terminal_event_sequence": None,
            "p08_terminal_event_kind": None,
            "p08_source_reference_digest": None,
        }
        if reason == "episode_end":
            source_interval_id = request.get("source_interval_id")
            episode = next(
                (
                    item
                    for item in temporal_snapshot.episodes
                    if item.interval_id == source_interval_id
                ),
                None,
            )
            if episode is None or not episode.revisions:
                raise EpisodicMemoryError("profile_state_terminal_source_mismatch")
            terminal = episode.revisions[-1]
            source_reference = snapshot.source_references[
                terminal.source_turn_sequences[-1] - 1
            ]
            if (episode.terminal_state, terminal.p08_event_kind) not in {
                ("ended", "expire"),
                ("cancelled", "revoke"),
            }:
                raise EpisodicMemoryError("profile_state_terminal_source_mismatch")
            p08_values = {
                "episode_revision_id": (
                    "p08-terminal-" + terminal.revision_digest[:48]
                ),
                "p08_episode_id": episode.episode_digest,
                "p08_interval_id": episode.interval_id,
                "p08_terminal_revision": terminal.revision,
                "p08_terminal_revision_digest": terminal.revision_digest,
                "p08_terminal_event_sequence": terminal.p08_event_sequence,
                "p08_terminal_event_kind": terminal.p08_event_kind,
                "p08_source_reference_digest": (
                    source_reference.source_reference_digest
                ),
            }
        if turn.draft.delivery_ack_digest is None:
            raise EpisodicMemoryError("profile_state_delivery_binding_mismatch")
        intent = ProfileStateIntent(
            intent_id=(
                "profile-" + delivery_token[:48]
                if actor == "owner"
                else "profile-" + str(request["intent_id"])[:40] + "-" + delivery_token[:16]
            ),
            action=action,
            module_id=manifest.module_id,
            field_id=manifest.field_id,
            actor=actor,
            reason_category=reason,
            requested_value=(
                requested_value if type(requested_value) is int else None
            ),
            requested_delta=(
                requested_delta if type(requested_delta) is int else None
            ),
            expected_event_digest=current.last_event_digest,
            raw_source_digest=snapshot.source_closure_digest,
            p08_source_digest=snapshot.temporal_snapshot_digest,
            trusted_time_digest=turn.draft.time_binding.binding_digest,
            delivered_turn_id=turn.draft.turn_id,
            delivery_ack_digest=turn.draft.delivery_ack_digest,
            delivered_source_reference_digest=(
                delivered_reference.source_reference_digest
            ),
            delivered_at_utc=turn.draft.time_binding.delivered_at_utc.astimezone(
                timezone.utc
            ).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            proposal_id=proposal_id,
            proposal_version=proposal_version,
            proposal_manifest_head=proposal_manifest_head,
            proposal_change_digest=proposal_change_digest,
            proposal_expires_at_utc=proposal_expires_at_utc,
            rollback_target_event_id=rollback_target_event_id,
            rollback_target_event_digest=rollback_target_event_digest,
            **p08_values,
        )
        self.diary.append_profile_state_intent(intent)

    def _rebind_temporal_archive_head(
        self,
        *,
        turns: Sequence[CompleteTurn],
        archive_head_digest: str,
    ) -> TemporalIntervalIndexSnapshot:
        prior = self.temporal_index.read(
            archive_head_digest=archive_head_digest,
            initial_event_sequence=self.selection.p08_lifecycle_start_watermark,
        )
        rebound = rebind_temporal_interval_archive_head(
            prior,
            archive_turns=turns,
            archive_head_digest=archive_head_digest,
        )
        if (
            not self.temporal_index.path.exists()
            or rebound.snapshot_digest != prior.snapshot_digest
        ):
            self.temporal_index.write(rebound)
        return rebound

    def initialize(self) -> dict[str, object]:
        root = self.selection.runtime_root
        if not root.exists() and not root.is_symlink():
            # The selected Telegram gateway composition verifies a precreated
            # root before constructing this runtime.  Retain bounded legacy
            # synthetic/derivative compatibility outside that active route.
            root.mkdir(parents=False, mode=0o700)
        require_precreated_runtime_root(self.selection)
        self._preflight_existing_paths()
        self.archive.initialize()
        self.diary.initialize()
        turns = self.archive.turns()
        corrections = self.archive.time_corrections()
        metadata = self.archive.metadata()
        temporal_snapshot = self._rebind_temporal_archive_head(
            turns=turns,
            archive_head_digest=str(metadata["head_digest"]),
        )
        index_recovered = recover_or_write_snapshot(
            self.index_path,
            turns,
            archive_id=self.selection.archive_id,
            corrections=corrections,
            temporal_snapshot=temporal_snapshot,
            owner_day_policy=self._owner_day_policy,
            explicit_rebuild=True,
        )
        self._verify_permissions()
        self._initialized = True
        return self.audit_projection() | {
            "index_sidecar_recovered": index_recovered,
            "startup_recovered_count": 0,
        }

    def content_free_ready(self) -> bool:
        if not self._initialized:
            raise EpisodicMemoryError("memory_runtime_not_initialized")
        return True

    def p08_lifecycle_cursor(self) -> int:
        self._verify_permissions()
        snapshot = self.temporal_index.read(
            archive_head_digest=str(self.archive.metadata()["head_digest"]),
            initial_event_sequence=self.selection.p08_lifecycle_start_watermark,
        )
        return snapshot.after_event_sequence

    def _preflight_existing_paths(self) -> None:
        paths = [
            self.archive.path,
            self.archive.path.with_name(self.archive.path.name + "-journal"),
            self.index_path,
            self.index_path.with_name(self.index_path.name + ".next"),
            self.temporal_index.path,
            self.temporal_index.path.with_name(self.temporal_index.path.name + ".tmp"),
        ]
        paths.append(self.diary.path)
        for path in paths:
            if not path.exists() and not path.is_symlink():
                continue
            status = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(status.st_mode)
                or status.st_uid != self.selection.expected_uid
                or status.st_gid != self.selection.expected_gid
                or stat.S_IMODE(status.st_mode) != 0o600
            ):
                raise EpisodicMemoryError("memory_runtime_file_permissions_rejected")

    def _verify_permissions(self) -> None:
        root_status = self.selection.runtime_root.lstat()
        if (
            root_status.st_uid != self.selection.expected_uid
            or root_status.st_gid != self.selection.expected_gid
            or stat.S_IMODE(root_status.st_mode) != 0o700
        ):
            raise EpisodicMemoryError("memory_runtime_root_permissions_rejected")
        paths = [
            self.archive.path,
            self.index_path,
            self.temporal_index.path,
        ]
        archive_journal = self.archive.path.with_name(self.archive.path.name + "-journal")
        if archive_journal.exists() or archive_journal.is_symlink():
            paths.append(archive_journal)
        paths.append(self.diary.path)
        for path in paths:
            status = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(status.st_mode)
                or status.st_uid != self.selection.expected_uid
                or status.st_gid != self.selection.expected_gid
                or stat.S_IMODE(status.st_mode) != 0o600
            ):
                raise EpisodicMemoryError("memory_runtime_file_permissions_rejected")

    def build_context(
        self,
        *,
        authenticated_context: AuthenticatedConversationContext,
        current_message: str,
        received_monotonic_ns: int,
        p08_temporal_coverage_state: str,
        trusted_time_sample: TrustedTimeSample | None,
        trusted_time_unresolved_reason: str | None,
        safety: EgressSafetySignals,
        active_snapshot_receipt: ActiveSnapshotReceipt | None = None,
        temporal_lifecycle_transitions: tuple[Mapping[str, object], ...] = (),
        temporal_lifecycle_watermark: int = 0,
        temporal_lifecycle_has_more: bool = False,
        visual_event: Mapping[str, object] | None = None,
    ) -> EpisodicRuntimeContext:
        temporal_preflight_failure: tuple[str, str] | None = None
        if p08_temporal_coverage_state == "complete":
            if (
                not isinstance(active_snapshot_receipt, ActiveSnapshotReceipt)
                or not isinstance(trusted_time_sample, TrustedTimeSample)
                or not active_snapshot_receipt.matches_source_tuple(
                    request_id=active_snapshot_receipt.request_id,
                    after_event_sequence=(
                        active_snapshot_receipt.after_event_sequence
                    ),
                    fact_count=active_snapshot_receipt.fact_count,
                    transitions=temporal_lifecycle_transitions,
                    lifecycle_watermark=temporal_lifecycle_watermark,
                    lifecycle_has_more=temporal_lifecycle_has_more,
                    trusted_time=trusted_time_sample.as_payload(),
                )
            ):
                temporal_preflight_failure = (
                    "conflict",
                    "source_receipt_conflict",
                )
        elif p08_temporal_coverage_state != "unavailable":
            temporal_preflight_failure = (
                "conflict",
                "source_coverage_conflict",
            )
        self._verify_permissions()
        binding = self._bind_prompt_time(
            received_monotonic_ns=received_monotonic_ns,
            trusted_time_sample=trusted_time_sample,
            trusted_time_unresolved_reason=trusted_time_unresolved_reason,
        )
        turns = self.archive.turns()
        corrections = self.archive.time_corrections()
        metadata = self.archive.metadata()
        temporal_source_failure = temporal_preflight_failure
        if temporal_preflight_failure is not None:
            prior_temporal_snapshot = TemporalIntervalIndexSnapshot.empty(
                str(metadata["head_digest"]),
                initial_event_sequence=self.selection.p08_lifecycle_start_watermark,
            )
        else:
            try:
                prior_temporal_snapshot = self.temporal_index.read(
                    archive_head_digest=str(metadata["head_digest"]),
                    initial_event_sequence=(
                        self.selection.p08_lifecycle_start_watermark
                    ),
                )
            except EpisodicMemoryError:
                temporal_source_failure = (
                    "conflict",
                    "source_derivative_conflict",
                )
                prior_temporal_snapshot = TemporalIntervalIndexSnapshot.empty(
                    str(metadata["head_digest"]),
                    initial_event_sequence=(
                        self.selection.p08_lifecycle_start_watermark
                    ),
                )
        if (
            prior_temporal_snapshot.after_event_sequence
            < self.selection.p08_lifecycle_start_watermark
        ):
            raise EpisodicMemoryError("temporal_interval_cursor_regressed")
        temporal_snapshot = prior_temporal_snapshot
        temporal_source_changed = False
        if p08_temporal_coverage_state == "complete" and temporal_source_failure is None:
            try:
                temporal_snapshot = advance_temporal_interval_index(
                    prior_temporal_snapshot,
                    temporal_lifecycle_transitions,
                    observed_watermark=temporal_lifecycle_watermark,
                    has_more=temporal_lifecycle_has_more,
                    archive_turns=turns,
                    archive_head_digest=str(metadata["head_digest"]),
                    active_snapshot_receipt=active_snapshot_receipt,
                )
            except EpisodicMemoryError:
                temporal_source_failure = ("conflict", "source_advance_conflict")
            else:
                temporal_source_changed = (
                    temporal_snapshot.snapshot_digest
                    != prior_temporal_snapshot.snapshot_digest
                )
                if temporal_source_changed:
                    self.temporal_index.write(temporal_snapshot)
        elif (
            temporal_source_failure is None
            and p08_temporal_coverage_state != "unavailable"
        ):
            temporal_source_failure = ("conflict", "source_coverage_conflict")
        if temporal_source_failure is not None:
            resident_projection = content_free_temporal_projection(
                state=temporal_source_failure[0],
                reason_category=temporal_source_failure[1],
                source_snapshot_digest=temporal_snapshot.snapshot_digest,
                trusted_time_binding_digest=binding.binding_digest,
                maximum_characters=MAX_TEMPORAL_CONTEXT_CHARACTERS,
                maximum_serialized_bytes=MAX_TEMPORAL_CONTEXT_SERIALIZED_BYTES,
                maximum_tokens=MAX_TEMPORAL_CONTEXT_TOKENS,
            )
        else:
            resident_projection = project_resident_temporal_items(
                temporal_snapshot.episodes,
                source_snapshot_digest=temporal_snapshot.snapshot_digest,
                source_complete=(
                    p08_temporal_coverage_state == "complete"
                    and not temporal_lifecycle_has_more
                    and temporal_snapshot.after_event_sequence
                    == temporal_snapshot.observed_watermark
                    and not temporal_snapshot.unresolved_event_sequences
                    and not temporal_snapshot.blocked_interval_ids
                ),
                trusted_time_binding=binding,
                active_snapshot_receipt=active_snapshot_receipt,
                maximum_characters=MAX_TEMPORAL_CONTEXT_CHARACTERS,
                maximum_serialized_bytes=MAX_TEMPORAL_CONTEXT_SERIALIZED_BYTES,
                maximum_tokens=MAX_TEMPORAL_CONTEXT_TOKENS,
                token_counter=_resident_token_upper_bound,
            )
        if resident_projection.state == "available":
            temporal_context = "\n\n".join(resident_projection.fragments)
        else:
            reason = (
                "none"
                if resident_projection.reason_category is None
                else resident_projection.reason_category
            )
            temporal_context = (
                "[resident_temporal_projection_v1 "
                f"state={resident_projection.state} reason_category={reason}]"
            )
        policy = RecallEgressPolicy(
            EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1,
            HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
        )
        query = EpisodicQuery(current_message)
        relative = _RELATIVE_DATE.search(current_message)
        relative_time_unavailable = False
        if relative is not None:
            if binding.status != "exact" or binding.sample_instant_utc is None:
                relative_time_unavailable = True
            else:
                interval = resolve_relative_date(
                    relative.group(0),
                    reference_utc=binding.sample_instant_utc,
                    zone_name=binding.calendar_zone,
                )
                query = EpisodicQuery(
                    current_message,
                    start_utc=interval.start,
                    end_utc=interval.end,
                )
        index_failure = temporal_preflight_failure
        if temporal_source_changed:
            try:
                prior_index_snapshot = read_snapshot(self.index_path)
            except EpisodicMemoryError:
                index_failure = ("unavailable", "index_unavailable")
            if index_failure is None:
                try:
                    verify_snapshot(
                        prior_index_snapshot,
                        turns,
                        archive_id=self.selection.archive_id,
                        corrections=corrections,
                        temporal_snapshot=prior_temporal_snapshot,
                        owner_day_policy=self._owner_day_policy,
                    )
                except EpisodicMemoryError:
                    index_failure = ("conflict", "index_source_conflict")
            if index_failure is None:
                try:
                    write_snapshot(
                        self.index_path,
                        derive_snapshot(
                            turns,
                            archive_id=self.selection.archive_id,
                            corrections=corrections,
                            temporal_snapshot=temporal_snapshot,
                            owner_day_policy=self._owner_day_policy,
                        ),
                    )
                except EpisodicMemoryError:
                    index_failure = (
                        "unavailable",
                        "index_source_advance_unavailable",
                    )
        if index_failure is None:
            try:
                snapshot = read_snapshot(self.index_path)
            except EpisodicMemoryError:
                index_failure = ("unavailable", "index_unavailable")
        if index_failure is None:
            try:
                verify_snapshot(
                    snapshot,
                    turns,
                    archive_id=self.selection.archive_id,
                    corrections=corrections,
                    temporal_snapshot=temporal_snapshot,
                    owner_day_policy=self._owner_day_policy,
                )
            except EpisodicMemoryError:
                index_failure = ("conflict", "index_source_conflict")
        if index_failure is not None:
            snapshot = derive_snapshot(
                turns,
                archive_id=self.selection.archive_id,
                corrections=corrections,
                temporal_snapshot=temporal_snapshot,
                owner_day_policy=self._owner_day_policy,
            )
            retrieval = content_free_retrieval_failure(
                state=index_failure[0],
                reason_category=index_failure[1],
                index=snapshot,
                query=query,
            )
        elif relative_time_unavailable:
            retrieval = content_free_retrieval_failure(
                state="unavailable",
                reason_category="trusted_time_unavailable",
                index=snapshot,
                query=query,
            )
        else:
            searched = search_relevant_sources(
                query=query,
                index=snapshot,
                egress_policy=policy,
                maximum_turns=12,
            )
            retrieval = fetch_relevant_raw(
                selection=searched,
                turns=turns,
                index=snapshot,
                archive_id=self.selection.archive_id,
                corrections=corrections,
                temporal_snapshot=temporal_snapshot,
                owner_day_policy=self._owner_day_policy,
            )
        coverage_state = "complete"
        if retrieval.state in {"unavailable", "conflict"} or retrieval.coverage_limited:
            coverage_state = "coverage_incomplete"
        visual = None
        if visual_event is not None:
            visual = VisualEvidence.create(
                context=authenticated_context,
                current_message=current_message,
                observation=str(visual_event["observation"]),
                caption_present=bool(visual_event["caption_present"]),
            )
        profile_v2_state = "available_empty"
        profile_v2_context = ""
        profile_v2_item_count = 0
        profile_v2_projection_digest = profile_state_digest(
            "myuna-profile-v2-empty-projection",
            {"items": []},
        )
        try:
            currents = self.diary.current_profile_values()
            manifests = {item.field_id: item for item in profile_v2_manifests()}
            rendered = tuple(
                text
                for current in currents
                for text in (
                    render_profile_v2_current_context(
                        manifests[current.field_id], current
                    ),
                )
                if text is not None
            )
            profile_v2_projection_digest = profile_state_digest(
                "myuna-profile-v2-current-selection",
                {
                    "projection_digests": [
                        item.projection_digest for item in currents
                    ]
                },
            )
            if rendered:
                profile_v2_state = "available"
                profile_v2_context = "\n".join(rendered)
                profile_v2_item_count = len(rendered)
            elif currents and all(item.state == "uninitialized" for item in currents):
                profile_v2_state = "uninitialized"
        except OwnerProfileError:
            profile_v2_state = "conflict"
            profile_v2_projection_digest = profile_state_digest(
                "myuna-profile-v2-conflict-projection",
                {"reason_category": "source_or_projection_conflict"},
            )
        except EpisodicMemoryError as exc:
            profile_v2_state = (
                "unavailable"
                if exc.code == "profile_state_unavailable"
                else "conflict"
            )
            profile_v2_projection_digest = profile_state_digest(
                "myuna-profile-v2-"
                + profile_v2_state
                + "-projection",
                {
                    "reason_category": (
                        "derivative_unavailable"
                        if profile_v2_state == "unavailable"
                        else "source_or_projection_conflict"
                    )
                },
            )
        return EpisodicRuntimeContext(
            parent_release_set_id=self.selection.parent_release_set_id,
            policy_overlay_id=self.selection.policy_overlay_id,
            parent_epoch_id=self.selection.parent_epoch_id,
            parent_epoch_revision=self.selection.parent_epoch_revision,
            archive_id=self.selection.archive_id,
            archive_turn_count=int(metadata["turn_count"]),
            archive_head_digest=str(metadata["head_digest"]),
            recall_state=retrieval.state,
            recall_reason_category=retrieval.reason_category,
            recall_source_closure_digest=retrieval.source_closure_digest,
            recall_selection_digest=retrieval.selection_digest,
            candidate_turns=retrieval.hydrated_turns,
            required_sequences=tuple(
                turn.draft.sequence for turn in retrieval.hydrated_turns
            ),
            all_raw_candidate=(
                retrieval.state == "available"
                and len(retrieval.hydrated_turns) == int(metadata["turn_count"])
                and tuple(turn.draft.sequence for turn in retrieval.hydrated_turns)
                == tuple(range(1, int(metadata["turn_count"]) + 1))
            ),
            coverage_state=coverage_state,
            current_message=current_message,
            current_message_digest=current_message_digest(
                authenticated_context, current_message
            ),
            trusted_time_binding=binding,
            temporal_context=temporal_context,
            temporal_item_count=(
                resident_projection.occupancy.item_count
                if resident_projection.state == "available"
                else 0
            ),
            temporal_projection_digest=resident_projection.projection_digest,
            temporal_coverage_state=(
                "complete"
                if resident_projection.state in {"available", "available_empty"}
                else "unavailable"
            ),
            temporal_state=resident_projection.state,
            temporal_reason_category=resident_projection.reason_category,
            temporal_source_closure_digest=(
                resident_projection.source_closure_digest
            ),
            temporal_selection_digest=resident_projection.selection_digest,
            egress_policy_mode=EGRESS_POLICY_HISTORICAL_RAW_RECALL_V1,
            egress_policy_digest=HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
            safety=safety,
            profile_v2_context=profile_v2_context,
            profile_v2_item_count=profile_v2_item_count,
            profile_v2_projection_digest=profile_v2_projection_digest,
            profile_v2_state=profile_v2_state,
            visual_evidence=visual,
        )

    def commit_prefix_capsule(
        self,
        capsule: PrefixCapsule,
        verification_receipt: tuple[PrefixCapsule, str],
        token_counter: Callable[[tuple[Mapping[str, str], ...]], int] | None,
    ) -> str:
        if not self._initialized:
            raise EpisodicMemoryError("memory_runtime_not_initialized")
        self._verify_permissions()
        source_snapshot = self._load_current_source_snapshot()
        return self.diary.append_prefix_capsule(
            capsule,
            source_snapshot=source_snapshot,
            verification_receipt=verification_receipt,
            token_counter=token_counter,
        )

    def _bind_prompt_time(
        self,
        *,
        received_monotonic_ns: int,
        trusted_time_sample: TrustedTimeSample | None,
        trusted_time_unresolved_reason: str | None,
    ):
        if trusted_time_sample is not None and trusted_time_unresolved_reason is None:
            return bind_prompt_time_sample(
                trusted_time_sample,
                received_monotonic_ns=received_monotonic_ns,
                calendar_zone=self.selection.calendar_zone,
            )
        if trusted_time_sample is None and trusted_time_unresolved_reason is not None:
            return unresolved_turn_time(
                reason_code=trusted_time_unresolved_reason,
                received_monotonic_ns=received_monotonic_ns,
                committed_monotonic_ns=received_monotonic_ns,
                delivered_monotonic_ns=received_monotonic_ns,
                calendar_zone=self.selection.calendar_zone,
            )
        raise EpisodicMemoryError("trusted_time_mode_conflicted")

    def prepare_control_delivery(
        self,
        *,
        delivery_token: str,
        turn_id: str,
        control_kind: str,
        authenticated_context: AuthenticatedConversationContext,
        owner_message: str,
        assistant_reply: str,
        received_monotonic_ns: int,
        committed_monotonic_ns: int,
        source_occurred_at_utc: datetime,
        trusted_time_sample: TrustedTimeSample | None,
        trusted_time_unresolved_reason: str | None,
    ) -> PreparedMemoryTurn:
        self._verify_permissions()
        if control_kind not in _CONTROL_KINDS:
            raise EpisodicMemoryError("control_archive_kind_rejected")
        binding = self._bind_prompt_time(
            received_monotonic_ns=received_monotonic_ns,
            trusted_time_sample=trusted_time_sample,
            trusted_time_unresolved_reason=trusted_time_unresolved_reason,
        )
        request = current_message_digest(authenticated_context, owner_message)
        response = response_digest(assistant_reply)
        categories = (
            "authenticated_owner_private",
            CONTROL_ISOLATED_CATEGORY,
            f"control_{control_kind}_isolated",
            "delivery_ack_exactly_once",
            (
                "trusted_time_bound"
                if binding.status == "exact"
                else "trusted_time_unresolved"
            ),
        )
        provenance_digest = semantic_digest(
            "myuna-p07-control-turn-provenance-v1",
            {
                "control_kind": control_kind,
                "egress_policy_digest": HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
                "prompt_time_binding_digest": binding.binding_digest,
                "request_digest": request,
                "response_digest": response,
            },
        )
        preparation = DeliveryPreparation(
            delivery_token=delivery_token,
            turn_id=turn_id,
            owner=ArchivedContent("text", owner_message),
            assistant=ArchivedContent("text", assistant_reply),
            prompt_time_binding=binding,
            source_occurred_at_utc=source_occurred_at_utc,
            committed_monotonic_ns=committed_monotonic_ns,
            epoch_id=self.selection.archive_id,
            release_set_id=self.selection.memory_release_set_id,
            request_digest=request,
            response_digest=response,
            expected_archive_turn_count=None,
            expected_archive_head_digest=None,
            provenance_categories=categories,
            provenance_digest=provenance_digest,
        )
        prepared = self.journal.prepare_episode(
            preparation,
            owner_day_policy=(
                None
                if self.owner_day_diary is None
                else self.owner_day_diary.owner_day_policy
            ),
        )
        self._stage_profile_request(delivery_token, owner_message)
        return PreparedMemoryTurn(
            delivery_token=delivery_token,
            replayed=prepared.replayed,
            episode=prepared.episode,
        )

    def record_incomplete_turn(
        self,
        *,
        turn_id: str,
        authenticated_context: AuthenticatedConversationContext,
        owner_message: str,
        source_occurred_at_utc: datetime,
        reason_code: str,
    ) -> None:
        self._verify_permissions()
        require_id(reason_code, "incomplete_turn_reason")
        self.archive.append_lifecycle(
            LifecycleRecord(
                lifecycle_id=f"{turn_id}:{reason_code}",
                event_kind="abandoned",
                request_digest=current_message_digest(
                    authenticated_context, owner_message
                ),
                occurred_at_utc=source_occurred_at_utc,
                reason_code=reason_code,
                delivery_acknowledged=False,
                complete_turn_written=False,
            )
        )

    def prepare_delivery(
        self,
        *,
        delivery_token: str,
        turn_id: str,
        runtime_context: EpisodicRuntimeContext,
        assistant_reply: str,
        provenance: EpisodicTurnProvenance,
        committed_monotonic_ns: int,
        source_occurred_at_utc: datetime,
    ) -> PreparedMemoryTurn:
        self._verify_permissions()
        if (
            provenance.archive_turn_count != runtime_context.archive_turn_count
            or provenance.archive_head_digest != runtime_context.archive_head_digest
            or provenance.parent_release_set_id != self.selection.parent_release_set_id
            or provenance.policy_overlay_id != self.selection.policy_overlay_id
            or provenance.parent_epoch_id != self.selection.parent_epoch_id
            or provenance.parent_epoch_revision != self.selection.parent_epoch_revision
            or provenance.recall_state != runtime_context.recall_state
            or provenance.recall_reason_category
            != runtime_context.recall_reason_category
            or provenance.recall_source_closure_digest
            != runtime_context.recall_source_closure_digest
            or provenance.recall_selection_digest
            != runtime_context.recall_selection_digest
            or provenance.trusted_time_binding_digest
            != runtime_context.trusted_time_binding.binding_digest
            or provenance.temporal_projection_digest
            != runtime_context.temporal_projection_digest
            or provenance.temporal_coverage_state
            != runtime_context.temporal_coverage_state
            or provenance.temporal_state != runtime_context.temporal_state
            or provenance.temporal_reason_category
            != runtime_context.temporal_reason_category
            or provenance.temporal_source_closure_digest
            != runtime_context.temporal_source_closure_digest
            or provenance.temporal_selection_digest
            != runtime_context.temporal_selection_digest
        ):
            raise EpisodicMemoryError("memory_delivery_provenance_drifted")
        owner = ArchivedContent("text", runtime_context.current_message)
        if runtime_context.visual_evidence is not None:
            owner = ArchivedContent(
                "image_description",
                runtime_context.visual_evidence.observation,
                runtime_context.visual_evidence.evidence_digest,
            )
        categories = [
            "authenticated_owner_private",
            "raw_preferred_context",
            "delivery_ack_exactly_once",
        ]
        if runtime_context.trusted_time_binding.status == "exact":
            categories.append("trusted_time_bound")
        else:
            categories.append("trusted_time_unresolved")
        categories.append(f"resident_temporal_{runtime_context.temporal_state}")
        if provenance.source_ranges:
            categories.append("historical_raw_recall_v1")
        if provenance.profile_revisions:
            categories.append("confirmed_profile_selected")
        if runtime_context.visual_evidence is not None:
            categories.append("authorized_image_description")
        preparation = DeliveryPreparation(
            delivery_token=delivery_token,
            turn_id=turn_id,
            owner=owner,
            assistant=ArchivedContent("text", assistant_reply),
            prompt_time_binding=runtime_context.trusted_time_binding,
            source_occurred_at_utc=source_occurred_at_utc,
            committed_monotonic_ns=committed_monotonic_ns,
            epoch_id=self.selection.archive_id,
            release_set_id=self.selection.memory_release_set_id,
            request_digest=runtime_context.current_message_digest,
            response_digest=response_digest(assistant_reply),
            expected_archive_turn_count=runtime_context.archive_turn_count,
            expected_archive_head_digest=runtime_context.archive_head_digest,
            provenance_categories=tuple(categories),
            provenance_digest=semantic_digest(
                "myuna-p07-episodic-turn-provenance-v1", provenance.as_payload()
            ),
        )
        prepared = self.journal.prepare_episode(
            preparation,
            owner_day_policy=(
                None
                if self.owner_day_diary is None
                else self.owner_day_diary.owner_day_policy
            ),
        )
        self._stage_profile_request(delivery_token, runtime_context.current_message)
        return PreparedMemoryTurn(
            delivery_token=delivery_token,
            replayed=prepared.replayed,
            episode=prepared.episode,
        )

    def delivery_close_evidence_required(self, delivery_token: str) -> bool:
        self._verify_permissions()
        return self.journal.close_evidence_required(delivery_token)

    def resolve_delivery(
        self,
        *,
        delivery_token: str,
        outcome: str,
        delivered_monotonic_ns: int | None,
        delivered_boot_id: str | None = None,
    ) -> MemoryDeliveryOutcome:
        self._verify_permissions()
        resolution = self.journal.resolve(
            delivery_token=delivery_token,
            outcome=outcome,
            delivered_monotonic_ns=delivered_monotonic_ns,
            delivered_boot_id=delivered_boot_id,
            owner_day_policy=(
                None
                if self.owner_day_diary is None
                else self.owner_day_diary.owner_day_policy
            ),
        )
        if outcome == "cancelled":
            self._pending_profile_requests.pop(delivery_token, None)
            return MemoryDeliveryOutcome(
                outcome="cancelled",
                replayed=resolution.replayed,
                delivered_monotonic_ns=None,
                delivered_boot_id=None,
                delivery_ack_digest=None,
                archive_written=False,
                index_current=True,
                diary_pending=False,
                derivative_gap_code=None,
                episode=resolution.episode,
            )
        archived = self._archive_resolution(resolution)
        if resolution.replayed:
            self._pending_profile_requests.pop(delivery_token, None)
            return archived
        try:
            assert resolution.complete_turn is not None
            self._commit_staged_profile_request(
                delivery_token, resolution.complete_turn
            )
        except (OwnerProfileError, EpisodicMemoryError) as exc:
            return replace(
                archived,
                derivative_gap_code=getattr(
                    exc, "code", "profile_state_commit_unavailable"
                ),
            )
        return archived

    def _archive_resolution(self, resolution: DeliveryResolution) -> MemoryDeliveryOutcome:
        if (
            resolution.outcome != "delivered"
            or resolution.delivery_ack_digest is None
            or resolution.complete_turn is None
            or resolution.episode.state
            not in {"CLOSED_EXACT", "CLOSED_TIME_UNRESOLVED"}
        ):
            raise EpisodicMemoryError("memory_delivery_resolution_invalid")
        turn = resolution.complete_turn
        if resolution.replayed:
            return MemoryDeliveryOutcome(
                outcome="delivered",
                replayed=True,
                delivered_monotonic_ns=resolution.delivered_monotonic_ns,
                delivered_boot_id=resolution.delivered_boot_id,
                delivery_ack_digest=resolution.delivery_ack_digest,
                archive_written=True,
                index_current=False,
                diary_pending=False,
                derivative_gap_code=None,
                episode=resolution.episode,
            )
        derivative_gap = None
        index_current = False
        try:
            temporal_snapshot = self._rebind_temporal_archive_head(
                turns=resolution.archive_turns,
                archive_head_digest=turn.turn_digest,
            )
            recover_or_write_snapshot(
                self.index_path,
                resolution.archive_turns,
                archive_id=self.selection.archive_id,
                corrections=resolution.time_corrections,
                temporal_snapshot=temporal_snapshot,
                owner_day_policy=self._owner_day_policy,
            )
            index_current = True
        except EpisodicMemoryError as exc:
            derivative_gap = exc.code
        except OSError:
            derivative_gap = "temporal_interval_index_write_unavailable"
        return MemoryDeliveryOutcome(
            outcome="delivered",
            replayed=resolution.replayed,
            delivered_monotonic_ns=resolution.delivered_monotonic_ns,
            delivered_boot_id=resolution.delivered_boot_id,
            delivery_ack_digest=resolution.delivery_ack_digest,
            archive_written=True,
            index_current=index_current,
            diary_pending=False,
            derivative_gap_code=derivative_gap,
            episode=resolution.episode,
        )

    def rebuild_derivatives(self) -> dict[str, object]:
        """Explicitly rebuild derivative closure from detached accepted facts."""

        self._verify_permissions()
        turns = self.archive.turns()
        corrections = self.archive.time_corrections()
        metadata = self.archive.metadata()
        temporal_snapshot = self._rebind_temporal_archive_head(
            turns=turns,
            archive_head_digest=str(metadata["head_digest"]),
        )
        recovered = recover_or_write_snapshot(
            self.index_path,
            turns,
            archive_id=self.selection.archive_id,
            corrections=corrections,
            temporal_snapshot=temporal_snapshot,
            owner_day_policy=self._owner_day_policy,
            explicit_rebuild=True,
        )
        snapshot = read_snapshot(self.index_path)
        verify_snapshot(
            snapshot,
            turns,
            archive_id=self.selection.archive_id,
            corrections=corrections,
            temporal_snapshot=temporal_snapshot,
            owner_day_policy=self._owner_day_policy,
        )
        diary_closure = self.diary.verify_source_closure(snapshot)
        return {
            "archive_head_digest": snapshot.archive_head_digest,
            "archive_turn_count": snapshot.archive_turn_count,
            "diary": self.diary.audit_projection() | diary_closure,
            "index_sidecar_recovered": recovered,
            "source_closure_digest": snapshot.source_closure_digest,
            "snapshot_digest": snapshot.snapshot_digest,
            "temporal_snapshot_digest": snapshot.temporal_snapshot_digest,
        }

    def audit_projection(self) -> dict[str, object]:
        self._verify_permissions()
        archive = self.archive.metadata()
        journal = self.journal.metadata()
        diary = self.diary.audit_projection() | {
            "owner_day_policy_digest": self._owner_day_policy.policy_digest,
            "selected": self.owner_day_diary is not None,
            "source_contract_capable": True,
            "timer_capable": False,
            "worker_capable": False,
        }
        snapshot = read_snapshot(self.index_path)
        temporal_snapshot = self.temporal_index.read(
            archive_head_digest=str(archive["head_digest"]),
            initial_event_sequence=self.selection.p08_lifecycle_start_watermark,
        )
        return {
            "archive": archive,
            "delivery": journal,
            "diary": diary,
            "index": snapshot.audit_projection(),
            "temporal_interval_index": temporal_snapshot.audit_projection(),
            "no_old_data_migration": True,
            "selection": self.selection.audit_projection(),
            "summary_used": False,
        }
