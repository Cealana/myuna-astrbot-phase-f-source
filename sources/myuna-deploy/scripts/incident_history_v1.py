"""Bounded, content-free incident occurrence history for P16.

This module is source-only and is not wired into a live gateway.  It stores a
strict digest chain of typed observations and rolls old entries into a bounded
content-free manifest.  It never accepts arbitrary diagnostic text.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping

from gateway_degradation_protocol import (
    CORE_FAILURE_PROVENANCE_SCHEMA,
    validate_core_failure_provenance,
    validate_safe_degradation,
)
from user_visible_fault_v1 import PUBLIC_FAULTS


EVIDENCE_SCHEMA_V1 = "myuna.incident-occurrence-evidence.v1"
EVIDENCE_SCHEMA = "myuna.incident-occurrence-evidence.v2"
OCCURRENCE_SCHEMA_V1 = "myuna.incident-occurrence.v1"
OCCURRENCE_SCHEMA = "myuna.incident-occurrence.v2"
HISTORY_SCHEMA = "myuna.incident-history.v1"
ROLLUP_SCHEMA = "myuna.incident-history-rollup.v1"
PROBLEM_ATTACHMENT_SCHEMA = "myuna.incident-problem-attachment.v1"
STATE_FILENAME = "history-v1.json"
LOCK_FILENAME = ".append.lock"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_INCIDENT_REF = re.compile(r"^(?:inc-[0-9a-f]{12}|inc1-[0-9a-f]{32})$")
_PUBLIC_CODE = re.compile(r"^MYU-[A-Z][A-Z0-9]*-[0-9]{2}$")
_SAFE_TOKEN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_SOURCE_FINGERPRINT = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,383}$")
_CHANNELS = frozenset({"telegram", "qq"})
_TRUSTED_TIME = frozenset({"trusted", "untrusted", "unavailable"})
_LATENCY = frozenset({"lt5s", "5to29s", "30to59s", "gte60s", "unknown"})
_HTTP_OUTCOME = frozenset({"2xx", "4xx", "5xx", "none", "unknown"})
_SERVICE = frozenset({"active_stable", "active_degraded", "inactive", "unknown"})
_RESTART = frozenset({"none_observed", "restart_observed", "unknown"})
_PERSONA_GROUNDING = frozenset(
    {
        "external_operation",
        "not_evaluated",
        "real_world_observation",
        "soft_persona_daily_life",
        "unknown",
        "unscoped",
    }
)
_PROVIDER_OUTCOME = frozenset(
    {
        "authentication_failed",
        "budget_failure",
        "error",
        "invalid_response",
        "not_called",
        "rate_limited",
        "request_rejected",
        "timeout",
        "transport_failure",
        "unknown",
        "upstream_failure",
    }
)
_CATEGORIES = frozenset(
    {
        "reply_contract_rejected",
        "provider_transient_failure",
        "provider_budget_or_auth_failure",
        "core_or_gateway_failure",
        "memory_service_failure",
        "onebot_or_napcat_offline",
        "host_or_network_unreachable",
        "scheduled_notification_unavailable",
        "memory_write_unavailable",
        "external_data_unavailable",
        "vision_unavailable",
        "external_action_unavailable",
        "unknown",
    }
)

# Frozen mappings only. An unrecognized safe detail is retained as unknown and
# never promoted into a new typed gate or fingerprint.
_TYPED_DETAILS: dict[str, tuple[str, str, str]] = {
    "provider-transport-failure": ("provider", "provider_request", "transport_failure"),
    "provider-rate-limited": ("provider", "provider_request", "rate_limited"),
    "provider-upstream-failure": ("provider", "provider_request", "upstream_failure"),
    "provider-invalid-response": ("provider", "provider_response", "invalid_response"),
    "provider-request-rejected": ("provider", "provider_request", "request_rejected"),
    "provider-authentication-failed": ("provider", "provider_request", "authentication_failed"),
    "provider-insufficient-balance": ("budget", "provider_request", "insufficient_balance"),
    "provider-daily-budget-exceeded": ("budget", "core_pre_provider", "daily_budget_exceeded"),
    "provider-budget-accounting-failed": (
        "budget",
        "core_pre_provider",
        "budget_accounting_failed",
    ),
    "local-provider-timeout": ("local_model", "provider_request", "local_timeout"),
    "local-provider-busy": ("local_model", "provider_request", "local_busy"),
    "local-model-not-ready": ("local_model", "provider_readiness", "model_not_ready"),
    "local-provider-unavailable": ("local_model", "provider_request", "local_unavailable"),
    "local-provider-http-rejected": ("local_model", "provider_response", "http_rejected"),
    "local-provider-endpoint-rejected": ("local_model", "provider_request", "endpoint_rejected"),
    "reply-contract-rejected": ("core", "output_repair", "reply_contract_rejected"),
    "reply-runtime-guard-rejected": (
        "core",
        "output_repair",
        "reply_runtime_guard_rejected",
    ),
    "core-request-rejected": ("core", "request_parser", "invalid_conversation_request"),
    "owner-memory-read-failed": (
        "profile_reader",
        "profile_projection",
        "profile_reader_fail_closed",
    ),
    "core-runtime-not-ready": ("core", "core_readiness", "core_not_ready"),
    "gateway-core-unreachable": ("channel_gateway", "core_transport", "core_unavailable"),
    "gateway-core-invalid-response": ("channel_gateway", "core_response", "core_invalid_response"),
    "gateway-owner-rate-limited": ("channel_gateway", "entry_guard", "rate_limited"),
    "gateway-temporal-unavailable": ("session", "temporal_context", "temporal_unavailable"),
}
_CORE_PRE_PROVIDER_FAILURE_GATES = frozenset(
    {
        "core_pre_provider_unknown",
        "credential_material_excluded",
        "definition_digest_mismatch",
        "definition_out_of_contract",
        "egress_safety_unavailable",
        "external_profile_egress_rejected",
        "forwarded_private_content_excluded",
        "generation_timeout_out_of_contract",
        "profile_context_characters_exceeded",
        "profile_section_count_exceeded",
        "profile_state_out_of_contract",
        "projection_byte_budget_exceeded",
        "projection_character_budget_exceeded",
        "projection_token_budget_exceeded",
        "recent_turn_characters_exceeded",
        "third_party_private_content_excluded",
        "token_capacity_oracle_unavailable",
    }
)
_TYPED_TRIPLES = (
    frozenset(_TYPED_DETAILS.values())
    | frozenset(
        {
            ("core", "core_pre_provider", "core_pre_provider_fail_closed"),
            ("core", "core_runtime", "core_runtime_fail_closed"),
            ("unknown", "unknown", "unknown"),
        }
    )
    | frozenset(
        ("core", "core_pre_provider", gate)
        for gate in _CORE_PRE_PROVIDER_FAILURE_GATES
    )
)

_EVIDENCE_FIELDS_V1 = frozenset(
    {
        "schema",
        "observed_at",
        "trusted_time_status",
        "channel",
        "release_set_id_status",
        "release_set_id",
        "category",
        "stage",
        "typed_namespace",
        "typed_gate",
        "latency_bucket",
        "http_outcome_class",
        "provider_outcome_class",
        "retryable",
        "provider_called",
        "model_called",
        "profile_called",
        "memory_called",
        "tool_called",
        "service_observation_class",
        "restart_observation_class",
        "epoch_revision_delta",
        "turn_delta",
        "summary_delta",
        "pending_after",
        "delivery_delta",
        "incident_ref_status",
        "incident_ref",
        "public_code_status",
        "public_code",
        "fingerprint_status",
        "fingerprint_digest",
    }
)
_EVIDENCE_FIELDS = _EVIDENCE_FIELDS_V1 | frozenset(
    {"attempt_count", "persona_grounding_class", "output_guard_applied"}
)
_OCCURRENCE_FIELDS_V1 = _EVIDENCE_FIELDS_V1 | frozenset(
    {"sequence", "event_digest", "previous_event_digest", "occurrence_digest"}
)
_OCCURRENCE_FIELDS = _EVIDENCE_FIELDS | frozenset(
    {"sequence", "event_digest", "previous_event_digest", "occurrence_digest"}
)


class IncidentHistoryRejected(RuntimeError):
    """Raised when content-free history cannot be proven safe to read/write."""


def _canonical(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest(domain: str, payload: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + _canonical(payload)).hexdigest()


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("observed_at must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _optional_bool(value: object, label: str) -> bool | None:
    if value is None or type(value) is bool:
        return value
    raise TypeError(f"{label} must be boolean or null")


def _optional_delta(value: object, label: str, *, nonnegative: bool = False) -> int | None:
    if value is None:
        return None
    if type(value) is not int:
        raise TypeError(f"{label} must be integer or null")
    lower = 0 if nonnegative else -1_000_000
    if value < lower or value > 1_000_000:
        raise ValueError(f"{label} is out of range")
    return value


def _available(value: str | None) -> str:
    return "available" if value is not None else "unavailable"


@dataclass(frozen=True, slots=True)
class IncidentEvidence:
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        canonical = dict(self.payload)
        schema = canonical.get("schema")
        expected = _EVIDENCE_FIELDS_V1 if schema == EVIDENCE_SCHEMA_V1 else _EVIDENCE_FIELDS
        if set(canonical) != expected:
            raise ValueError("incident evidence fields are invalid")
        _validate_evidence_payload(canonical)
        object.__setattr__(self, "payload", canonical)

    def as_payload(self) -> dict[str, object]:
        return dict(self.payload)

    @property
    def event_digest(self) -> str:
        domain = (
            "myuna-incident-event-v1"
            if self.payload["schema"] == EVIDENCE_SCHEMA_V1
            else "myuna-incident-event-v2"
        )
        return _digest(domain, self.payload)


@dataclass(frozen=True, slots=True)
class AppendOutcome:
    status: str
    occurrence_digest: str


def _typed_projection(
    projection: object,
    *,
    provider_called: bool | None,
    http_outcome_class: str,
) -> tuple[str, str, str, str, bool | None, str, str | None]:
    if projection is None:
        return "unknown", "unknown", "unknown", "unknown", None, "unavailable", None
    validated = validate_safe_degradation(projection)
    category = str(validated["category"])
    retryable = validated["retryable"]
    detail = str(validated["safe_detail_code"])

    typed = _TYPED_DETAILS.get(detail)
    if detail == "core-runtime-fail-closed":
        if provider_called is False and http_outcome_class == "5xx":
            typed = ("core", "core_pre_provider", "core_pre_provider_fail_closed")
        else:
            typed = ("core", "core_runtime", "core_runtime_fail_closed")
    if typed is None:
        return category, "unknown", "unknown", "unknown", retryable, "unavailable", None

    fingerprint = validated["fingerprint"]
    if (
        not isinstance(fingerprint, str)
        or _SAFE_SOURCE_FINGERPRINT.fullmatch(fingerprint) is None
    ):
        raise ValueError("projection fingerprint is invalid")
    fingerprint_status = "available"
    fingerprint_digest = _digest(
        "myuna-incident-fingerprint-v1",
        {
            "source_fingerprint": fingerprint,
            "stage": typed[1],
            "typed_namespace": typed[0],
            "typed_gate": typed[2],
        },
    )
    return category, typed[1], typed[0], typed[2], retryable, fingerprint_status, fingerprint_digest


def build_incident_evidence(
    projection: object,
    *,
    observed_at: datetime,
    trusted_time_status: str,
    channel: str,
    release_set_id: str | None,
    incident_ref: str | None,
    public_code: str | None,
    latency_bucket: str,
    http_outcome_class: str,
    provider_called: bool | None,
    model_called: bool | None,
    profile_called: bool | None,
    memory_called: bool | None,
    tool_called: bool | None,
    service_observation_class: str,
    restart_observation_class: str,
    epoch_revision_delta: int | None,
    turn_delta: int | None,
    summary_delta: int | None,
    pending_after: int | None,
    delivery_delta: int | None,
    failure_provenance: object | None = None,
) -> IncidentEvidence:
    if trusted_time_status not in _TRUSTED_TIME:
        raise ValueError("trusted time status is invalid")
    if channel not in _CHANNELS:
        raise ValueError("channel is invalid")
    if latency_bucket not in _LATENCY:
        raise ValueError("latency bucket is invalid")
    if http_outcome_class not in _HTTP_OUTCOME:
        raise ValueError("HTTP outcome class is invalid")
    if service_observation_class not in _SERVICE:
        raise ValueError("service observation class is invalid")
    if restart_observation_class not in _RESTART:
        raise ValueError("restart observation class is invalid")
    if release_set_id is not None and (
        not isinstance(release_set_id, str) or _HEX64.fullmatch(release_set_id) is None
    ):
        raise ValueError("release_set_id is invalid")
    if incident_ref is not None and (
        not isinstance(incident_ref, str) or _INCIDENT_REF.fullmatch(incident_ref) is None
    ):
        raise ValueError("incident_ref is invalid")
    if public_code is not None and (
        not isinstance(public_code, str)
        or _PUBLIC_CODE.fullmatch(public_code) is None
        or public_code not in PUBLIC_FAULTS
    ):
        raise ValueError("public code is invalid")

    provider_called_value = _optional_bool(provider_called, "provider_called")
    category, stage, namespace, gate, retryable, fingerprint_status, fingerprint = (
        _typed_projection(
            projection,
            provider_called=provider_called_value,
            http_outcome_class=http_outcome_class,
        )
    )
    if failure_provenance is not None:
        provenance = validate_core_failure_provenance(failure_provenance)
        if (
            stage != "unknown"
            and provenance["stage"] != "unknown"
            and provenance["stage"] != stage
        ):
            raise ValueError("failure provenance stage contradicts typed projection")
        provider_called_value = provenance["provider_called"]
        provider_outcome = str(provenance["provider_outcome_class"])
        attempt_count = provenance["attempt_count"]
        model_called = provenance["model_called"]
        profile_called = provenance["profile_called"]
        memory_called = provenance["memory_called"]
        tool_called = provenance["tool_called"]
        persona_grounding_class = str(provenance["persona_grounding_class"])
        output_guard_applied = provenance["output_guard_applied"]
        if (
            provenance["schema"] == CORE_FAILURE_PROVENANCE_SCHEMA
            and stage == "core_pre_provider"
            and gate == "core_pre_provider_fail_closed"
        ):
            failure_gate = provenance["failure_gate"]
            if failure_gate not in _CORE_PRE_PROVIDER_FAILURE_GATES:
                raise ValueError("pre-provider failure gate is not frozen")
            gate = str(failure_gate)
            source_projection = validate_safe_degradation(projection)
            fingerprint = _digest(
                "myuna-incident-fingerprint-v1",
                {
                    "source_fingerprint": source_projection["fingerprint"],
                    "stage": stage,
                    "typed_namespace": namespace,
                    "typed_gate": gate,
                },
            )
    elif provider_called_value is False:
        provider_outcome = "not_called"
        attempt_count = None
        persona_grounding_class = "unknown"
        output_guard_applied = None
    elif gate == "transport_failure":
        provider_outcome = "transport_failure"
        attempt_count = None
        persona_grounding_class = "unknown"
        output_guard_applied = None
    elif gate == "rate_limited":
        provider_outcome = "rate_limited"
        attempt_count = None
        persona_grounding_class = "unknown"
        output_guard_applied = None
    elif namespace in {"provider", "local_model"} and provider_called_value is True:
        provider_outcome = "error"
        attempt_count = None
        persona_grounding_class = "unknown"
        output_guard_applied = None
    else:
        provider_outcome = "unknown"
        attempt_count = None
        persona_grounding_class = "unknown"
        output_guard_applied = None

    return IncidentEvidence(
        {
            "schema": EVIDENCE_SCHEMA,
            "observed_at": _utc(observed_at),
            "trusted_time_status": trusted_time_status,
            "channel": channel,
            "release_set_id_status": _available(release_set_id),
            "release_set_id": release_set_id,
            "category": category,
            "stage": stage,
            "typed_namespace": namespace,
            "typed_gate": gate,
            "latency_bucket": latency_bucket,
            "http_outcome_class": http_outcome_class,
            "provider_outcome_class": provider_outcome,
            "attempt_count": attempt_count,
            "retryable": retryable,
            "provider_called": provider_called_value,
            "model_called": _optional_bool(model_called, "model_called"),
            "profile_called": _optional_bool(profile_called, "profile_called"),
            "memory_called": _optional_bool(memory_called, "memory_called"),
            "tool_called": _optional_bool(tool_called, "tool_called"),
            "persona_grounding_class": persona_grounding_class,
            "output_guard_applied": _optional_bool(
                output_guard_applied, "output_guard_applied"
            ),
            "service_observation_class": service_observation_class,
            "restart_observation_class": restart_observation_class,
            "epoch_revision_delta": _optional_delta(epoch_revision_delta, "epoch_revision_delta"),
            "turn_delta": _optional_delta(turn_delta, "turn_delta"),
            "summary_delta": _optional_delta(summary_delta, "summary_delta"),
            "pending_after": _optional_delta(pending_after, "pending_after", nonnegative=True),
            "delivery_delta": _optional_delta(delivery_delta, "delivery_delta"),
            "incident_ref_status": _available(incident_ref),
            "incident_ref": incident_ref,
            "public_code_status": _available(public_code),
            "public_code": public_code,
            "fingerprint_status": fingerprint_status,
            "fingerprint_digest": fingerprint,
        }
    )


def _validate_evidence_payload(payload: Mapping[str, object]) -> None:
    schema = payload.get("schema")
    if schema not in {EVIDENCE_SCHEMA_V1, EVIDENCE_SCHEMA}:
        raise ValueError("incident evidence schema is invalid")
    observed_at = payload["observed_at"]
    if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
        raise ValueError("observed_at is invalid")
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("observed_at is not UTC")
    if payload["trusted_time_status"] not in _TRUSTED_TIME:
        raise ValueError("trusted time status is invalid")
    if payload["channel"] not in _CHANNELS:
        raise ValueError("channel is invalid")
    for field in ("stage", "typed_namespace", "typed_gate", "provider_outcome_class"):
        value = payload[field]
        if not isinstance(value, str) or _SAFE_TOKEN.fullmatch(value) is None:
            raise ValueError(f"{field} is invalid")
    if (
        payload["typed_namespace"],
        payload["stage"],
        payload["typed_gate"],
    ) not in _TYPED_TRIPLES:
        raise ValueError("typed provenance is not frozen")
    if payload["category"] not in _CATEGORIES:
        raise ValueError("category is invalid")
    if payload["latency_bucket"] not in _LATENCY:
        raise ValueError("latency bucket is invalid")
    if payload["http_outcome_class"] not in _HTTP_OUTCOME:
        raise ValueError("HTTP outcome class is invalid")
    if payload["provider_outcome_class"] not in _PROVIDER_OUTCOME:
        raise ValueError("provider outcome class is invalid")
    if schema == EVIDENCE_SCHEMA:
        attempts = payload["attempt_count"]
        if attempts is not None and (
            type(attempts) is not int or not 0 <= attempts <= 16
        ):
            raise ValueError("attempt count is invalid")
        if payload["persona_grounding_class"] not in _PERSONA_GROUNDING:
            raise ValueError("persona grounding class is invalid")
        _optional_bool(payload["output_guard_applied"], "output_guard_applied")
    if payload["retryable"] is not None and type(payload["retryable"]) is not bool:
        raise TypeError("retryable is invalid")
    for field in (
        "provider_called",
        "model_called",
        "profile_called",
        "memory_called",
        "tool_called",
    ):
        _optional_bool(payload[field], field)
    if payload["provider_called"] is False and payload["provider_outcome_class"] != "not_called":
        raise ValueError("provider outcome contradicts called evidence")
    if payload["provider_called"] is True and payload["provider_outcome_class"] == "not_called":
        raise ValueError("provider outcome contradicts called evidence")
    if payload["model_called"] is True and payload["provider_called"] is not True:
        raise ValueError("model call lacks provider call evidence")
    if schema == EVIDENCE_SCHEMA and payload["provider_called"] is False:
        if payload["attempt_count"] not in {None, 0}:
            raise ValueError("attempt count contradicts provider call evidence")
        if payload["output_guard_applied"] is True:
            raise ValueError("output guard lacks provider output evidence")
    if payload["service_observation_class"] not in _SERVICE:
        raise ValueError("service observation class is invalid")
    if payload["restart_observation_class"] not in _RESTART:
        raise ValueError("restart observation class is invalid")
    for field in (
        "epoch_revision_delta",
        "turn_delta",
        "summary_delta",
        "delivery_delta",
    ):
        _optional_delta(payload[field], field)
    _optional_delta(payload["pending_after"], "pending_after", nonnegative=True)
    for status_field, value_field, validator in (
        ("release_set_id_status", "release_set_id", _HEX64),
        ("incident_ref_status", "incident_ref", _INCIDENT_REF),
        ("public_code_status", "public_code", _PUBLIC_CODE),
        ("fingerprint_status", "fingerprint_digest", _HEX64),
    ):
        status_value = payload[status_field]
        value = payload[value_field]
        if status_value == "available":
            if not isinstance(value, str) or validator.fullmatch(value) is None:
                raise ValueError(f"{value_field} is invalid")
        elif status_value != "unavailable" or value is not None:
            raise ValueError(f"{status_field} is invalid")


def _empty_rollup() -> dict[str, object]:
    return {
        "schema": ROLLUP_SCHEMA,
        "occurrence_count": 0,
        "first_observed_at": None,
        "last_observed_at": None,
        "terminal_occurrence_digest": None,
        "summary_digest": None,
    }


class IncidentHistoryStore:
    def __init__(self, root: Path, *, capacity: int = 128) -> None:
        self.root = Path(root)
        if type(capacity) is not int or capacity < 1 or capacity > 4096:
            raise ValueError("history capacity is invalid")
        self.capacity = capacity

    @property
    def state_path(self) -> Path:
        return self.root / STATE_FILENAME

    def _validate_root(self, *, allow_lock: bool) -> None:
        try:
            root_stat = self.root.lstat()
        except OSError as exc:
            raise IncidentHistoryRejected("history root is unavailable") from exc
        if (
            not self.root.is_absolute()
            or not stat.S_ISDIR(root_stat.st_mode)
            or self.root.is_symlink()
        ):
            raise IncidentHistoryRejected("history root is invalid")
        if (
            root_stat.st_uid != os.geteuid()
            or stat.S_IMODE(root_stat.st_mode) & 0o022
        ):
            raise IncidentHistoryRejected("history root permissions are invalid")
        allowed = {STATE_FILENAME}
        if allow_lock:
            allowed.add(LOCK_FILENAME)
        try:
            names = {entry.name for entry in self.root.iterdir()}
        except OSError as exc:
            raise IncidentHistoryRejected("history root is unreadable") from exc
        if not names.issubset(allowed):
            raise IncidentHistoryRejected("history root contains an uncommitted artifact")

    def _empty_state(self) -> dict[str, object]:
        state: dict[str, object] = {
            "schema": HISTORY_SCHEMA,
            "capacity": self.capacity,
            "next_sequence": 1,
            "rollup": _empty_rollup(),
            "occurrences": [],
        }
        state["state_digest"] = _digest("myuna-incident-history-state-v1", state)
        return state

    def _load(self, *, allow_lock: bool = False) -> dict[str, object]:
        self._validate_root(allow_lock=allow_lock)
        if not self.state_path.exists() and not self.state_path.is_symlink():
            return self._empty_state()
        try:
            path_stat = self.state_path.lstat()
            if (
                not stat.S_ISREG(path_stat.st_mode)
                or self.state_path.is_symlink()
                or path_stat.st_uid != os.geteuid()
                or stat.S_IMODE(path_stat.st_mode) != 0o640
            ):
                raise IncidentHistoryRejected("history state type or permissions drifted")
            raw = self.state_path.read_bytes()
            if len(raw) > 8_000_000 or not raw.endswith(b"\n"):
                raise IncidentHistoryRejected("history state framing is invalid")
            state = json.loads(raw.decode("ascii"))
        except IncidentHistoryRejected:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise IncidentHistoryRejected("history state is unreadable") from exc
        self._validate_state(state)
        return state

    def _validate_state(self, state: object) -> None:
        if not isinstance(state, dict) or set(state) != {
            "schema",
            "capacity",
            "next_sequence",
            "rollup",
            "occurrences",
            "state_digest",
        }:
            raise IncidentHistoryRejected("history state fields are invalid")
        digest = state["state_digest"]
        unsigned = {key: value for key, value in state.items() if key != "state_digest"}
        if not isinstance(digest, str) or digest != _digest(
            "myuna-incident-history-state-v1", unsigned
        ):
            raise IncidentHistoryRejected("history state digest drifted")
        if state["schema"] != HISTORY_SCHEMA or state["capacity"] != self.capacity:
            raise IncidentHistoryRejected("history state contract drifted")
        if type(state["next_sequence"]) is not int or state["next_sequence"] < 1:
            raise IncidentHistoryRejected("history sequence is invalid")
        rollup = state["rollup"]
        if not isinstance(rollup, dict) or set(rollup) != {
            "schema",
            "occurrence_count",
            "first_observed_at",
            "last_observed_at",
            "terminal_occurrence_digest",
            "summary_digest",
        } or rollup["schema"] != ROLLUP_SCHEMA:
            raise IncidentHistoryRejected("history rollup is invalid")
        if type(rollup["occurrence_count"]) is not int or rollup["occurrence_count"] < 0:
            raise IncidentHistoryRejected("history rollup count is invalid")
        if rollup["occurrence_count"] == 0:
            if any(rollup[field] is not None for field in (
                "first_observed_at",
                "last_observed_at",
                "terminal_occurrence_digest",
                "summary_digest",
            )):
                raise IncidentHistoryRejected("empty history rollup is invalid")
        else:
            for field in ("terminal_occurrence_digest", "summary_digest"):
                if not isinstance(rollup[field], str) or _HEX64.fullmatch(rollup[field]) is None:
                    raise IncidentHistoryRejected("history rollup digest is invalid")
            for field in ("first_observed_at", "last_observed_at"):
                try:
                    datetime.fromisoformat(str(rollup[field]).replace("Z", "+00:00"))
                except ValueError as exc:
                    raise IncidentHistoryRejected("history rollup time is invalid") from exc
        occurrences = state["occurrences"]
        if not isinstance(occurrences, list) or len(occurrences) > self.capacity:
            raise IncidentHistoryRejected("history occurrences are invalid")
        previous = rollup["terminal_occurrence_digest"]
        last_sequence = 0
        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                raise IncidentHistoryRejected("history occurrence fields are invalid")
            occurrence_schema = occurrence.get("schema")
            if occurrence_schema == OCCURRENCE_SCHEMA_V1:
                occurrence_fields = _OCCURRENCE_FIELDS_V1
                evidence_fields = _EVIDENCE_FIELDS_V1
                evidence_schema = EVIDENCE_SCHEMA_V1
                event_domain = "myuna-incident-event-v1"
                occurrence_domain = "myuna-incident-occurrence-v1"
            elif occurrence_schema == OCCURRENCE_SCHEMA:
                occurrence_fields = _OCCURRENCE_FIELDS
                evidence_fields = _EVIDENCE_FIELDS
                evidence_schema = EVIDENCE_SCHEMA
                event_domain = "myuna-incident-event-v2"
                occurrence_domain = "myuna-incident-occurrence-v2"
            else:
                raise IncidentHistoryRejected("history occurrence schema is invalid")
            if set(occurrence) != occurrence_fields:
                raise IncidentHistoryRejected("history occurrence fields are invalid")
            evidence_payload = {field: occurrence[field] for field in evidence_fields}
            evidence_payload["schema"] = evidence_schema
            try:
                IncidentEvidence(evidence_payload)
            except (TypeError, ValueError) as exc:
                raise IncidentHistoryRejected("history occurrence evidence is invalid") from exc
            event_digest = _digest(event_domain, evidence_payload)
            if occurrence["event_digest"] != event_digest:
                raise IncidentHistoryRejected("history event digest drifted")
            if occurrence["previous_event_digest"] != previous:
                raise IncidentHistoryRejected("history occurrence chain drifted")
            unsigned_occurrence = {
                key: value for key, value in occurrence.items() if key != "occurrence_digest"
            }
            expected = _digest(occurrence_domain, unsigned_occurrence)
            if occurrence["occurrence_digest"] != expected:
                raise IncidentHistoryRejected("history occurrence digest drifted")
            sequence = occurrence["sequence"]
            if type(sequence) is not int or sequence <= last_sequence:
                raise IncidentHistoryRejected("history occurrence sequence drifted")
            last_sequence = sequence
            previous = expected
        if last_sequence >= state["next_sequence"]:
            raise IncidentHistoryRejected("history next sequence drifted")

    def read(self) -> dict[str, object]:
        return self._load()

    def append(self, evidence: IncidentEvidence) -> AppendOutcome:
        if not isinstance(evidence, IncidentEvidence):
            raise TypeError("incident evidence is invalid")
        self._validate_root(allow_lock=False)
        lock_path = self.root / LOCK_FILENAME
        try:
            lock_fd = os.open(
                lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as exc:
            raise IncidentHistoryRejected("history append is already locked") from exc
        temporary: Path | None = None
        try:
            os.close(lock_fd)
            state = self._load(allow_lock=True)
            event_digest = evidence.event_digest
            for occurrence in state["occurrences"]:
                if occurrence["event_digest"] == event_digest:
                    return AppendOutcome("duplicate", occurrence["occurrence_digest"])
                if (
                    evidence.payload["incident_ref_status"] == "available"
                    and occurrence["incident_ref"] == evidence.payload["incident_ref"]
                ):
                    common_fields = _EVIDENCE_FIELDS_V1 - {"schema"}
                    if all(
                        occurrence[field] == evidence.payload[field]
                        for field in common_fields
                    ):
                        return AppendOutcome(
                            "duplicate", occurrence["occurrence_digest"]
                        )
                    raise IncidentHistoryRejected("incident_ref collision")
            rollup = state["rollup"]
            rolled_through = rollup["last_observed_at"]
            if rolled_through is not None and evidence.payload["observed_at"] <= rolled_through:
                raise IncidentHistoryRejected("stale occurrence cannot bypass bounded retention")

            occurrences = list(state["occurrences"])
            if len(occurrences) == self.capacity:
                oldest = occurrences.pop(0)
                prior_summary = rollup["summary_digest"]
                summary_payload = {
                    "previous_summary_digest": prior_summary,
                    "rolled_event_digest": oldest["event_digest"],
                    "rolled_occurrence_digest": oldest["occurrence_digest"],
                    "sequence": oldest["sequence"],
                }
                rollup = {
                    "schema": ROLLUP_SCHEMA,
                    "occurrence_count": rollup["occurrence_count"] + 1,
                    "first_observed_at": rollup["first_observed_at"] or oldest["observed_at"],
                    "last_observed_at": oldest["observed_at"],
                    "terminal_occurrence_digest": oldest["occurrence_digest"],
                    "summary_digest": _digest("myuna-incident-rollup-v1", summary_payload),
                }

            previous = (
                occurrences[-1]["occurrence_digest"]
                if occurrences
                else rollup["terminal_occurrence_digest"]
            )
            record = evidence.as_payload()
            is_v1 = evidence.payload["schema"] == EVIDENCE_SCHEMA_V1
            record["schema"] = OCCURRENCE_SCHEMA_V1 if is_v1 else OCCURRENCE_SCHEMA
            record.update(
                {
                    "sequence": state["next_sequence"],
                    "event_digest": event_digest,
                    "previous_event_digest": previous,
                }
            )
            record["occurrence_digest"] = _digest(
                "myuna-incident-occurrence-v1"
                if is_v1
                else "myuna-incident-occurrence-v2",
                record,
            )
            occurrences.append(record)
            next_state: dict[str, object] = {
                "schema": HISTORY_SCHEMA,
                "capacity": self.capacity,
                "next_sequence": state["next_sequence"] + 1,
                "rollup": rollup,
                "occurrences": occurrences,
            }
            next_state["state_digest"] = _digest("myuna-incident-history-state-v1", next_state)
            self._validate_state(next_state)
            temporary = self.root / f".history-v1.{os.getpid()}.tmp"
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o640,
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(_canonical(next_state) + b"\n")
                    handle.flush()
                    os.fchmod(handle.fileno(), 0o640)
                    os.fsync(handle.fileno())
                os.replace(temporary, self.state_path)
                temporary = None
                directory_fd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except BaseException:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise
            return AppendOutcome("appended", record["occurrence_digest"])
        except IncidentHistoryRejected:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise IncidentHistoryRejected("history append failed closed") from exc
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            try:
                lock_path.unlink(missing_ok=True)
            except OSError:
                pass

    def problem_attachment(self, occurrence_digest: str) -> dict[str, object]:
        if not isinstance(occurrence_digest, str) or _HEX64.fullmatch(occurrence_digest) is None:
            raise ValueError("occurrence digest is invalid")
        state = self.read()
        for occurrence in state["occurrences"]:
            if occurrence["occurrence_digest"] == occurrence_digest:
                status = occurrence["fingerprint_status"]
                return {
                    "schema": PROBLEM_ATTACHMENT_SCHEMA,
                    "occurrence_digest": occurrence_digest,
                    "fingerprint_status": status,
                    "fingerprint_digest": occurrence["fingerprint_digest"],
                    "attachment_status": "eligible" if status == "available" else "unavailable",
                }
        raise IncidentHistoryRejected("occurrence is outside active retention")
