"""Content-free P16 fault taxonomy and deterministic diagnostic projection."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping
import re

from fault_incident_v1 import incident_ref_for_request, validate_incident_ref


SNAPSHOT_SCHEMA = "myuna.diagnostics.snapshot.v1"
OUTPUT_SCHEMA = "myuna.diagnostics.v1"
AUDIT_NAMESPACE = "fault_diagnosis_v1"

_CHANNELS = frozenset({"all", "qq", "telegram"})
_EVIDENCE_CLASSES = frozenset(
    {"verified_live", "source_only", "historical", "unknown"}
)
_STATES = frozenset({"ok", "unknown", "degraded", "failed"})
_GATES = frozenset({"T0", "T2", "T3"})
_TARGETS = frozenset(
    {
        "core",
        "deepseek_budget",
        "local_provider",
        "provider",
        "profile_reader",
        "profile_writer",
        "qq_gateway",
        "qq_session",
        "release",
        "telegram_gateway",
        "telegram_recovery",
        "telegram_session",
        "temporal_context",
    }
)


@dataclass(frozen=True, slots=True)
class FaultProfile:
    layer: str
    state: str
    retryable: bool
    owner_action_required: bool
    recovery_gate: str

    def __post_init__(self) -> None:
        if self.state not in _STATES or self.recovery_gate not in _GATES:
            raise ValueError("fault profile is invalid")


def _profile(
    layer: str,
    state: str,
    retryable: bool,
    owner_action_required: bool,
    recovery_gate: str,
) -> FaultProfile:
    return FaultProfile(
        layer,
        state,
        retryable,
        owner_action_required,
        recovery_gate,
    )


FAULT_PROFILES = {
    "active": _profile("service", "ok", False, False, "T0"),
    "listening": _profile("socket", "ok", False, False, "T0"),
    "secure": _profile("storage", "ok", False, False, "T0"),
    "match": _profile("drift", "ok", False, False, "T0"),
    "current": _profile("budget", "ok", False, False, "T0"),
    "service_inactive": _profile("service", "failed", True, True, "T2"),
    "socket_inactive": _profile("socket", "failed", True, True, "T2"),
    "ingress_rejected": _profile("channel_ingress", "failed", False, True, "T2"),
    "identity_rejected": _profile("identity", "failed", False, True, "T2"),
    "duplicate_suppressed": _profile("dedupe", "degraded", False, False, "T0"),
    "rate_limited": _profile("gateway", "degraded", True, False, "T0"),
    "session_unavailable": _profile("session", "failed", False, True, "T3"),
    "session_capacity_128": _profile("session_capacity", "ok", False, False, "T0"),
    "session_capacity_mismatch": _profile(
        "session_capacity", "failed", False, True, "T2"
    ),
    "core_unreachable": _profile("gateway_core", "failed", True, True, "T2"),
    "core_invalid_response": _profile("gateway_core", "failed", True, True, "T2"),
    "core_runtime_not_ready": _profile("core", "failed", False, True, "T2"),
    "core_runtime_fail_closed": _profile("core", "failed", True, True, "T2"),
    "provider_timeout": _profile("provider", "degraded", True, False, "T0"),
    "provider_unavailable": _profile("provider", "degraded", True, False, "T0"),
    "provider_auth_failed": _profile("provider", "failed", False, True, "T2"),
    "budget_exceeded": _profile("budget", "failed", False, True, "T2"),
    "budget_rollover_required": _profile("budget", "degraded", False, True, "T2"),
    "budget_accounting_failed": _profile("budget", "failed", False, True, "T3"),
    "local_model_not_ready": _profile("local_provider", "failed", False, True, "T2"),
    "local_model_readiness_unverified": _profile(
        "local_provider", "unknown", False, False, "T0"
    ),
    "local_provider_timeout": _profile("local_provider", "degraded", True, False, "T0"),
    "local_provider_busy": _profile("local_provider", "degraded", True, False, "T0"),
    "local_provider_unavailable": _profile("local_provider", "failed", True, True, "T2"),
    "local_provider_http_rejected": _profile(
        "local_provider", "failed", False, True, "T2"
    ),
    "local_provider_endpoint_rejected": _profile(
        "local_provider", "failed", False, True, "T2"
    ),
    "profile_read_unavailable": _profile("profile_reader", "degraded", True, True, "T2"),
    "profile_write_unavailable": _profile("profile_writer", "failed", True, True, "T2"),
    "candidate_duplicate": _profile("profile_writer", "degraded", False, True, "T0"),
    "candidate_conflict": _profile("profile_writer", "degraded", False, True, "T0"),
    "boundary_rejected": _profile("policy", "failed", False, True, "T0"),
    "recovery_episode_active": _profile("recovery", "degraded", True, False, "T0"),
    "recovery_state_unavailable": _profile("recovery", "degraded", True, True, "T2"),
    "config_drift": _profile("drift", "failed", False, True, "T2"),
    "release_drift": _profile("drift", "failed", False, True, "T2"),
    "permission_drift": _profile("permission", "failed", False, True, "T2"),
    "temporal_context_unavailable": _profile(
        "temporal_context", "degraded", True, True, "T3"
    ),
    "temporal_service_inactive": _profile(
        "temporal_context", "failed", True, True, "T2"
    ),
    "temporal_socket_inactive": _profile(
        "temporal_context", "failed", True, True, "T2"
    ),
    "unknown_insufficient_safe_evidence": _profile(
        "unknown", "unknown", False, True, "T0"
    ),
}

_OBSERVATION_FIELDS = frozenset({"code", "evidence_class", "target"})
_SNAPSHOT_FIELDS = frozenset(
    {"channel", "incident_ref", "observations", "observed_at", "schema"}
)
_STATE_PRIORITY = {"ok": 0, "unknown": 1, "degraded": 2, "failed": 3}
_COMMON_CODES = frozenset(
    {"active", "service_inactive", "unknown_insufficient_safe_evidence"}
)
_TARGET_CODE_ALLOWLIST = {
    "core": _COMMON_CODES
    | {
        "listening",
        "socket_inactive",
        "core_runtime_not_ready",
        "core_runtime_fail_closed",
    },
    "deepseek_budget": {
        "current",
        "budget_exceeded",
        "budget_rollover_required",
        "budget_accounting_failed",
        "unknown_insufficient_safe_evidence",
    },
    "local_provider": _COMMON_CODES
    | {
        "listening",
        "socket_inactive",
        "local_model_not_ready",
        "local_model_readiness_unverified",
        "local_provider_timeout",
        "local_provider_busy",
        "local_provider_unavailable",
        "local_provider_http_rejected",
        "local_provider_endpoint_rejected",
    },
    "provider": _COMMON_CODES
    | {
        "provider_timeout",
        "provider_unavailable",
        "provider_auth_failed",
    },
    "profile_reader": _COMMON_CODES
    | {"listening", "socket_inactive", "profile_read_unavailable"},
    "profile_writer": _COMMON_CODES
    | {
        "listening",
        "socket_inactive",
        "profile_write_unavailable",
        "candidate_duplicate",
        "candidate_conflict",
        "boundary_rejected",
    },
    "qq_gateway": _COMMON_CODES
    | {
        "listening",
        "socket_inactive",
        "ingress_rejected",
        "identity_rejected",
        "duplicate_suppressed",
        "rate_limited",
        "core_unreachable",
        "core_invalid_response",
    },
    "telegram_gateway": _COMMON_CODES
    | {
        "listening",
        "socket_inactive",
        "ingress_rejected",
        "identity_rejected",
        "duplicate_suppressed",
        "rate_limited",
        "core_unreachable",
        "core_invalid_response",
    },
    "qq_session": {
        "secure",
        "session_capacity_128",
        "session_capacity_mismatch",
        "session_unavailable",
        "unknown_insufficient_safe_evidence",
    },
    "telegram_session": {
        "secure",
        "session_capacity_128",
        "session_capacity_mismatch",
        "session_unavailable",
        "unknown_insufficient_safe_evidence",
    },
    "telegram_recovery": _COMMON_CODES
    | {"recovery_episode_active", "recovery_state_unavailable"},
    "temporal_context": {
        "active",
        "listening",
        "temporal_context_unavailable",
        "temporal_service_inactive",
        "temporal_socket_inactive",
        "unknown_insufficient_safe_evidence",
    },
    "release": {
        "match",
        "config_drift",
        "release_drift",
        "permission_drift",
        "unknown_insufficient_safe_evidence",
    },
}


def _timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("observed_at is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observed_at is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("observed_at is invalid")
    return (
        parsed.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _incident(value: object) -> str | None:
    if value is None:
        return None
    return validate_incident_ref(value)


def build_diagnostic_report(snapshot: object) -> dict[str, object]:
    if not isinstance(snapshot, Mapping) or set(snapshot) != _SNAPSHOT_FIELDS:
        raise ValueError("diagnostic snapshot is invalid")
    if snapshot.get("schema") != SNAPSHOT_SCHEMA:
        raise ValueError("diagnostic snapshot is invalid")
    channel = snapshot.get("channel")
    if channel not in _CHANNELS:
        raise ValueError("diagnostic channel is invalid")
    observed_at = _timestamp(snapshot.get("observed_at"))
    incident_ref = _incident(snapshot.get("incident_ref"))
    observations = snapshot.get("observations")
    if not isinstance(observations, list) or not 1 <= len(observations) <= 64:
        raise ValueError("diagnostic observations are invalid")

    findings: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for observation in observations:
        if not isinstance(observation, Mapping) or set(observation) != _OBSERVATION_FIELDS:
            raise ValueError("diagnostic observation is invalid")
        target = observation.get("target")
        code = observation.get("code")
        evidence_class = observation.get("evidence_class")
        if target not in _TARGETS or code not in FAULT_PROFILES:
            raise ValueError("diagnostic observation is invalid")
        if code not in _TARGET_CODE_ALLOWLIST[str(target)]:
            raise ValueError("diagnostic target and code do not match")
        if evidence_class not in _EVIDENCE_CLASSES:
            raise ValueError("diagnostic observation is invalid")
        identity = (str(target), str(code))
        if identity in seen:
            raise ValueError("diagnostic observation is duplicated")
        seen.add(identity)
        profile = FAULT_PROFILES[str(code)]
        findings.append(
            {
                "target": target,
                "layer": profile.layer,
                "code": code,
                "state": profile.state,
                "evidence_class": evidence_class,
                "retryable": profile.retryable,
                "owner_action_required": profile.owner_action_required,
                "recovery_gate": profile.recovery_gate,
            }
        )

    findings.sort(key=lambda item: (str(item["target"]), str(item["code"])))
    overall = max(
        (str(item["state"]) for item in findings),
        key=_STATE_PRIORITY.__getitem__,
    )
    state_counts = Counter(str(item["state"]) for item in findings)
    return {
        "schema": OUTPUT_SCHEMA,
        "observed_at": observed_at,
        "channel": channel,
        "incident_ref": incident_ref,
        "overall": overall,
        "findings": findings,
        "checks_prohibited": [
            "channel_call",
            "core_health_endpoint",
            "model_or_provider_call",
            "private_or_secret_read",
            "raw_log_read",
            "service_or_state_mutation",
        ],
        "audit_projection": {
            "event_namespace": AUDIT_NAMESPACE,
            "outcome": overall,
            "finding_count": len(findings),
            "finding_state_counts": dict(sorted(state_counts.items())),
            "incident_ref_present": incident_ref is not None,
            "private_content_read": False,
            "raw_log_read": False,
            "model_called": False,
            "channel_called": False,
            "provider_called": False,
            "state_changed": False,
        },
    }
