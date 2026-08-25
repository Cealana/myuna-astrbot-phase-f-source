"""Default-off post-response adapter for P16 incident history.

The adapter accepts only fixed, validated failure provenance.  It never sees a
request, response, Profile value, log line, provider payload, or arbitrary
diagnostic detail.  Activation requires a separately reviewed root-owned
marker and a pre-provisioned per-channel history directory.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable

from degradation_shadow_enqueue import DegradationShadowJob
from gateway_degradation_protocol import validate_core_failure_provenance
from gateway_enqueue import approved_marker_enabled
from incident_history_v1 import (
    IncidentEvidence,
    IncidentHistoryRejected,
    IncidentHistoryStore,
    build_incident_evidence,
)


INCIDENT_HISTORY_MARKER = Path(
    "/etc/myuna-gateway/incident-history-v1-enabled"
)
INCIDENT_HISTORY_SELECTOR = Path(
    "/etc/myuna-gateway/incident-history-v1.selector.json"
)
INCIDENT_HISTORY_ROOT = Path("/var/lib/myuna-fault-diagnostics/incident-history-v1")
INCIDENT_HISTORY_SELECTOR_SCHEMA = "myuna.p16-incident-history-selector.v1"

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SELECTOR_BYTES = 4096
_SELECTOR_FIELDS = frozenset(
    {
        "schema",
        "status",
        "channel",
        "marker_path",
        "history_root",
        "capacity",
        "bundle_digest",
        "core_release_digest",
        "runtime_release_digest",
        "plugin_release_digest",
        "adapter_release_digest",
        "core_source_commit",
        "deploy_source_commit",
        "public_reply_contract",
        "write_boundary",
    }
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def validate_incident_history_selector(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _SELECTOR_FIELDS:
        raise ValueError("incident history selector fields are invalid")
    selector = dict(value)
    if selector["schema"] != INCIDENT_HISTORY_SELECTOR_SCHEMA:
        raise ValueError("incident history selector schema is invalid")
    if selector["status"] != "approved" or selector["channel"] != "telegram":
        raise ValueError("incident history selector scope is invalid")
    if selector["marker_path"] != str(INCIDENT_HISTORY_MARKER):
        raise ValueError("incident history selector marker is invalid")
    if selector["history_root"] != str(INCIDENT_HISTORY_ROOT):
        raise ValueError("incident history selector root is invalid")
    if selector["capacity"] != 128:
        raise ValueError("incident history selector capacity is invalid")
    for field in (
        "bundle_digest",
        "core_release_digest",
        "runtime_release_digest",
        "plugin_release_digest",
        "adapter_release_digest",
    ):
        item = selector[field]
        if not isinstance(item, str) or _HEX64.fullmatch(item) is None:
            raise ValueError(f"incident history selector {field} is invalid")
    for field in ("core_source_commit", "deploy_source_commit"):
        item = selector[field]
        if not isinstance(item, str) or _HEX40.fullmatch(item) is None:
            raise ValueError(f"incident history selector {field} is invalid")
    if selector["public_reply_contract"] != "unchanged":
        raise ValueError("incident history public reply contract is invalid")
    if selector["write_boundary"] != "post_response_failure_only":
        raise ValueError("incident history write boundary is invalid")
    return selector


def load_approved_incident_history_selector(
    path: Path = INCIDENT_HISTORY_SELECTOR,
    *,
    expected_uid: int = 0,
    expected_gid: int | None = None,
) -> dict[str, object] | None:
    """Read one canonical selector without following links or accepting drift."""

    expected_group = os.getegid() if expected_gid is None else expected_gid
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_group
            or stat.S_IMODE(metadata.st_mode) != 0o440
            or metadata.st_size < 2
            or metadata.st_size > _MAX_SELECTOR_BYTES
        ):
            return None
        raw = b""
        while len(raw) <= _MAX_SELECTOR_BYTES:
            part = os.read(descriptor, _MAX_SELECTOR_BYTES + 1 - len(raw))
            if not part:
                break
            raw += part
        if len(raw) != metadata.st_size or not raw.endswith(b"\n"):
            return None
        payload = json.loads(raw.decode("ascii"))
        selector = validate_incident_history_selector(payload)
        if raw != _canonical(selector) + b"\n":
            return None
        return selector
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class IncidentHistoryAppendJob:
    evidence: IncidentEvidence

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, IncidentEvidence):
            raise TypeError("incident history evidence is invalid")

    @property
    def incident_ref(self) -> str | None:
        value = self.evidence.payload["incident_ref"]
        return value if isinstance(value, str) else None


def latency_bucket(elapsed_seconds: float | None) -> str:
    if elapsed_seconds is None:
        return "unknown"
    if isinstance(elapsed_seconds, bool) or not isinstance(elapsed_seconds, (int, float)):
        raise TypeError("elapsed seconds is invalid")
    if elapsed_seconds < 0:
        raise ValueError("elapsed seconds is invalid")
    if elapsed_seconds < 5:
        return "lt5s"
    if elapsed_seconds < 30:
        return "5to29s"
    if elapsed_seconds < 60:
        return "30to59s"
    return "gte60s"


def http_outcome_class(http_status: int | None) -> str:
    if http_status is None:
        return "none"
    if type(http_status) is not int or not 100 <= http_status <= 599:
        raise ValueError("HTTP status is invalid")
    if 200 <= http_status <= 299:
        return "2xx"
    if 400 <= http_status <= 499:
        return "4xx"
    if 500 <= http_status <= 599:
        return "5xx"
    return "unknown"


def build_incident_history_job(
    degradation: DegradationShadowJob,
    *,
    failure_provenance: object,
    http_status: int | None,
    elapsed_seconds: float | None,
    release_set_id: str | None,
    pending_after: int | None,
    observed_at: datetime | None = None,
    epoch_revision_delta: int | None = None,
    turn_delta: int | None = None,
    summary_delta: int | None = None,
    delivery_delta: int | None = 0,
) -> IncidentHistoryAppendJob:
    if not isinstance(degradation, DegradationShadowJob):
        raise TypeError("degradation job is invalid")
    provenance = validate_core_failure_provenance(failure_provenance)
    timestamp = observed_at or datetime.now(timezone.utc)
    evidence = build_incident_evidence(
        degradation.safe_projection(),
        observed_at=timestamp,
        trusted_time_status="untrusted",
        channel=degradation.channel,
        release_set_id=release_set_id,
        incident_ref=degradation.incident_ref,
        public_code=None,
        latency_bucket=latency_bucket(elapsed_seconds),
        http_outcome_class=http_outcome_class(http_status),
        provider_called=provenance["provider_called"],
        model_called=provenance["model_called"],
        profile_called=provenance["profile_called"],
        memory_called=provenance["memory_called"],
        tool_called=provenance["tool_called"],
        service_observation_class="unknown",
        restart_observation_class="unknown",
        epoch_revision_delta=epoch_revision_delta,
        turn_delta=turn_delta,
        summary_delta=summary_delta,
        pending_after=pending_after,
        delivery_delta=delivery_delta,
        failure_provenance=provenance,
    )
    return IncidentHistoryAppendJob(evidence)


def append_incident_history_after_response(
    job: IncidentHistoryAppendJob,
    *,
    marker: Path = INCIDENT_HISTORY_MARKER,
    selector: Path = INCIDENT_HISTORY_SELECTOR,
    root: Path = INCIDENT_HISTORY_ROOT,
    marker_check: Callable[[str], bool] = approved_marker_enabled,
    selector_load: Callable[[Path], dict[str, object] | None] = (
        load_approved_incident_history_selector
    ),
    capacity: int = 128,
) -> str:
    """Append once after the reply boundary; disabled and failure paths are inert."""

    if not isinstance(job, IncidentHistoryAppendJob):
        return "invalid_event"
    try:
        if not marker_check(str(marker)):
            return "disabled"
        configuration = selector_load(Path(selector))
        if configuration is None:
            return "disabled"
        if (
            configuration["channel"] != job.evidence.payload["channel"]
            or configuration["marker_path"] != str(marker)
            or configuration["history_root"] != str(root)
            or configuration["capacity"] != capacity
        ):
            return "disabled"
        outcome = IncidentHistoryStore(
            Path(root) / str(job.evidence.payload["channel"]),
            capacity=capacity,
        ).append(job.evidence)
        return outcome.status
    except (IncidentHistoryRejected, KeyError, OSError, TypeError, ValueError):
        return "unavailable"
