"""Content-free post-response sender for Natural Degradation R2C Shadow."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import time
from typing import Mapping
from uuid import UUID, uuid4

from gateway_degradation_protocol import (
    CANONICAL_DEGRADATION_REPLIES,
    SAFE_DEGRADATION_SCHEMA,
    validate_safe_degradation,
)
from fault_incident_v1 import incident_ref_for_request, validate_incident_ref


SHADOW_EVENT_SCHEMA = "myuna.degradation-shadow.event.v1"
MAX_DATAGRAM_BYTES = 4096
LEGACY_RESPONSE_CODE = "owner-runtime-unavailable"
ALLOWED_PROJECTION_SOURCES = frozenset({"core", "gateway"})
FAULT_RECEIPT_SCHEMA = "myuna.fault-incident-receipt.v1"
FAULT_RECEIPT_ROOT = Path("/run/myuna-fault-diagnostics")
ALLOWED_CHANNELS = frozenset({"qq", "telegram"})


@dataclass(frozen=True, slots=True)
class DegradationShadowJob:
    channel: str
    incident_ref: str
    observation_uuid: str
    projection_source: str
    category: str
    retryable: bool
    owner_action_required: bool
    safe_detail_code: str
    recovery_state: str
    fingerprint: str
    legacy_response_code: str = LEGACY_RESPONSE_CODE

    def __post_init__(self) -> None:
        if self.channel not in ALLOWED_CHANNELS:
            raise ValueError("invalid degradation channel")
        validate_incident_ref(self.incident_ref)
        UUID(self.observation_uuid)
        if self.projection_source not in ALLOWED_PROJECTION_SOURCES:
            raise ValueError("invalid degradation Shadow source")
        if self.legacy_response_code != LEGACY_RESPONSE_CODE:
            raise ValueError("invalid legacy response code")
        if type(self.retryable) is not bool:
            raise TypeError("retryable must be boolean")
        if type(self.owner_action_required) is not bool:
            raise TypeError("owner_action_required must be boolean")

    def safe_projection(self) -> dict[str, object]:
        """Reconstruct the exact public-safe projection without request content."""

        return validate_safe_degradation(
            {
                "schema": SAFE_DEGRADATION_SCHEMA,
                "status": "degraded",
                "category": self.category,
                "retryable": self.retryable,
                "owner_action_required": self.owner_action_required,
                "safe_detail_code": self.safe_detail_code,
                "recovery_state": self.recovery_state,
                "fingerprint": self.fingerprint,
                "reply": CANONICAL_DEGRADATION_REPLIES[self.category],
            }
        )

    @classmethod
    def from_projection(
        cls,
        projection: object,
        *,
        projection_source: str,
        channel: str,
        request_id: str,
        observation_uuid: str | None = None,
    ) -> "DegradationShadowJob":
        validated = validate_safe_degradation(projection)
        return cls(
            channel=channel,
            incident_ref=incident_ref_for_request(request_id),
            observation_uuid=observation_uuid or str(uuid4()),
            projection_source=projection_source,
            category=str(validated["category"]),
            retryable=validated["retryable"],
            owner_action_required=validated["owner_action_required"],
            safe_detail_code=str(validated["safe_detail_code"]),
            recovery_state=str(validated["recovery_state"]),
            fingerprint=str(validated["fingerprint"]),
        )


def build_fault_incident_receipt(
    job: DegradationShadowJob,
    *,
    observed_at: datetime | None = None,
) -> bytes:
    if not isinstance(job, DegradationShadowJob):
        raise TypeError("invalid degradation Shadow job")
    timestamp = observed_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("fault receipt timestamp is invalid")
    receipt = {
        "schema": FAULT_RECEIPT_SCHEMA,
        "observed_at": timestamp.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "channel": job.channel,
        "incident_ref": job.incident_ref,
        "projection_source": job.projection_source,
        "category": job.category,
        "retryable": job.retryable,
        "owner_action_required": job.owner_action_required,
        "safe_detail_code": job.safe_detail_code,
        "recovery_state": job.recovery_state,
        "fingerprint": job.fingerprint,
        "private_content_written": False,
        "raw_payload_written": False,
    }
    encoded = json.dumps(
        receipt,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    if len(encoded) > MAX_DATAGRAM_BYTES:
        raise ValueError("fault receipt exceeds limit")
    return encoded


def write_fault_incident_receipt_after_response(
    job: DegradationShadowJob,
    *,
    receipt_root: Path = FAULT_RECEIPT_ROOT,
) -> str:
    """Atomically replace one fixed per-channel content-free receipt."""

    temporary: Path | None = None
    try:
        root = receipt_root
        root_stat = root.lstat()
        if not root.is_absolute() or not root_stat or not root.is_dir() or root.is_symlink():
            raise ValueError("fault receipt root is invalid")
        channel_root = root / job.channel
        channel_stat = channel_root.lstat()
        if not channel_stat or not channel_root.is_dir() or channel_root.is_symlink():
            raise ValueError("fault receipt channel root is invalid")
        destination = channel_root / "last.json"
        if destination.exists() and (
            destination.is_symlink() or not destination.is_file()
        ):
            raise ValueError("fault receipt destination is invalid")
        temporary = channel_root / f".last.{os.getpid()}.{uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o640)
        try:
            payload = build_fault_incident_receipt(job)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fchmod(handle.fileno(), 0o640)
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            temporary = None
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        return "written"
    except (OSError, TypeError, ValueError):
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        return "unavailable"


def build_degradation_shadow_event(
    job: DegradationShadowJob,
    *,
    monotonic_ns: int | None = None,
) -> bytes:
    if not isinstance(job, DegradationShadowJob):
        raise TypeError("invalid degradation Shadow job")
    event: dict[str, object] = {
        "schema": SHADOW_EVENT_SCHEMA,
        "boundary": "verified_owner_private_failure_post_response",
        "observation_uuid": job.observation_uuid,
        "legacy_response_code": job.legacy_response_code,
        "projection_source": job.projection_source,
        "category": job.category,
        "retryable": job.retryable,
        "owner_action_required": job.owner_action_required,
        "safe_detail_code": job.safe_detail_code,
        "recovery_state": job.recovery_state,
        "fingerprint": job.fingerprint,
        "enqueue_monotonic_ns": monotonic_ns or time.monotonic_ns(),
    }
    encoded = json.dumps(
        event,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if len(encoded) > MAX_DATAGRAM_BYTES:
        raise ValueError("degradation Shadow event exceeds limit")
    return encoded


def enqueue_degradation_after_response(
    socket_path: str,
    job: DegradationShadowJob,
) -> str:
    """Attempt one non-blocking local datagram send; never retry or raise."""

    try:
        payload = build_degradation_shadow_event(job)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            client.setblocking(False)
            client.connect(socket_path)
            client.send(payload)
        finally:
            client.close()
        return "enqueued"
    except (OSError, UnicodeError, ValueError, TypeError):
        return "unavailable"
