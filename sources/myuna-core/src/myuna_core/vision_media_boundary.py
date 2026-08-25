from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import BinaryIO, Mapping, Protocol

from .vision_input import VisionInputEnvelope, VisionMediaDescriptor


POLICY_SCHEMA_VERSION = 1
TICKET_SCHEMA_VERSION = "myuna.vision-media-ticket.v1"
LEASE_SCHEMA_VERSION = "myuna.vision-media-lease.v1"
DISPOSAL_SCHEMA_VERSION = "myuna.vision-media-disposal.v1"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DISPOSAL_REASONS = frozenset({"consumed", "expired", "rejected", "cancelled"})


class VisionMediaBoundaryError(PermissionError):
    """Fail-closed media lifecycle error without path or media disclosure."""


def _reject() -> VisionMediaBoundaryError:
    return VisionMediaBoundaryError("vision media boundary rejected")


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a safe opaque identifier")
    return value


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone offset")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class VisionMediaStagingPolicy:
    schema_version: int
    policy_id: str
    status: str
    storage_scope: str
    maximum_ttl_seconds: int
    maximum_reads_per_media: int
    require_private_owner: bool
    require_regular_file: bool
    reject_symlinks: bool
    allow_persistent_copy: bool
    allow_remote_fetch: bool
    secure_disposal_required: bool

    @classmethod
    def from_document(cls, document: object) -> VisionMediaStagingPolicy:
        try:
            if not isinstance(document, Mapping) or set(document) != {
                "schema_version",
                "policy_id",
                "status",
                "storage_scope",
                "maximum_ttl_seconds",
                "maximum_reads_per_media",
                "filesystem_guards",
                "side_effects",
            }:
                raise ValueError("media staging policy fields do not match v1")
            if document["schema_version"] != POLICY_SCHEMA_VERSION:
                raise ValueError("unsupported media staging policy schema")
            if document["status"] != "inactive_candidate":
                raise ValueError("v1 media staging policy must remain inactive")
            ttl = document["maximum_ttl_seconds"]
            reads = document["maximum_reads_per_media"]
            if not isinstance(ttl, int) or not 30 <= ttl <= 900:
                raise ValueError("media staging TTL is invalid")
            if reads != 1:
                raise ValueError("v1 media staging must be single-read")
            guards = document["filesystem_guards"]
            if not isinstance(guards, Mapping) or set(guards) != {
                "require_private_owner",
                "require_regular_file",
                "reject_symlinks",
            }:
                raise ValueError("filesystem guards are invalid")
            if any(value is not True for value in guards.values()):
                raise ValueError("all filesystem guards must be enabled")
            effects = document["side_effects"]
            if not isinstance(effects, Mapping) or set(effects) != {
                "allow_persistent_copy",
                "allow_remote_fetch",
                "secure_disposal_required",
            }:
                raise ValueError("media staging side effects are invalid")
            if effects["allow_persistent_copy"] is not False:
                raise ValueError("persistent media copies are forbidden")
            if effects["allow_remote_fetch"] is not False:
                raise ValueError("remote fetch is forbidden at the staging boundary")
            if effects["secure_disposal_required"] is not True:
                raise ValueError("secure disposal must be required")
            return cls(
                schema_version=POLICY_SCHEMA_VERSION,
                policy_id=_safe_id(document["policy_id"], "policy_id"),
                status="inactive_candidate",
                storage_scope=_safe_id(document["storage_scope"], "storage_scope"),
                maximum_ttl_seconds=ttl,
                maximum_reads_per_media=1,
                require_private_owner=True,
                require_regular_file=True,
                reject_symlinks=True,
                allow_persistent_copy=False,
                allow_remote_fetch=False,
                secure_disposal_required=True,
            )
        except (KeyError, TypeError, ValueError):
            raise _reject() from None

    @classmethod
    def load(cls, path: Path) -> VisionMediaStagingPolicy:
        try:
            return cls.from_document(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise _reject() from None


@dataclass(frozen=True, slots=True)
class VisionMediaStagingTicket:
    schema_version: str
    stage_id: str
    request_id: str
    trace_id: str
    media: tuple[VisionMediaDescriptor, ...]
    created_at: datetime
    expires_at: datetime
    storage_scope: str

    def __post_init__(self) -> None:
        if self.schema_version != TICKET_SCHEMA_VERSION:
            raise ValueError("unsupported media staging ticket schema")
        for value, label in (
            (self.stage_id, "stage_id"),
            (self.request_id, "request_id"),
            (self.trace_id, "trace_id"),
            (self.storage_scope, "storage_scope"),
        ):
            _safe_id(value, label)
        if not self.media or len(self.media) != len({item.media_id for item in self.media}):
            raise ValueError("staging ticket media must be non-empty and unique")
        created_at = _utc(self.created_at, "created_at")
        expires_at = _utc(self.expires_at, "expires_at")
        if expires_at <= created_at:
            raise ValueError("staging ticket must expire after creation")
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "expires_at", expires_at)

    def audit_metadata(self) -> dict[str, object]:
        return {
            "created_at": self.created_at.isoformat(timespec="microseconds"),
            "expires_at": self.expires_at.isoformat(timespec="microseconds"),
            "media_count": len(self.media),
            "media_ids": [item.media_id for item in self.media],
            "request_id": self.request_id,
            "stage_id": self.stage_id,
            "storage_scope": self.storage_scope,
            "trace_id": self.trace_id,
        }


@dataclass(frozen=True, slots=True)
class VisionMediaLease:
    schema_version: str
    lease_id: str
    stage_id: str
    media_id: str
    request_id: str
    issued_at: datetime
    expires_at: datetime
    permitted_reads: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != LEASE_SCHEMA_VERSION:
            raise ValueError("unsupported media lease schema")
        for value, label in (
            (self.lease_id, "lease_id"),
            (self.stage_id, "stage_id"),
            (self.media_id, "media_id"),
            (self.request_id, "request_id"),
        ):
            _safe_id(value, label)
        issued_at = _utc(self.issued_at, "issued_at")
        expires_at = _utc(self.expires_at, "expires_at")
        if expires_at <= issued_at or self.permitted_reads != 1:
            raise ValueError("media lease must be live and single-read")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)


@dataclass(frozen=True, slots=True)
class VisionMediaDisposalReceipt:
    schema_version: str
    stage_id: str
    media_id: str
    disposed_at: datetime
    reason: str
    byte_length: int
    content_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != DISPOSAL_SCHEMA_VERSION:
            raise ValueError("unsupported media disposal schema")
        _safe_id(self.stage_id, "stage_id")
        _safe_id(self.media_id, "media_id")
        object.__setattr__(self, "disposed_at", _utc(self.disposed_at, "disposed_at"))
        if self.reason not in _DISPOSAL_REASONS:
            raise ValueError("unsupported media disposal reason")
        if not isinstance(self.byte_length, int) or self.byte_length < 1:
            raise ValueError("disposed byte length is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.content_sha256):
            raise ValueError("disposed content hash is invalid")

    def audit_metadata(self) -> dict[str, object]:
        return {
            "byte_length": self.byte_length,
            "content_sha256": self.content_sha256,
            "disposed_at": self.disposed_at.isoformat(timespec="microseconds"),
            "media_id": self.media_id,
            "reason": self.reason,
            "stage_id": self.stage_id,
        }


class VisionMediaStagingPort(Protocol):
    """Implementation boundary; paths and handles never cross this interface."""

    def stage_verified_streams(
        self,
        *,
        envelope: VisionInputEnvelope,
        streams: Mapping[str, BinaryIO],
        expires_at: datetime,
    ) -> VisionMediaStagingTicket: ...

    def lease_once(
        self,
        *,
        ticket: VisionMediaStagingTicket,
        media_id: str,
        now: datetime,
    ) -> VisionMediaLease: ...

    def read_once(self, lease: VisionMediaLease, *, maximum_bytes: int) -> bytes: ...

    def dispose(
        self,
        ticket: VisionMediaStagingTicket,
        *,
        reason: str,
        now: datetime,
    ) -> tuple[VisionMediaDisposalReceipt, ...]: ...


def validate_ticket(
    *,
    envelope: VisionInputEnvelope,
    ticket: VisionMediaStagingTicket,
    policy: VisionMediaStagingPolicy,
    now: datetime,
) -> None:
    try:
        current = _utc(now, "now")
        if (
            ticket.request_id != envelope.context.request_id
            or ticket.trace_id != envelope.context.trace_id
            or ticket.storage_scope != policy.storage_scope
            or ticket.media != envelope.media
            or ticket.expires_at <= current
            or ticket.expires_at - ticket.created_at
            > timedelta(seconds=policy.maximum_ttl_seconds)
        ):
            raise _reject()
    except (TypeError, ValueError, VisionMediaBoundaryError):
        raise _reject() from None


def validate_lease(
    *,
    ticket: VisionMediaStagingTicket,
    lease: VisionMediaLease,
    now: datetime,
) -> VisionMediaDescriptor:
    try:
        current = _utc(now, "now")
        if (
            lease.stage_id != ticket.stage_id
            or lease.request_id != ticket.request_id
            or lease.expires_at > ticket.expires_at
            or lease.expires_at <= current
            or lease.permitted_reads != 1
        ):
            raise _reject()
        matches = tuple(item for item in ticket.media if item.media_id == lease.media_id)
        if len(matches) != 1:
            raise _reject()
        return matches[0]
    except (TypeError, ValueError, VisionMediaBoundaryError):
        raise _reject() from None
