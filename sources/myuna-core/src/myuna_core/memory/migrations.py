from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any, Callable, Mapping

from .models import (
    CURRENT_SCHEMA_VERSION,
    ConfirmationLevel,
    MemoryKind,
    MemoryRecord,
    MemorySource,
    MemoryStatus,
    SourceKind,
    TimePrecision,
)


Migration = Callable[[dict[str, Any]], dict[str, Any]]


class SchemaMigrationRegistry:
    """Pure payload migrations; database migrations are deliberately out of scope."""

    def __init__(self) -> None:
        self._steps: dict[int, Migration] = {}

    def register(self, from_version: int, migration: Migration) -> None:
        if from_version in self._steps:
            raise ValueError(f"migration already registered from version {from_version}")
        self._steps[from_version] = migration

    def migrate(self, payload: Mapping[str, Any], target_version: int) -> dict[str, Any]:
        result = deepcopy(dict(payload))
        version = int(result.get("schema_version", 0))
        if target_version < version:
            raise ValueError("downgrade migrations are not supported")
        while version < target_version:
            step = self._steps.get(version)
            if step is None:
                raise ValueError(f"no migration registered from version {version}")
            result = step(result)
            next_version = int(result.get("schema_version", -1))
            if next_version != version + 1:
                raise ValueError("migration must advance exactly one schema version")
            version = next_version
        return result


def _v0_to_v1(payload: dict[str, Any]) -> dict[str, Any]:
    migrated = deepcopy(payload)
    migrated.setdefault("policy_version", "legacy-import-v0")
    migrated.setdefault("status", "provisional")
    migrated.setdefault("confirmation", "observed")
    migrated.setdefault("time_precision", "unknown")
    migrated.setdefault("time_phrase", None)
    migrated.setdefault("exact_quote", None)
    migrated.setdefault("scope", ["global"])
    migrated.setdefault("importance", 0.5)
    migrated.setdefault("sensitivity", "normal")
    migrated.setdefault("tags", [])
    migrated.setdefault("do_not_surface_proactively", False)
    migrated.setdefault("expires_at", None)
    migrated.setdefault("supersedes_id", None)
    migrated.setdefault("policy_reasons", ["migrated_from_v0"])
    migrated.setdefault("metadata", {})
    migrated["schema_version"] = 1
    return migrated


def _v1_to_v2(payload: dict[str, Any]) -> dict[str, Any]:
    migrated = deepcopy(payload)
    source = dict(migrated.get("source", {}))
    source.setdefault("principal_id", "principal-synthetic")
    source.setdefault("namespace_id", "ns-synthetic-dev")
    source.setdefault("channel_binding_id", None)
    migrated["source"] = source
    migrated.setdefault("rationale", None)
    migrated.setdefault("review_after", None)
    migrated.setdefault("consolidate_after", None)
    migrated.setdefault("low_activity_after", None)
    migrated["schema_version"] = 2
    return migrated


def default_registry() -> SchemaMigrationRegistry:
    registry = SchemaMigrationRegistry()
    registry.register(0, _v0_to_v1)
    registry.register(1, _v1_to_v2)
    return registry


def _datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None


def record_to_payload(record: MemoryRecord) -> dict[str, Any]:
    return {
        "memory_id": record.memory_id,
        "schema_version": record.schema_version,
        "policy_version": record.policy_version,
        "source": {
            "source_id": record.source.source_id,
            "kind": record.source.kind.value,
            "reference": record.source.reference,
            "captured_at": record.source.captured_at.isoformat(),
            "metadata": dict(record.source.metadata),
            "principal_id": record.source.principal_id,
            "namespace_id": record.source.namespace_id,
            "channel_binding_id": record.source.channel_binding_id,
        },
        "kind": record.kind.value,
        "status": record.status.value,
        "confirmation": record.confirmation.value,
        "text": record.text,
        "occurred_at": record.occurred_at.isoformat(),
        "recorded_at": record.recorded_at.isoformat(),
        "timezone": record.timezone,
        "time_precision": record.time_precision.value,
        "time_phrase": record.time_phrase,
        "exact_quote": record.exact_quote,
        "scope": list(record.scope),
        "importance": record.importance,
        "sensitivity": record.sensitivity,
        "tags": list(record.tags),
        "do_not_surface_proactively": record.do_not_surface_proactively,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        "supersedes_id": record.supersedes_id,
        "policy_reasons": list(record.policy_reasons),
        "metadata": dict(record.metadata),
        "rationale": record.rationale,
        "review_after": record.review_after.isoformat() if record.review_after else None,
        "consolidate_after": (
            record.consolidate_after.isoformat() if record.consolidate_after else None
        ),
        "low_activity_after": (
            record.low_activity_after.isoformat() if record.low_activity_after else None
        ),
    }


def record_from_payload(payload: Mapping[str, Any]) -> MemoryRecord:
    migrated = default_registry().migrate(payload, CURRENT_SCHEMA_VERSION)
    source_payload = dict(migrated["source"])
    source = MemorySource(
        source_id=str(source_payload["source_id"]),
        kind=SourceKind(str(source_payload["kind"])),
        reference=str(source_payload["reference"]),
        captured_at=datetime.fromisoformat(str(source_payload["captured_at"])),
        metadata=dict(source_payload.get("metadata", {})),
        principal_id=str(source_payload["principal_id"]),
        namespace_id=str(source_payload["namespace_id"]),
        channel_binding_id=source_payload.get("channel_binding_id"),
    )
    return MemoryRecord(
        memory_id=str(migrated["memory_id"]),
        schema_version=int(migrated["schema_version"]),
        policy_version=str(migrated["policy_version"]),
        source=source,
        kind=MemoryKind(str(migrated["kind"])),
        status=MemoryStatus(str(migrated["status"])),
        confirmation=ConfirmationLevel(str(migrated["confirmation"])),
        text=str(migrated["text"]),
        occurred_at=datetime.fromisoformat(str(migrated["occurred_at"])),
        recorded_at=datetime.fromisoformat(str(migrated["recorded_at"])),
        timezone=str(migrated["timezone"]),
        time_precision=TimePrecision(str(migrated["time_precision"])),
        time_phrase=migrated.get("time_phrase"),
        exact_quote=migrated.get("exact_quote"),
        scope=tuple(str(value) for value in migrated["scope"]),
        importance=float(migrated["importance"]),
        sensitivity=str(migrated["sensitivity"]),
        tags=tuple(str(value) for value in migrated["tags"]),
        do_not_surface_proactively=bool(migrated["do_not_surface_proactively"]),
        expires_at=_datetime(migrated.get("expires_at")),
        supersedes_id=migrated.get("supersedes_id"),
        policy_reasons=tuple(str(value) for value in migrated["policy_reasons"]),
        metadata=dict(migrated["metadata"]),
        rationale=migrated.get("rationale"),
        review_after=_datetime(migrated.get("review_after")),
        consolidate_after=_datetime(migrated.get("consolidate_after")),
        low_activity_after=_datetime(migrated.get("low_activity_after")),
    )
