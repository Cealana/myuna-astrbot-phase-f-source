from __future__ import annotations

from .models import MemoryRecord, MemoryStatus, SourceKind


class InMemoryStore:
    """Append-only Stage 0 store for tests and development only.

    It deliberately offers no persistence and must never be treated as the
    production source of truth.
    """

    def __init__(self) -> None:
        self._records: list[MemoryRecord] = []
        self._by_id: dict[str, MemoryRecord] = {}

    def append(self, record: MemoryRecord) -> None:
        if record.memory_id in self._by_id:
            raise ValueError(f"memory_id already exists: {record.memory_id}")
        if record.source.kind is SourceKind.OPERATIONAL_RECORD:
            raise ValueError("operational records require an external record store")
        if record.status is MemoryStatus.EXCLUDED:
            raise ValueError("excluded candidates must not enter the personal memory store")
        self._records.append(record)
        self._by_id[record.memory_id] = record

    def get(self, memory_id: str) -> MemoryRecord | None:
        return self._by_id.get(memory_id)

    def all_records(self) -> tuple[MemoryRecord, ...]:
        return tuple(self._records)
