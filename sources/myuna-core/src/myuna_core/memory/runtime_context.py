from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Mapping, Protocol

from .models import MemoryQuery
from .worker_adapter import WorkerRetrievalResult


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_VISIBLE_STATUSES = frozenset({"confirmed", "provisional", "suppressed"})


class SyntheticMemoryContextError(RuntimeError):
    pass


class RetrievalAdapter(Protocol):
    def retrieve(
        self,
        query: MemoryQuery,
        *,
        mode: str = "auto",
        timeout_seconds: float = 20.0,
        request_id: str | None = None,
        route_reason: str = "synthetic_stage5_validation",
    ) -> WorkerRetrievalResult: ...


@dataclass(frozen=True, slots=True)
class SyntheticDocument:
    memory_id: str
    text: str
    kind: str
    status: str
    confirmation: str
    occurred_at: str
    time_precision: str
    time_phrase: str | None
    scope: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SyntheticMemorySelection:
    context: str
    hit_ids: tuple[str, ...]
    mode_used: str
    degraded_reason: str | None
    fixture_sha256: str


class SyntheticFixtureCatalog:
    def __init__(
        self,
        documents: Mapping[str, SyntheticDocument],
        *,
        source_sha256: str,
    ) -> None:
        self.documents = dict(documents)
        self.source_sha256 = source_sha256

    @classmethod
    def load(cls, path: Path, *, expected_sha256: str) -> "SyntheticFixtureCatalog":
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise SyntheticMemoryContextError("synthetic fixture path is unavailable or unsafe")
        raw = path.read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            raise SyntheticMemoryContextError("synthetic fixture exceeds the size limit")
        actual_sha256 = sha256(raw).hexdigest().upper()
        if actual_sha256 != expected_sha256.upper():
            raise SyntheticMemoryContextError("synthetic fixture checksum mismatch")
        documents: dict[str, SyntheticDocument] = {}
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise SyntheticMemoryContextError("synthetic fixture must be UTF-8") from exc
        for line_number, line in enumerate(lines, start=1):
            if not line:
                continue
            try:
                item: Any = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SyntheticMemoryContextError(
                    f"invalid synthetic fixture JSON at line {line_number}"
                ) from exc
            if not isinstance(item, dict) or item.get("type") != "document":
                continue
            memory_id = item.get("id")
            text = item.get("text")
            scope = item.get("scope")
            if (
                item.get("synthetic") is not True
                or not isinstance(memory_id, str)
                or _IDENTIFIER.fullmatch(memory_id) is None
                or memory_id in documents
                or not isinstance(text, str)
                or not 1 <= len(text) <= 4000
                or not isinstance(scope, list)
                or not scope
                or any(not isinstance(value, str) or not value for value in scope)
            ):
                raise SyntheticMemoryContextError(
                    f"invalid synthetic document at line {line_number}"
                )
            status = item.get("status")
            required_strings = {
                name: item.get(name)
                for name in (
                    "kind",
                    "confirmation",
                    "occurred_at",
                    "time_precision",
                )
            }
            if status not in _VISIBLE_STATUSES or any(
                not isinstance(value, str) or not value
                for value in required_strings.values()
            ):
                if status == "tombstoned":
                    continue
                raise SyntheticMemoryContextError(
                    f"unsupported synthetic document state at line {line_number}"
                )
            time_phrase = item.get("time_phrase")
            if time_phrase is not None and not isinstance(time_phrase, str):
                raise SyntheticMemoryContextError(
                    f"invalid time phrase at line {line_number}"
                )
            documents[memory_id] = SyntheticDocument(
                memory_id=memory_id,
                text=text,
                kind=required_strings["kind"],
                status=status,
                confirmation=required_strings["confirmation"],
                occurred_at=required_strings["occurred_at"],
                time_precision=required_strings["time_precision"],
                time_phrase=time_phrase,
                scope=tuple(scope),
            )
        if not documents or len(documents) > 1000:
            raise SyntheticMemoryContextError("synthetic fixture document count is unsafe")
        return cls(documents, source_sha256=actual_sha256)

    def render(
        self,
        result: WorkerRetrievalResult,
        *,
        query_scope: tuple[str, ...],
    ) -> tuple[str, tuple[str, ...]]:
        records: list[dict[str, object]] = []
        hit_ids: list[str] = []
        for hit in result.hits:
            document = self.documents.get(hit.memory_id)
            if document is None:
                raise SyntheticMemoryContextError(
                    "retrieval worker returned an unknown synthetic record"
                )
            if not set(document.scope).intersection(query_scope):
                raise SyntheticMemoryContextError(
                    "retrieval worker returned an out-of-scope synthetic record"
                )
            records.append(
                {
                    "synthetic": True,
                    "memory_id": document.memory_id,
                    "kind": document.kind,
                    "status": document.status,
                    "confirmation": document.confirmation,
                    "occurred_at": document.occurred_at,
                    "time_precision": document.time_precision,
                    "time_phrase": document.time_phrase,
                    "text": document.text,
                }
            )
            hit_ids.append(document.memory_id)
        context = (
            "The following JSON array contains the single top-ranked fictional synthetic "
            "test record only. "
            "It is not the user's history and not a real shared memory. Explicitly label any "
            "answer based on it as synthetic or fictional test data. State only facts explicitly "
            "present in the JSON fields. Never invent, infer, or embellish a method, tool, cause, "
            "action, emotion, quote, place, or time that is absent. If the question asks for an "
            "unstated detail, say the synthetic record does not contain that detail. If the array "
            "is empty, say that no matching synthetic test record was found.\n"
            + json.dumps(records, ensure_ascii=False, sort_keys=True)
        )
        return context, tuple(hit_ids)


class SyntheticMemoryRuntime:
    def __init__(
        self,
        adapter: RetrievalAdapter,
        catalog: SyntheticFixtureCatalog,
        *,
        fixed_at: datetime,
    ) -> None:
        if fixed_at.tzinfo is None or fixed_at.utcoffset() is None:
            raise ValueError("synthetic fixture time must be timezone-aware")
        self.adapter = adapter
        self.catalog = catalog
        self.fixed_at = fixed_at

    def retrieve(self, text: str, *, request_id: str) -> SyntheticMemorySelection:
        query = MemoryQuery(text=text, at=self.fixed_at, limit=1)
        result = self.adapter.retrieve(
            query,
            mode="hybrid",
            timeout_seconds=30.0,
            request_id=request_id,
            route_reason="synthetic_loopback_memory_read",
        )
        if result.mode_used != "hybrid" or result.degraded_reason is not None:
            raise SyntheticMemoryContextError(
                "synthetic loopback memory test requires non-degraded hybrid retrieval"
            )
        if len(result.hits) > 1:
            raise SyntheticMemoryContextError(
                "synthetic loopback memory test accepts only the top-ranked record"
            )
        context, hit_ids = self.catalog.render(result, query_scope=query.scope)
        return SyntheticMemorySelection(
            context=context,
            hit_ids=hit_ids,
            mode_used=result.mode_used,
            degraded_reason=result.degraded_reason,
            fixture_sha256=self.catalog.source_sha256,
        )
