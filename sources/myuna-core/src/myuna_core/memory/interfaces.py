from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping, Protocol, Sequence, runtime_checkable

from .models import (
    MemoryCandidate,
    MemoryQuery,
    MemoryRecord,
    MemorySource,
    PolicyDecision,
    RetrievalResult,
)


@runtime_checkable
class MemorySourceAdapter(Protocol):
    def adapt(self, payload: Mapping[str, Any]) -> MemorySource: ...


@runtime_checkable
class CandidateExtractor(Protocol):
    def extract(self, source: MemorySource, content: str) -> Sequence[MemoryCandidate]: ...


@runtime_checkable
class MemoryPolicy(Protocol):
    policy_version: str

    def evaluate(self, candidate: MemoryCandidate, now: datetime) -> PolicyDecision: ...


@runtime_checkable
class MemoryStore(Protocol):
    def append(self, record: MemoryRecord) -> None: ...

    def get(self, memory_id: str) -> MemoryRecord | None: ...

    def all_records(self) -> tuple[MemoryRecord, ...]: ...


@runtime_checkable
class ArchiveStore(Protocol):
    def append_source(self, source: MemorySource, content: str) -> str: ...


@runtime_checkable
class Consolidator(Protocol):
    def plan(
        self,
        records: Iterable[MemoryRecord],
        now: datetime,
    ) -> Sequence[Mapping[str, Any]]: ...


@runtime_checkable
class Retriever(Protocol):
    def retrieve(self, query: MemoryQuery) -> RetrievalResult: ...


@runtime_checkable
class Reranker(Protocol):
    def rerank(
        self,
        query: MemoryQuery,
        records: Sequence[MemoryRecord],
    ) -> Sequence[MemoryRecord]: ...


@runtime_checkable
class EmbeddingProvider(Protocol):
    provider_id: str
    dimensions: int

    def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]: ...


@runtime_checkable
class MemoryRenderer(Protocol):
    def render(self, query: MemoryQuery, result: RetrievalResult) -> str: ...


@runtime_checkable
class PrivacyController(Protocol):
    def authorize(self, action: str, record: MemoryRecord) -> bool: ...


@runtime_checkable
class MigrationRunner(Protocol):
    def migrate(self, payload: Mapping[str, Any], target_version: int) -> dict[str, Any]: ...


@runtime_checkable
class EvaluationHarness(Protocol):
    def run(self) -> Mapping[str, Any]: ...
