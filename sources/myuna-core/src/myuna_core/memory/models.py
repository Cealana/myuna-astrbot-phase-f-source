from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Mapping


CURRENT_SCHEMA_VERSION = 2


class SourceKind(StrEnum):
    CONVERSATION = "conversation"
    MANUAL_IMPORT = "manual_import"
    DOCUMENT = "document"
    OPERATIONAL_RECORD = "operational_record"
    MODEL_INFERENCE = "model_inference"


class MemoryKind(StrEnum):
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PREFERENCE = "preference"
    ANCHOR = "anchor"
    CURRENT_STATE = "current_state"
    EXACT_QUOTE = "exact_quote"
    FACT = "fact"
    RELATIONSHIP = "relationship"
    PROJECT = "project"


class MemoryStatus(StrEnum):
    PROVISIONAL = "provisional"
    CONFIRMED = "confirmed"
    SUPPRESSED = "suppressed"
    EXCLUDED = "excluded"
    TOMBSTONED = "tombstoned"


class ConfirmationLevel(StrEnum):
    MODEL_INFERRED = "model_inferred"
    OBSERVED = "observed"
    USER_CONFIRMED = "user_confirmed"


class TimePrecision(StrEnum):
    UNKNOWN = "unknown"
    DATE = "date"
    PART_OF_DAY = "part_of_day"
    MINUTE = "minute"
    EXACT = "exact"


class PolicyAction(StrEnum):
    RETAIN_PROVISIONAL = "retain_provisional"
    RETAIN_CONFIRMED = "retain_confirmed"
    RETAIN_SUPPRESSED = "retain_suppressed"
    SESSION_ONLY = "session_only"
    EXCLUDE = "exclude"
    SEALED_ARCHIVE = "sealed_archive"
    DISCARD = "discard"
    STORE_AS_EXTERNAL_RECORD = "store_as_external_record"


def require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class MemorySource:
    source_id: str
    kind: SourceKind
    reference: str
    captured_at: datetime
    metadata: Mapping[str, Any] = field(default_factory=dict)
    principal_id: str = "principal-synthetic"
    namespace_id: str = "ns-synthetic-dev"
    channel_binding_id: str | None = None

    def __post_init__(self) -> None:
        if not self.source_id.strip():
            raise ValueError("source_id must not be empty")
        if not self.reference.strip():
            raise ValueError("reference must not be empty")
        if not self.principal_id.strip():
            raise ValueError("principal_id must not be empty")
        if not self.namespace_id.strip():
            raise ValueError("namespace_id must not be empty")
        require_aware(self.captured_at, "captured_at")


@dataclass(frozen=True, slots=True)
class MemoryCandidate:
    memory_id: str
    source: MemorySource
    kind: MemoryKind
    text: str
    occurred_at: datetime
    recorded_at: datetime
    timezone: str
    time_precision: TimePrecision
    time_phrase: str | None = None
    exact_quote: str | None = None
    scope: tuple[str, ...] = ("global",)
    importance: float = 0.5
    sensitivity: str = "normal"
    tags: tuple[str, ...] = ()
    confirmation: ConfirmationLevel = ConfirmationLevel.OBSERVED
    directive_text: str = ""
    supersedes_id: str | None = None
    expires_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    rationale: str | None = None
    review_after: datetime | None = None
    consolidate_after: datetime | None = None
    low_activity_after: datetime | None = None

    def __post_init__(self) -> None:
        if not self.memory_id.strip():
            raise ValueError("memory_id must not be empty")
        if not self.text.strip():
            raise ValueError("text must not be empty")
        if not self.timezone.strip():
            raise ValueError("timezone must not be empty")
        if not self.scope:
            raise ValueError("scope must contain at least one value")
        if not 0.0 <= self.importance <= 1.0:
            raise ValueError("importance must be between 0 and 1")
        require_aware(self.occurred_at, "occurred_at")
        require_aware(self.recorded_at, "recorded_at")
        if self.expires_at is not None:
            require_aware(self.expires_at, "expires_at")
        for name, value in (
            ("review_after", self.review_after),
            ("consolidate_after", self.consolidate_after),
            ("low_activity_after", self.low_activity_after),
        ):
            if value is not None:
                require_aware(value, name)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: PolicyAction
    status: MemoryStatus | None
    reason_codes: tuple[str, ...]
    expires_at: datetime | None = None
    do_not_surface_proactively: bool = False
    review_after: datetime | None = None
    consolidate_after: datetime | None = None
    low_activity_after: datetime | None = None
    archive_receipt_required: bool = False


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    memory_id: str
    schema_version: int
    policy_version: str
    source: MemorySource
    kind: MemoryKind
    status: MemoryStatus
    confirmation: ConfirmationLevel
    text: str
    occurred_at: datetime
    recorded_at: datetime
    timezone: str
    time_precision: TimePrecision
    time_phrase: str | None
    exact_quote: str | None
    scope: tuple[str, ...]
    importance: float
    sensitivity: str
    tags: tuple[str, ...]
    do_not_surface_proactively: bool
    expires_at: datetime | None
    supersedes_id: str | None
    policy_reasons: tuple[str, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    rationale: str | None = None
    review_after: datetime | None = None
    consolidate_after: datetime | None = None
    low_activity_after: datetime | None = None

    def __post_init__(self) -> None:
        if self.schema_version < 1:
            raise ValueError("schema_version must be positive")
        if not self.memory_id.strip() or not self.text.strip():
            raise ValueError("memory_id and text must not be empty")
        require_aware(self.occurred_at, "occurred_at")
        require_aware(self.recorded_at, "recorded_at")
        if self.expires_at is not None:
            require_aware(self.expires_at, "expires_at")
        for name, value in (
            ("review_after", self.review_after),
            ("consolidate_after", self.consolidate_after),
            ("low_activity_after", self.low_activity_after),
        ):
            if value is not None:
                require_aware(value, name)
        lifecycle = tuple(
            value
            for value in (
                self.review_after,
                self.consolidate_after,
                self.low_activity_after,
            )
            if value is not None
        )
        if lifecycle != tuple(sorted(lifecycle)):
            raise ValueError("memory lifecycle timestamps must be ordered")
        if self.source.namespace_id != self.namespace_id:
            raise ValueError("record namespace must match source namespace")

    @property
    def namespace_id(self) -> str:
        return self.source.namespace_id


@dataclass(frozen=True, slots=True)
class MemoryQuery:
    text: str
    scope: tuple[str, ...] = ("global",)
    at: datetime | None = None
    time_start: datetime | None = None
    time_end: datetime | None = None
    kinds: tuple[MemoryKind, ...] = ()
    proactive: bool = False
    include_external_records: bool = False
    limit: int = 10
    principal_id: str = "principal-synthetic"
    namespace_id: str = "ns-synthetic-dev"

    def __post_init__(self) -> None:
        if not self.text.strip():
            raise ValueError("query text must not be empty")
        if self.limit < 1:
            raise ValueError("limit must be positive")
        if not self.principal_id.strip():
            raise ValueError("principal_id must not be empty")
        if not self.namespace_id.strip():
            raise ValueError("namespace_id must not be empty")
        for name, value in (
            ("at", self.at),
            ("time_start", self.time_start),
            ("time_end", self.time_end),
        ):
            if value is not None:
                require_aware(value, name)


@dataclass(frozen=True, slots=True)
class RetrievalHit:
    record: MemoryRecord
    score: float
    reasons: tuple[str, ...]
    score_components: Mapping[str, float] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RetrievalTrace:
    strategy_version: str
    examined: int
    eligible: int
    filtered: Mapping[str, int]
    query_terms: tuple[str, ...]
    query_intents: tuple[str, ...] = ()
    candidate_sources: Mapping[str, int] = field(default_factory=dict)
    score_weights: Mapping[str, float] = field(default_factory=dict)
    embedding_identity: Mapping[str, str | int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    hits: tuple[RetrievalHit, ...]
    trace: RetrievalTrace
