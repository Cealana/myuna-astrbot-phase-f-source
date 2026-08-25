from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
import unicodedata


SCHEMA_VERSION = 1
SCHEMA_LABEL = "myuna.active-temporal-context.v1"
AUDIT_NAMESPACE = "active_temporal_context_v1"
SQLITE_APPLICATION_ID = 0x4D594154

TEMPORAL_CATEGORIES = (
    "current_task",
    "short_term_status",
    "temporary_plan",
    "next_action",
    "deadline",
    "waiting_item",
    "temporary_constraint",
    "temporary_availability",
    "short_lived_preference",
)
FACT_STATES = (
    "active",
    "superseded",
    "conflicted",
    "expired",
    "revoked",
)
MUTATION_ACTIONS = ("create", "supersede", "refresh", "revoke", "restore")
SOURCE_KINDS = (
    "owner_statement",
    "owner_confirmation",
    "owner_refresh",
    "owner_restore",
)

MAX_ID_CHARACTERS = 128
MAX_SUMMARY_CHARACTERS = 500
MAX_QUERY_CHARACTERS = 512
MAX_RESULTS = 6
MAX_CONTEXT_CHARACTERS = 2_400
MAX_PROPOSAL_BYTES = 16_384
MAX_HORIZON = timedelta(days=31)
MIN_PROPOSAL_TTL = timedelta(minutes=1)
MAX_PROPOSAL_TTL = timedelta(minutes=30)

_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PROHIBITED_SUMMARY = re.compile(
    r"(?i)(password|passcode|api[_ -]?key|access[_ -]?token|bearer |private key|"
    r"credential|bank account|credit card|medical diagnosis|legal case|"
    r"ignore previous|system prompt|act as|"
    r"密码|口令|密钥|令牌|银行卡|信用卡|医疗诊断|法律案件|忽略之前|系统提示)"
)
_EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
_PHONE = re.compile(r"(?<!\d)(?:\+?\d[\d -]{7,}\d)(?!\d)")


class TemporalContextError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TemporalContextError(f"{label}_timezone_missing")
    return value.astimezone(timezone.utc)


def safe_label(value: str, label: str) -> str:
    if not isinstance(value, str) or _SAFE_LABEL.fullmatch(value) is None:
        raise TemporalContextError(f"{label}_invalid")
    return value


def bounded_text(value: str, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value) > maximum
    ):
        raise TemporalContextError(f"{label}_invalid")
    return value


def normalized_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def validate_summary_policy(value: str) -> None:
    if (
        "\n" in value
        or "\r" in value
        or _PROHIBITED_SUMMARY.search(value)
        or _EMAIL.search(value)
        or _PHONE.search(value)
    ):
        raise TemporalContextError("summary_policy_rejected")


@dataclass(frozen=True, slots=True)
class TemporalFactDraft:
    category: str
    slot_key: str
    summary: str
    source_kind: str
    source_channel: str
    source_ref: str
    valid_from: datetime
    valid_to: datetime | None
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.category not in TEMPORAL_CATEGORIES:
            raise TemporalContextError("category_prohibited")
        safe_label(self.slot_key, "slot_key")
        bounded_text(self.summary, "summary", MAX_SUMMARY_CHARACTERS)
        validate_summary_policy(self.summary)
        if self.source_kind not in SOURCE_KINDS:
            raise TemporalContextError("source_kind_rejected")
        if self.source_channel != "telegram":
            raise TemporalContextError("source_channel_rejected")
        safe_label(self.source_ref, "source_ref")
        valid_from = utc(self.valid_from, "valid_from")
        valid_to = utc(self.valid_to, "valid_to") if self.valid_to is not None else None
        expires_at = utc(self.expires_at, "expires_at")
        if valid_to is not None and not valid_from < valid_to <= expires_at:
            raise TemporalContextError("validity_window_invalid")
        if expires_at <= valid_from:
            raise TemporalContextError("validity_window_invalid")
        object.__setattr__(self, "valid_from", valid_from)
        object.__setattr__(self, "valid_to", valid_to)
        object.__setattr__(self, "expires_at", expires_at)

    def validate_observed_at(self, observed_at: datetime) -> None:
        observed = utc(observed_at, "observed_at")
        if self.valid_from < observed - MAX_HORIZON:
            raise TemporalContextError("valid_from_out_of_range")
        if not observed < self.expires_at <= observed + MAX_HORIZON:
            raise TemporalContextError("expiry_out_of_range")

    def as_payload(self) -> dict[str, object]:
        return {
            "category": self.category,
            "expires_at": self.expires_at.isoformat(timespec="microseconds"),
            "slot_key": self.slot_key,
            "source_channel": self.source_channel,
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "summary": self.summary,
            "valid_from": self.valid_from.isoformat(timespec="microseconds"),
            "valid_to": (
                self.valid_to.isoformat(timespec="microseconds")
                if self.valid_to is not None
                else None
            ),
        }

    @classmethod
    def from_payload(cls, payload: object) -> TemporalFactDraft:
        if not isinstance(payload, dict) or set(payload) != {
            "category",
            "expires_at",
            "slot_key",
            "source_channel",
            "source_kind",
            "source_ref",
            "summary",
            "valid_from",
            "valid_to",
        }:
            raise TemporalContextError("candidate_schema_invalid")
        try:
            for key in (
                "category",
                "slot_key",
                "source_channel",
                "source_kind",
                "source_ref",
                "summary",
                "valid_from",
                "expires_at",
            ):
                if not isinstance(payload[key], str):
                    raise ValueError
            valid_to = payload["valid_to"]
            if valid_to is not None and not isinstance(valid_to, str):
                raise ValueError
            return cls(
                category=payload["category"],
                slot_key=payload["slot_key"],
                summary=payload["summary"],
                source_kind=payload["source_kind"],
                source_channel=payload["source_channel"],
                source_ref=payload["source_ref"],
                valid_from=datetime.fromisoformat(payload["valid_from"]),
                valid_to=(datetime.fromisoformat(valid_to) if valid_to else None),
                expires_at=datetime.fromisoformat(payload["expires_at"]),
            )
        except (TypeError, ValueError) as exc:
            raise TemporalContextError("candidate_schema_invalid") from exc

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.as_payload(), ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class TemporalFact:
    fact_id: str
    revision: int
    category: str
    slot_key: str
    summary: str
    source_kind: str
    source_channel: str
    source_ref: str
    observed_at: datetime
    valid_from: datetime
    valid_to: datetime | None
    expires_at: datetime
    state: str
    supersedes_fact_id: str | None

    def __post_init__(self) -> None:
        safe_label(self.fact_id, "fact_id")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 1
        ):
            raise TemporalContextError("revision_invalid")
        if self.state not in FACT_STATES:
            raise TemporalContextError("fact_state_invalid")
        draft = TemporalFactDraft(
            category=self.category,
            slot_key=self.slot_key,
            summary=self.summary,
            source_kind=self.source_kind,
            source_channel=self.source_channel,
            source_ref=self.source_ref,
            valid_from=self.valid_from,
            valid_to=self.valid_to,
            expires_at=self.expires_at,
        )
        observed = utc(self.observed_at, "observed_at")
        draft.validate_observed_at(observed)
        object.__setattr__(self, "observed_at", observed)
        if self.supersedes_fact_id is not None:
            safe_label(self.supersedes_fact_id, "supersedes_fact_id")
            if self.supersedes_fact_id == self.fact_id:
                raise TemporalContextError("supersede_cycle")

    @property
    def effective_end(self) -> datetime:
        return self.valid_to or self.expires_at


@dataclass(frozen=True, slots=True)
class TemporalLifecycleRecord:
    event_sequence: int
    event_kind: str
    transition: str
    reason: str
    trusted_time_source_class: str
    occurred_at: datetime
    fact_id: str
    revision: int
    category: str
    slot_key: str
    source_kind: str
    source_ref: str
    valid_from: datetime
    valid_to: datetime | None
    expires_at: datetime
    state: str
    supersedes_fact_id: str | None

    def __post_init__(self) -> None:
        if (
            isinstance(self.event_sequence, bool)
            or not isinstance(self.event_sequence, int)
            or self.event_sequence < 1
            or isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 1
        ):
            raise TemporalContextError("lifecycle_sequence_invalid")
        for value, label in (
            (self.event_kind, "event_kind"),
            (self.transition, "transition"),
            (self.reason, "reason"),
            (self.trusted_time_source_class, "trusted_time_source_class"),
        ):
            bounded_text(value, label, 128)
        safe_label(self.fact_id, "fact_id")
        safe_label(self.slot_key, "slot_key")
        safe_label(self.source_ref, "source_ref")
        if self.category not in TEMPORAL_CATEGORIES:
            raise TemporalContextError("category_prohibited")
        if self.source_kind not in SOURCE_KINDS:
            raise TemporalContextError("source_kind_rejected")
        if self.state not in FACT_STATES:
            raise TemporalContextError("fact_state_invalid")
        object.__setattr__(self, "occurred_at", utc(self.occurred_at, "occurred_at"))
        object.__setattr__(self, "valid_from", utc(self.valid_from, "valid_from"))
        object.__setattr__(
            self,
            "valid_to",
            None if self.valid_to is None else utc(self.valid_to, "valid_to"),
        )
        object.__setattr__(self, "expires_at", utc(self.expires_at, "expires_at"))
        if self.supersedes_fact_id is not None:
            safe_label(self.supersedes_fact_id, "supersedes_fact_id")

    def as_payload(self) -> dict[str, object]:
        return {
            "category": self.category,
            "event_kind": self.event_kind,
            "event_sequence": self.event_sequence,
            "expires_at": self.expires_at.isoformat(timespec="microseconds"),
            "fact_id": self.fact_id,
            "occurred_at": self.occurred_at.isoformat(timespec="microseconds"),
            "reason": self.reason,
            "revision": self.revision,
            "slot_key": self.slot_key,
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "state": self.state,
            "supersedes_fact_id": self.supersedes_fact_id,
            "transition": self.transition,
            "trusted_time_source_class": self.trusted_time_source_class,
            "valid_from": self.valid_from.isoformat(timespec="microseconds"),
            "valid_to": (
                None
                if self.valid_to is None
                else self.valid_to.isoformat(timespec="microseconds")
            ),
        }

@dataclass(frozen=True, slots=True)
class TemporalMutationResult:
    outcome: str
    fact: TemporalFact | None
    previous_state: str | None
    event_written: bool


@dataclass(frozen=True, slots=True)
class PreparedTemporalProposal:
    proposal_id: str
    confirmation_code: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class TemporalRetrievalResult:
    state: str
    query_characters: int
    facts: tuple[TemporalFact, ...]
    context: str | None
