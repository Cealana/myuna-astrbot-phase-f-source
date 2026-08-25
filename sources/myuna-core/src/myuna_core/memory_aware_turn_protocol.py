from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
import unicodedata
from typing import Literal, Mapping

PROTOCOL_SCHEMA = "myuna.memory-aware-turn-protocol.v1"
STEP_RESPONSE_SCHEMA = "myuna.memory-aware-turn-step-response.v1"
CATALOG_SCHEMA = "myuna.memory-aware-turn-catalog.v1"
RESULT_SCHEMA = "myuna.memory-aware-turn-result.v1"
RECEIPT_SCHEMA = "myuna.memory-aware-turn-receipt.v1"
OBLIGATION_SCHEMA = "myuna.memory-aware-turn-obligation.v1"
BUDGET_SCHEMA = "myuna.memory-aware-turn-budget.v1"

MEMORY_OPERATIONS = (
    "p07_search_references",
    "p07_fetch_sources",
    "p08_temporal_read",
    "profile_read",
    "p10b_trusted_time_read",
)
MEMORY_STATUSES = (
    "available",
    "available_empty",
    "unavailable",
    "paused",
    "uninitialized",
    "denied",
    "budget_exhausted",
    "snapshot_drift",
    "conflict",
    "rejected",
)
FINAL_RESOLUTIONS = ("answer", "uncertain", "clarify", "abstain")
SERVER_INTENT_KINDS = (
    "clarification_proposal",
    "follow_up_proposal",
    "profile_state_proposal",
)
OBLIGATION_REASONS = (
    "historical_reference",
    "indirect_historical_reference",
    "exact_source_claim",
    "relationship_change",
    "stale_or_conflicting_evidence",
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Finite product grammar: these phrases are the complete supported memory triggers.
_HISTORY_MARKERS = (
    "historical",
    "recall",
    "remember",
    "history",
    "previous",
    "before",
    "earlier",
    "last time",
    "last year",
    "last month",
    "last week",
    "prior",
    "past",
    "back when",
    "our first",
    "we discussed",
    "we talked about",
    "we spoke about",
    "what did we",
    "you told me",
    "i told you",
    "mentioned before",
    "used to",
    "曾经",
    "之前",
    "过去",
    "记得",
    "还记得",
    "刚才",
    "以前",
    "历史",
    "聊过",
    "说过",
    "提过",
    "当时",
    "那次",
    "上回",
    "第一次",
    "最早",
    "那年",
    "往事",
)
_INDIRECT_HISTORY_MARKERS = (
    "again",
    "as usual",
    "same as",
    "resume",
    "continue from",
    "continue where we left off",
    "pick up where we left off",
    "the usual",
    "like last time",
    "do the same",
    "same way",
    "usual way",
    "where we left off",
    "pick that up",
    "continue that",
    "上次",
    "又像",
    "像往常",
    "照旧",
    "还是一样",
    "老样子",
    "老规矩",
    "接着上回",
    "接着上次",
    "接着之前",
    "接着刚才",
    "继续上次",
    "继续之前",
    "继续刚才",
    "接着我们的计划",
    "继续我们的计划",
    "我们说好的",
    "那件事",
    "按以前",
    "照以前",
    "按原来",
    "延续之前",
)
_RELATIONSHIP_MARKERS = (
    "relationship changed",
    "relationship change",
    "closer now",
    "drifted apart",
    "关系变了",
    "关系变化",
    "更亲近",
    "疏远",
)
_STALE_CONFLICT_MARKERS = (
    "stale",
    "conflict",
    "contradiction",
    "outdated",
    "冲突",
    "矛盾",
    "过时",
)
_EXACT_CLAIM_MARKERS = (
    "exactly",
    "exact source",
    "original source",
    "according to the source",
    "cite the source",
    "show the source",
    "where did that come from",
    "original record",
    "verbatim",
    "quote",
    "quoted",
    "exact words",
    "what did i say",
    "what did you say",
    "on that date",
    "exact date",
    "precise date",
    "which date",
    "what date",
    "what day",
    "which day",
    "when exactly",
    "chronology",
    "timeline",
    "order of events",
    "event order",
    "sequence of events",
    "what happened first",
    "in what order",
    "which came first",
    "before or after",
    "precise",
    "specific number",
    "exact number",
    "how many",
    "exact amount",
    "specific amount",
    "quantity",
    "price",
    "原话",
    "逐字",
    "原文",
    "出处",
    "原始来源",
    "具体来源",
    "引用来源",
    "给出来源",
    "哪条记录",
    "原始记录",
    "准确日期",
    "具体日期",
    "哪一天",
    "哪天",
    "几号",
    "何时",
    "具体数字",
    "准确数字",
    "多少",
    "金额",
    "数量",
    "次数",
    "价格",
    "数值",
    "先后顺序",
    "先后",
    "时间线",
    "事件顺序",
    "先发生",
    "后发生",
)
_DECISION_CLAIM_MARKERS = (
    "decision",
    "decide",
    "decided",
    "agreement",
    "agree",
    "agreed",
    "choose",
    "chose",
    "决定",
    "决策",
    "约定",
    "同意",
    "选择",
)
_PROMISE_CLAIM_MARKERS = (
    "promise",
    "promised",
    "commitment",
    "committed to",
    "答应",
    "承诺",
    "说好",
)
_RELATIONSHIP_REASON_MARKERS = (
    "why did our relationship",
    "why our relationship",
    "reason our relationship",
    "reason we drifted apart",
    "why we drifted apart",
    "关系为什么",
    "为什么关系",
    "关系变化的原因",
    "疏远的原因",
    "为什么疏远",
    "更亲近的原因",
)
_PRECISE_DATE = re.compile(
    r"(?:\b(?:19|20)\d{2}[-/.年]\d{1,2}(?:[-/.月]\d{1,2}日?)?"
    r"|\b(?:january|february|march|april|may|june|july|august|september|"
    r"october|november|december)\s+\d{1,2}(?:st|nd|rd|th)?"
    r"(?:,\s*(?:19|20)\d{2})?\b"
    r"|[〇零一二三四五六七八九十百0-9]{2,4}年"
    r"[一二三四五六七八九十0-9]{1,3}月"
    r"[一二三四五六七八九十0-9]{1,3}日)"
)

MemoryOperation = Literal[
    "p07_search_references",
    "p07_fetch_sources",
    "p08_temporal_read",
    "profile_read",
    "p10b_trusted_time_read",
]
MemoryStatus = Literal[
    "available",
    "available_empty",
    "unavailable",
    "paused",
    "uninitialized",
    "denied",
    "budget_exhausted",
    "snapshot_drift",
    "conflict",
    "rejected",
]
FinalResolution = Literal["answer", "uncertain", "clarify", "abstain"]


class MemoryAwareTurnError(ValueError):
    """Content-free failure for the inactive memory-aware turn protocol."""

    def __init__(
        self,
        code: str,
        *,
        attempts: int = 0,
        repairable: bool = False,
    ) -> None:
        super().__init__(code)
        self.code = _safe_id(code, "error_code_invalid")
        self.attempts = _bounded_integer(
            attempts,
            "error_attempts_invalid",
            minimum=0,
            maximum=5,
        )
        self.repairable = repairable

    def content_free_projection(
        self,
        turn: TurnStepRequest | None = None,
    ) -> dict[str, object]:
        projection: dict[str, object] = {
            "attempts": self.attempts,
            "category": "memory_turn_rejected",
            "code": self.code,
            "repairable": self.repairable,
            "schema": PROTOCOL_SCHEMA,
        }
        if turn is not None:
            projection.update(
                {
                    "budget_digest": turn.budget.digest,
                    "continuation_digest": turn.continuation_digest,
                    "round_index": turn.round_index,
                    "turn_digest": turn.turn_digest,
                }
            )
        return projection


def _canonical(payload: object) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError):
        raise MemoryAwareTurnError("canonical_value_invalid") from None


def _digest(domain: bytes, payload: object) -> str:
    return sha256(domain + b"\0" + _canonical(payload)).hexdigest()


def _safe_id(value: object, code: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise MemoryAwareTurnError(code)
    return value


def _sha(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise MemoryAwareTurnError(code)
    return value


def _bounded_integer(
    value: object,
    code: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise MemoryAwareTurnError(code)
    return value


def _text(
    value: object,
    code: str,
    *,
    maximum_characters: int,
    maximum_bytes: int,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MemoryAwareTurnError(code)
    if any(ord(character) < 32 or 0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise MemoryAwareTurnError(code)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise MemoryAwareTurnError(code) from None
    if len(value) > maximum_characters or len(encoded) > maximum_bytes:
        raise MemoryAwareTurnError(code)
    return value


def _body_text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise MemoryAwareTurnError(code)
    if "\x00" in value or any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise MemoryAwareTurnError(code)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise MemoryAwareTurnError(code) from None
    return value


def _nfkc_casefold(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _lexical_text(value: str) -> str:
    normalized = _nfkc_casefold(value)
    selected = "".join(
        character
        if unicodedata.category(character)[0] in {"L", "M", "N"}
        else " "
        for character in normalized
    )
    return " ".join(selected.split())


def _compact_lmn(value: str) -> str:
    normalized = _nfkc_casefold(value)
    return "".join(
        character
        for character in normalized
        if unicodedata.category(character)[0] in {"L", "M", "N"}
    )


def _canonical_progress_text(value: str) -> str:
    selected = _compact_lmn(value)
    if not selected:
        raise MemoryAwareTurnError("memory_query_canonical_empty")
    return selected


def _contains_marker(value: str, markers: tuple[str, ...]) -> bool:
    lexical_value = _lexical_text(value)
    compact_value = _compact_lmn(value)
    for marker in markers:
        lexical_marker = _lexical_text(marker)
        if any(ord(character) > 127 for character in lexical_marker):
            if _compact_lmn(marker) in compact_value:
                return True
            continue
        pattern = (
            r"(?<!\w)"
            + re.escape(lexical_marker).replace(r"\ ", r"\s+")
            + r"(?!\w)"
        )
        if re.search(pattern, lexical_value) is not None:
            return True
    return False


def _exact_mapping(value: object, keys: set[str], code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise MemoryAwareTurnError(code)
    return value


def _ordered_digest(domain: bytes, values: tuple[str, ...]) -> str:
    return _digest(domain, {"digests": list(values)})


def _identity_digest(domain: bytes, value: object, code: str) -> str:
    selected = _safe_id(value, code)
    return sha256(domain + b"\0" + selected.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class TurnBudget:
    absolute_deadline_ns: int
    max_retrieval_rounds: int = 2
    max_provider_attempts: int = 4
    max_repairs: int = 1
    max_characters: int = 24_000
    max_utf8_bytes: int = 96_000
    max_input_token_upper_bound: int = 120_000
    output_token_reservation: int = 4_096
    max_result_count: int = 32

    def __post_init__(self) -> None:
        _bounded_integer(
            self.absolute_deadline_ns,
            "deadline_invalid",
            minimum=1,
            maximum=2**63 - 1,
        )
        _bounded_integer(
            self.max_retrieval_rounds,
            "retrieval_round_budget_invalid",
            minimum=0,
            maximum=3,
        )
        _bounded_integer(
            self.max_provider_attempts,
            "provider_attempt_budget_invalid",
            minimum=1,
            maximum=5,
        )
        _bounded_integer(
            self.max_repairs,
            "repair_budget_invalid",
            minimum=0,
            maximum=1,
        )
        _bounded_integer(
            self.max_characters,
            "character_budget_invalid",
            minimum=1,
            maximum=200_000,
        )
        _bounded_integer(
            self.max_utf8_bytes,
            "byte_budget_invalid",
            minimum=1,
            maximum=800_000,
        )
        _bounded_integer(
            self.max_input_token_upper_bound,
            "token_budget_invalid",
            minimum=1,
            maximum=800_000,
        )
        _bounded_integer(
            self.output_token_reservation,
            "output_reservation_invalid",
            minimum=1,
            maximum=32_768,
        )
        _bounded_integer(
            self.max_result_count,
            "result_count_budget_invalid",
            minimum=1,
            maximum=256,
        )
        minimum_attempts = self.max_retrieval_rounds + 2
        if self.max_provider_attempts < minimum_attempts:
            raise MemoryAwareTurnError("provider_attempt_budget_too_small")

    def as_payload(self) -> dict[str, object]:
        return {
            "absolute_deadline_ns": self.absolute_deadline_ns,
            "max_characters": self.max_characters,
            "max_input_token_upper_bound": self.max_input_token_upper_bound,
            "max_provider_attempts": self.max_provider_attempts,
            "max_repairs": self.max_repairs,
            "max_result_count": self.max_result_count,
            "max_retrieval_rounds": self.max_retrieval_rounds,
            "max_utf8_bytes": self.max_utf8_bytes,
            "output_token_reservation": self.output_token_reservation,
            "schema": BUDGET_SCHEMA,
        }

    @property
    def digest(self) -> str:
        return _digest(b"myuna-memory-turn-budget-v1", self.as_payload())


@dataclass(frozen=True, slots=True)
class MemoryCatalogEntry:
    operation: MemoryOperation
    scope_id: str
    availability: MemoryStatus
    snapshot_digest: str
    source_closure_digest: str

    def __post_init__(self) -> None:
        if self.operation not in MEMORY_OPERATIONS:
            raise MemoryAwareTurnError("catalog_operation_invalid")
        _safe_id(self.scope_id, "catalog_scope_invalid")
        if self.availability not in MEMORY_STATUSES:
            raise MemoryAwareTurnError("catalog_availability_invalid")
        _sha(self.snapshot_digest, "catalog_snapshot_invalid")
        _sha(self.source_closure_digest, "catalog_source_closure_invalid")

    def as_payload(self) -> dict[str, object]:
        return {
            "availability": self.availability,
            "operation": self.operation,
            "scope_id": self.scope_id,
            "snapshot_digest": self.snapshot_digest,
            "source_closure_digest": self.source_closure_digest,
        }


@dataclass(frozen=True, slots=True)
class MemoryCatalog:
    entries: tuple[MemoryCatalogEntry, ...]

    def __post_init__(self) -> None:
        if not self.entries:
            raise MemoryAwareTurnError("catalog_empty")
        identities: set[tuple[str, str]] = set()
        for entry in self.entries:
            if not isinstance(entry, MemoryCatalogEntry):
                raise MemoryAwareTurnError("catalog_entry_invalid")
            identity = (entry.operation, entry.scope_id)
            if identity in identities:
                raise MemoryAwareTurnError("catalog_entry_duplicate")
            identities.add(identity)
        ordered = tuple(
            sorted(self.entries, key=lambda item: (item.operation, item.scope_id))
        )
        if ordered != self.entries:
            raise MemoryAwareTurnError("catalog_order_invalid")

    def as_payload(self) -> dict[str, object]:
        return {
            "entries": [entry.as_payload() for entry in self.entries],
            "schema": CATALOG_SCHEMA,
        }

    @property
    def digest(self) -> str:
        return _digest(b"myuna-memory-turn-catalog-v1", self.as_payload())

    @property
    def snapshot_digest(self) -> str:
        return _digest(
            b"myuna-memory-turn-snapshot-set-v1",
            {
                "entries": [
                    {
                        "operation": entry.operation,
                        "scope_id": entry.scope_id,
                        "snapshot_digest": entry.snapshot_digest,
                    }
                    for entry in self.entries
                ]
            },
        )

    @property
    def source_closure_digest(self) -> str:
        return _digest(
            b"myuna-memory-turn-source-closure-set-v1",
            {
                "entries": [
                    {
                        "operation": entry.operation,
                        "scope_id": entry.scope_id,
                        "source_closure_digest": entry.source_closure_digest,
                    }
                    for entry in self.entries
                ]
            },
        )

    def require(self, operation: str, scope_id: str) -> MemoryCatalogEntry:
        for entry in self.entries:
            if entry.operation == operation and entry.scope_id == scope_id:
                return entry
        raise MemoryAwareTurnError("catalog_scope_not_authorized")

    def first_scope(self, operation: str) -> str | None:
        for entry in self.entries:
            if entry.operation == operation:
                return entry.scope_id
        return None


@dataclass(frozen=True, slots=True)
class RetrievalObligation:
    reason: str
    operation: MemoryOperation
    scope_id: str | None
    availability: Literal["available", "unavailable"] = "available"

    def __post_init__(self) -> None:
        if self.reason not in OBLIGATION_REASONS:
            raise MemoryAwareTurnError("obligation_reason_invalid")
        if self.operation not in MEMORY_OPERATIONS:
            raise MemoryAwareTurnError("obligation_operation_invalid")
        if self.availability not in {"available", "unavailable"}:
            raise MemoryAwareTurnError("obligation_availability_invalid")
        if self.availability == "available":
            _safe_id(self.scope_id, "obligation_scope_invalid")
        elif self.scope_id is not None:
            raise MemoryAwareTurnError("unavailable_obligation_scope_present")

    def as_payload(self) -> dict[str, object]:
        return {
            "availability": self.availability,
            "operation": self.operation,
            "reason": self.reason,
            "schema": OBLIGATION_SCHEMA,
            "scope_id": self.scope_id,
        }

    @property
    def digest(self) -> str:
        return _digest(b"myuna-memory-turn-obligation-v1", self.as_payload())


@dataclass(frozen=True, slots=True)
class MemoryRequest:
    operation: MemoryOperation
    scope_id: str
    query: str = field(repr=False)
    turn_digest: str
    catalog_digest: str
    snapshot_digest: str
    source_closure_digest: str
    continuation_digest: str
    budget_digest: str
    obligation_digest: str
    round_index: int
    selection_digest: str | None = None
    parent_receipt_digest: str | None = None

    def __post_init__(self) -> None:
        if self.operation not in MEMORY_OPERATIONS:
            raise MemoryAwareTurnError("memory_operation_invalid")
        _safe_id(self.scope_id, "memory_scope_invalid")
        _text(
            self.query,
            "memory_query_invalid",
            maximum_characters=4_096,
            maximum_bytes=16_384,
        )
        for value, code in (
            (self.turn_digest, "memory_turn_binding_invalid"),
            (self.catalog_digest, "memory_catalog_binding_invalid"),
            (self.snapshot_digest, "memory_snapshot_binding_invalid"),
            (self.source_closure_digest, "memory_source_closure_binding_invalid"),
            (self.continuation_digest, "memory_continuation_binding_invalid"),
            (self.budget_digest, "memory_budget_binding_invalid"),
            (self.obligation_digest, "memory_obligation_binding_invalid"),
        ):
            _sha(value, code)
        _bounded_integer(
            self.round_index,
            "memory_round_invalid",
            minimum=0,
            maximum=3,
        )
        if self.selection_digest is not None:
            _sha(self.selection_digest, "memory_selection_binding_invalid")
        if self.parent_receipt_digest is not None:
            _sha(self.parent_receipt_digest, "memory_parent_receipt_invalid")
        if self.operation == "p07_fetch_sources":
            if self.selection_digest is None or self.parent_receipt_digest is None:
                raise MemoryAwareTurnError("fetch_search_binding_missing")
        elif self.selection_digest is not None or self.parent_receipt_digest is not None:
            raise MemoryAwareTurnError("memory_search_binding_unexpected")

    @property
    def query_digest(self) -> str:
        return _digest(b"myuna-memory-turn-query-v1", {"query": self.query})

    def binding_payload(self) -> dict[str, object]:
        return {
            "budget_digest": self.budget_digest,
            "catalog_digest": self.catalog_digest,
            "continuation_digest": self.continuation_digest,
            "obligation_digest": self.obligation_digest,
            "round_index": self.round_index,
            "snapshot_digest": self.snapshot_digest,
            "source_closure_digest": self.source_closure_digest,
            "turn_digest": self.turn_digest,
        }

    def as_payload(self, *, include_query: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "operation": self.operation,
            "parent_receipt_digest": self.parent_receipt_digest,
            "query_digest": self.query_digest,
            "scope_id": self.scope_id,
            "selection_digest": self.selection_digest,
            **self.binding_payload(),
        }
        if include_query:
            payload["query"] = self.query
        return payload

    @property
    def digest(self) -> str:
        return _digest(b"myuna-memory-turn-request-v1", self.as_payload())


def memory_request_progress_fingerprint(request: MemoryRequest) -> str:
    """Return a content-free equivalence key for bounded loop progress."""

    if not isinstance(request, MemoryRequest):
        raise MemoryAwareTurnError("memory_request_type_invalid")
    return _digest(
        b"myuna-memory-turn-progress-v1",
        {
            "normalized_query": _canonical_progress_text(request.query),
            "operation": request.operation,
            "parent_receipt_digest": request.parent_receipt_digest,
            "scope_id": request.scope_id,
            "selection_digest": request.selection_digest,
        },
    )


@dataclass(frozen=True, slots=True)
class MemoryResult:
    request_digest: str
    operation: MemoryOperation
    scope_id: str
    status: MemoryStatus
    values: tuple[str, ...] = field(repr=False)
    snapshot_digest: str = ""
    source_closure_digest: str = ""
    selection_digest: str | None = None
    parent_receipt_digest: str | None = None

    def __post_init__(self) -> None:
        _sha(self.request_digest, "result_request_binding_invalid")
        if self.operation not in MEMORY_OPERATIONS:
            raise MemoryAwareTurnError("result_operation_invalid")
        _safe_id(self.scope_id, "result_scope_invalid")
        if self.status not in MEMORY_STATUSES:
            raise MemoryAwareTurnError("result_status_invalid")
        _sha(self.snapshot_digest, "result_snapshot_invalid")
        _sha(self.source_closure_digest, "result_source_closure_invalid")
        for value in self.values:
            _body_text(value, "result_value_invalid")
        if self.status == "available" and not self.values:
            raise MemoryAwareTurnError("available_result_empty")
        if self.status != "available" and self.values:
            raise MemoryAwareTurnError("nonavailable_result_has_values")
        if self.selection_digest is not None:
            _sha(self.selection_digest, "result_selection_invalid")
        if self.parent_receipt_digest is not None:
            _sha(self.parent_receipt_digest, "result_parent_receipt_invalid")

    @property
    def values_digest(self) -> str:
        return _digest(b"myuna-memory-turn-result-values-v1", {"values": list(self.values)})

    def content_free_payload(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "parent_receipt_digest": self.parent_receipt_digest,
            "request_digest": self.request_digest,
            "result_count": len(self.values),
            "schema": RESULT_SCHEMA,
            "scope_id": self.scope_id,
            "selection_digest": self.selection_digest,
            "snapshot_digest": self.snapshot_digest,
            "source_closure_digest": self.source_closure_digest,
            "status": self.status,
            "values_digest": self.values_digest,
        }

    @property
    def digest(self) -> str:
        return _digest(b"myuna-memory-turn-result-v1", self.content_free_payload())


def _validate_result_budgets(
    budget: TurnBudget,
    results: tuple[MemoryResult, ...],
) -> None:
    values = tuple(value for result in results for value in result.values)
    if len(values) > budget.max_result_count:
        raise MemoryAwareTurnError("result_count_budget_exhausted")
    if sum(len(value) for value in values) > budget.max_characters:
        raise MemoryAwareTurnError("result_character_budget_exhausted")
    if sum(len(value.encode("utf-8")) for value in values) > budget.max_utf8_bytes:
        raise MemoryAwareTurnError("result_byte_budget_exhausted")


@dataclass(frozen=True, slots=True)
class MemoryReceipt:
    receipt_id: str
    request_digest: str
    result_digest: str
    operation: MemoryOperation
    scope_id: str
    status: MemoryStatus
    turn_digest: str
    snapshot_digest: str
    source_closure_digest: str
    continuation_digest: str
    query_digest: str
    result_count: int
    selection_digest: str | None = None
    parent_receipt_digest: str | None = None

    def __post_init__(self) -> None:
        _safe_id(self.receipt_id, "receipt_id_invalid")
        for value, code in (
            (self.request_digest, "receipt_request_binding_invalid"),
            (self.result_digest, "receipt_result_binding_invalid"),
            (self.turn_digest, "receipt_turn_binding_invalid"),
            (self.snapshot_digest, "receipt_snapshot_binding_invalid"),
            (self.source_closure_digest, "receipt_source_closure_binding_invalid"),
            (self.continuation_digest, "receipt_continuation_binding_invalid"),
            (self.query_digest, "receipt_query_binding_invalid"),
        ):
            _sha(value, code)
        if self.operation not in MEMORY_OPERATIONS:
            raise MemoryAwareTurnError("receipt_operation_invalid")
        _safe_id(self.scope_id, "receipt_scope_invalid")
        if self.status not in MEMORY_STATUSES:
            raise MemoryAwareTurnError("receipt_status_invalid")
        _bounded_integer(
            self.result_count,
            "receipt_result_count_invalid",
            minimum=0,
            maximum=256,
        )
        if self.selection_digest is not None:
            _sha(self.selection_digest, "receipt_selection_invalid")
        if self.parent_receipt_digest is not None:
            _sha(self.parent_receipt_digest, "receipt_parent_invalid")

    def as_payload(self) -> dict[str, object]:
        return {
            "continuation_digest": self.continuation_digest,
            "operation": self.operation,
            "parent_receipt_digest": self.parent_receipt_digest,
            "query_digest": self.query_digest,
            "receipt_id": self.receipt_id,
            "request_digest": self.request_digest,
            "result_count": self.result_count,
            "result_digest": self.result_digest,
            "schema": RECEIPT_SCHEMA,
            "scope_id": self.scope_id,
            "selection_digest": self.selection_digest,
            "snapshot_digest": self.snapshot_digest,
            "source_closure_digest": self.source_closure_digest,
            "status": self.status,
            "turn_digest": self.turn_digest,
        }

    @property
    def digest(self) -> str:
        return _digest(b"myuna-memory-turn-receipt-v1", self.as_payload())


def _continuation_value(
    *,
    turn_digest: str,
    catalog_digest: str,
    snapshot_digest: str,
    source_closure_digest: str,
    budget_digest: str,
    round_index: int,
    provider_attempts_used: int,
    repairs_used: int,
    obligations: tuple[RetrievalObligation, ...],
    results: tuple[MemoryResult, ...],
    receipts: tuple[MemoryReceipt, ...],
) -> str:
    return _digest(
        b"myuna-memory-turn-continuation-v1",
        {
            "budget_digest": budget_digest,
            "catalog_digest": catalog_digest,
            "obligation_digests": [item.digest for item in obligations],
            "provider_attempts_used": provider_attempts_used,
            "receipt_digests": [item.digest for item in receipts],
            "repairs_used": repairs_used,
            "result_digests": [item.digest for item in results],
            "round_index": round_index,
            "snapshot_digest": snapshot_digest,
            "source_closure_digest": source_closure_digest,
            "turn_digest": turn_digest,
        },
    )


@dataclass(frozen=True, slots=True)
class TurnStepRequest:
    owner_principal_digest: str
    conversation_digest: str
    turn_identity_digest: str
    request_identity_digest: str
    owner_message: str = field(repr=False)
    catalog: MemoryCatalog
    budget: TurnBudget
    continuation_digest: str
    round_index: int = 0
    provider_attempts_used: int = 0
    repairs_used: int = 0
    obligations: tuple[RetrievalObligation, ...] = ()
    results: tuple[MemoryResult, ...] = field(default=(), repr=False)
    receipts: tuple[MemoryReceipt, ...] = ()

    def __post_init__(self) -> None:
        for value, code in (
            (self.owner_principal_digest, "owner_binding_invalid"),
            (self.conversation_digest, "conversation_binding_invalid"),
            (self.turn_identity_digest, "turn_identity_binding_invalid"),
            (self.request_identity_digest, "request_identity_binding_invalid"),
            (self.continuation_digest, "continuation_binding_invalid"),
        ):
            _sha(value, code)
        if not isinstance(self.catalog, MemoryCatalog) or not isinstance(self.budget, TurnBudget):
            raise MemoryAwareTurnError("turn_dependency_invalid")
        _text(
            self.owner_message,
            "owner_message_invalid",
            maximum_characters=self.budget.max_characters,
            maximum_bytes=self.budget.max_utf8_bytes,
        )
        _bounded_integer(
            self.round_index,
            "turn_round_invalid",
            minimum=0,
            maximum=3,
        )
        _bounded_integer(
            self.provider_attempts_used,
            "turn_provider_attempts_invalid",
            minimum=0,
            maximum=5,
        )
        _bounded_integer(
            self.repairs_used,
            "turn_repairs_invalid",
            minimum=0,
            maximum=1,
        )
        if len(self.results) != len(self.receipts) or self.round_index != len(self.results):
            raise MemoryAwareTurnError("turn_history_shape_invalid")
        _validate_result_budgets(self.budget, self.results)
        if self.round_index > self.budget.max_retrieval_rounds:
            raise MemoryAwareTurnError("turn_round_budget_exhausted")
        if self.provider_attempts_used > self.budget.max_provider_attempts:
            raise MemoryAwareTurnError("turn_provider_budget_exhausted")
        if self.repairs_used > self.budget.max_repairs:
            raise MemoryAwareTurnError("turn_repair_budget_exhausted")
        if tuple(sorted(self.obligations, key=lambda item: item.digest)) != self.obligations:
            raise MemoryAwareTurnError("turn_obligation_order_invalid")
        expected = _continuation_value(
            turn_digest=self.turn_digest,
            catalog_digest=self.catalog.digest,
            snapshot_digest=self.catalog.snapshot_digest,
            source_closure_digest=self.catalog.source_closure_digest,
            budget_digest=self.budget.digest,
            round_index=self.round_index,
            provider_attempts_used=self.provider_attempts_used,
            repairs_used=self.repairs_used,
            obligations=self.obligations,
            results=self.results,
            receipts=self.receipts,
        )
        if self.continuation_digest != expected:
            raise MemoryAwareTurnError("continuation_binding_mismatch")

    @property
    def owner_message_digest(self) -> str:
        return _digest(b"myuna-memory-turn-owner-message-v1", {"value": self.owner_message})

    @property
    def turn_digest(self) -> str:
        return _digest(
            b"myuna-memory-turn-v1",
            {
                "conversation_digest": self.conversation_digest,
                "owner_message_digest": self.owner_message_digest,
                "owner_principal_digest": self.owner_principal_digest,
                "request_identity_digest": self.request_identity_digest,
                "turn_identity_digest": self.turn_identity_digest,
            },
        )

    @property
    def obligation_digest(self) -> str:
        return _ordered_digest(
            b"myuna-memory-turn-obligations-v1",
            tuple(item.digest for item in self.obligations),
        )

    @property
    def ordered_result_digest(self) -> str:
        return _ordered_digest(
            b"myuna-memory-turn-results-v1",
            tuple(item.digest for item in self.results),
        )

    @property
    def ordered_receipt_digest(self) -> str:
        return _ordered_digest(
            b"myuna-memory-turn-receipts-v1",
            tuple(item.digest for item in self.receipts),
        )

    def bindings_payload(self) -> dict[str, object]:
        return {
            "budget_digest": self.budget.digest,
            "catalog_digest": self.catalog.digest,
            "continuation_digest": self.continuation_digest,
            "conversation_digest": self.conversation_digest,
            "obligation_digest": self.obligation_digest,
            "ordered_receipt_digest": self.ordered_receipt_digest,
            "ordered_result_digest": self.ordered_result_digest,
            "owner_message_digest": self.owner_message_digest,
            "owner_principal_digest": self.owner_principal_digest,
            "provider_attempts_used": self.provider_attempts_used,
            "repairs_used": self.repairs_used,
            "request_identity_digest": self.request_identity_digest,
            "round_index": self.round_index,
            "snapshot_digest": self.catalog.snapshot_digest,
            "source_closure_digest": self.catalog.source_closure_digest,
            "turn_digest": self.turn_digest,
            "turn_identity_digest": self.turn_identity_digest,
        }

    def provider_payload(self, *, repair: bool) -> dict[str, object]:
        return {
            "bindings": self.bindings_payload(),
            "budget": self.budget.as_payload(),
            "catalog": self.catalog.as_payload(),
            "obligations": [item.as_payload() for item in self.obligations],
            "owner_message": self.owner_message,
            "prior_receipts": [item.as_payload() for item in self.receipts],
            "prior_results": [
                {
                    **item.content_free_payload(),
                    "values": list(item.values),
                }
                for item in self.results
            ],
            "repair": repair,
            "schema": PROTOCOL_SCHEMA,
        }


@dataclass(frozen=True, slots=True)
class ServerIntentProposal:
    intent_id: str
    kind: str
    proposal_digest: str
    action: str | None = None
    field_id: str | None = None
    requested_delta: int | None = None
    reason_category: str | None = None
    source_interval_id: str | None = None

    @classmethod
    def profile_state(
        cls,
        *,
        intent_id: str,
        requested_delta: int,
        reason_category: str = "delivered_turn",
        source_interval_id: str | None = None,
    ) -> ServerIntentProposal:
        payload = {
            "action": "delta",
            "field_id": "relationship_state.intimacy_headline",
            "intent_id": intent_id,
            "kind": "profile_state_proposal",
            "reason_category": reason_category,
            "requested_delta": requested_delta,
            "source_interval_id": source_interval_id,
        }
        return cls(
            intent_id=intent_id,
            kind="profile_state_proposal",
            proposal_digest=_digest(
                b"myuna-profile-state-server-intent-v2",
                payload,
            ),
            action="delta",
            field_id="relationship_state.intimacy_headline",
            requested_delta=requested_delta,
            reason_category=reason_category,
            source_interval_id=source_interval_id,
        )

    def __post_init__(self) -> None:
        _safe_id(self.intent_id, "server_intent_id_invalid")
        if self.kind not in SERVER_INTENT_KINDS:
            raise MemoryAwareTurnError("server_intent_kind_invalid")
        _sha(self.proposal_digest, "server_intent_digest_invalid")
        profile_values = (
            self.action,
            self.field_id,
            self.requested_delta,
            self.reason_category,
            self.source_interval_id,
        )
        if self.kind == "profile_state_proposal":
            if (
                self.action != "delta"
                or self.field_id != "relationship_state.intimacy_headline"
                or isinstance(self.requested_delta, bool)
                or not isinstance(self.requested_delta, int)
                or self.requested_delta == 0
                or abs(self.requested_delta) > 20_000
                or self.reason_category not in {"delivered_turn", "episode_end"}
                or (
                    self.reason_category == "episode_end"
                    and not isinstance(self.source_interval_id, str)
                )
                or (
                    self.reason_category == "delivered_turn"
                    and self.source_interval_id is not None
                )
            ):
                raise MemoryAwareTurnError("server_intent_profile_binding_invalid")
            if self.source_interval_id is not None:
                _safe_id(
                    self.source_interval_id,
                    "server_intent_profile_source_invalid",
                )
            expected = _digest(
                b"myuna-profile-state-server-intent-v2",
                {
                    "action": self.action,
                    "field_id": self.field_id,
                    "intent_id": self.intent_id,
                    "kind": self.kind,
                    "reason_category": self.reason_category,
                    "requested_delta": self.requested_delta,
                    "source_interval_id": self.source_interval_id,
                },
            )
            if self.proposal_digest != expected:
                raise MemoryAwareTurnError("server_intent_profile_digest_mismatch")
        elif any(value is not None for value in profile_values):
            raise MemoryAwareTurnError("server_intent_profile_fields_rejected")

    def as_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "intent_id": self.intent_id,
            "kind": self.kind,
            "proposal_digest": self.proposal_digest,
        }
        if self.kind == "profile_state_proposal":
            payload.update(
                {
                    "action": self.action,
                    "field_id": self.field_id,
                    "reason_category": self.reason_category,
                    "requested_delta": self.requested_delta,
                    "source_interval_id": self.source_interval_id,
                }
            )
        return payload


@dataclass(frozen=True, slots=True)
class FinalBranch:
    owner_message: str = field(repr=False)
    resolution: FinalResolution
    receipt_digests: tuple[str, ...]
    uncertainty_statuses: tuple[MemoryStatus, ...]
    server_intents: tuple[ServerIntentProposal, ...] = ()

    def __post_init__(self) -> None:
        _text(
            self.owner_message,
            "final_owner_message_invalid",
            maximum_characters=24_000,
            maximum_bytes=96_000,
        )
        if self.resolution not in FINAL_RESOLUTIONS:
            raise MemoryAwareTurnError("final_resolution_invalid")
        for digest in self.receipt_digests:
            _sha(digest, "final_receipt_digest_invalid")
        if len(set(self.receipt_digests)) != len(self.receipt_digests):
            raise MemoryAwareTurnError("final_receipt_duplicate")
        if tuple(sorted(set(self.uncertainty_statuses))) != self.uncertainty_statuses:
            raise MemoryAwareTurnError("final_uncertainty_order_invalid")
        if any(
            status not in MEMORY_STATUSES or status == "available"
            for status in self.uncertainty_statuses
        ):
            raise MemoryAwareTurnError("final_uncertainty_status_invalid")
        if len({item.intent_id for item in self.server_intents}) != len(self.server_intents):
            raise MemoryAwareTurnError("server_intent_duplicate")

    def as_payload(self, *, include_owner_message: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "receipt_digests": list(self.receipt_digests),
            "resolution": self.resolution,
            "server_intents": [item.as_payload() for item in self.server_intents],
            "uncertainty_statuses": list(self.uncertainty_statuses),
        }
        if include_owner_message:
            payload["owner_message"] = self.owner_message
        return payload


@dataclass(frozen=True, slots=True)
class FinalValue:
    owner_message: str = field(repr=False)
    resolution: FinalResolution
    server_intents: tuple[ServerIntentProposal, ...]
    receipt_digests: tuple[str, ...]
    turn_digest: str
    continuation_digest: str
    provider_attempts_used: int
    retrieval_rounds: int

    def content_free_projection(self) -> dict[str, object]:
        return {
            "continuation_digest": self.continuation_digest,
            "provider_attempts_used": self.provider_attempts_used,
            "receipt_count": len(self.receipt_digests),
            "resolution": self.resolution,
            "retrieval_rounds": self.retrieval_rounds,
            "schema": PROTOCOL_SCHEMA,
            "server_intent_count": len(self.server_intents),
            "turn_digest": self.turn_digest,
        }


def _obligation(
    catalog: MemoryCatalog,
    *,
    reason: str,
    operation: MemoryOperation,
) -> RetrievalObligation:
    scope_id = catalog.first_scope(operation)
    return RetrievalObligation(
        reason=reason,
        operation=operation,
        scope_id=scope_id,
        availability="available" if scope_id is not None else "unavailable",
    )


def derive_obligations(
    text: str,
    catalog: MemoryCatalog,
    *,
    include_exact_claims: bool,
) -> tuple[RetrievalObligation, ...]:
    source = _body_text(text, "obligation_text_invalid")
    normalized = _nfkc_casefold(source)
    obligations: dict[str, RetrievalObligation] = {}

    def add(reason: str, operation: MemoryOperation) -> None:
        item = _obligation(catalog, reason=reason, operation=operation)
        obligations[item.digest] = item

    historical_reference = _contains_marker(source, _HISTORY_MARKERS)
    indirect_historical_reference = _contains_marker(
        source,
        _INDIRECT_HISTORY_MARKERS,
    )
    if historical_reference:
        add("historical_reference", "p07_search_references")
    if indirect_historical_reference:
        add("indirect_historical_reference", "p07_search_references")
    if _contains_marker(source, _RELATIONSHIP_MARKERS):
        add("relationship_change", "profile_read")
    if _contains_marker(source, _STALE_CONFLICT_MARKERS):
        add("stale_or_conflicting_evidence", "p08_temporal_read")
    if include_exact_claims and (
        _contains_marker(source, _EXACT_CLAIM_MARKERS)
        or (
            (historical_reference or indirect_historical_reference)
            and _contains_marker(source, _DECISION_CLAIM_MARKERS)
        )
        or (
            (historical_reference or indirect_historical_reference)
            and (
                _contains_marker(source, _PROMISE_CLAIM_MARKERS)
                or _contains_marker(source, _RELATIONSHIP_REASON_MARKERS)
            )
        )
        or re.search(r"(?:^|\D)\d{2,}(?:\D|$)", normalized) is not None
        or _PRECISE_DATE.search(normalized) is not None
        or any(
            character in normalized
            for character in (
                '"',
                "`",
                "\u201c",
                "\u201d",
                "\u300c",
                "\u300d",
                "\u300e",
                "\u300f",
            )
        )
    ):
        add("exact_source_claim", "p07_fetch_sources")
    return tuple(obligations[key] for key in sorted(obligations))


def _build_turn(
    *,
    owner_principal_digest: str,
    conversation_digest: str,
    turn_identity_digest: str,
    request_identity_digest: str,
    owner_message: str,
    catalog: MemoryCatalog,
    budget: TurnBudget,
    round_index: int,
    provider_attempts_used: int,
    repairs_used: int,
    obligations: tuple[RetrievalObligation, ...],
    results: tuple[MemoryResult, ...],
    receipts: tuple[MemoryReceipt, ...],
) -> TurnStepRequest:
    provisional = object.__new__(TurnStepRequest)
    object.__setattr__(provisional, "owner_principal_digest", owner_principal_digest)
    object.__setattr__(provisional, "conversation_digest", conversation_digest)
    object.__setattr__(provisional, "turn_identity_digest", turn_identity_digest)
    object.__setattr__(provisional, "request_identity_digest", request_identity_digest)
    object.__setattr__(provisional, "owner_message", owner_message)
    object.__setattr__(provisional, "catalog", catalog)
    object.__setattr__(provisional, "budget", budget)
    object.__setattr__(provisional, "continuation_digest", "0" * 64)
    object.__setattr__(provisional, "round_index", round_index)
    object.__setattr__(provisional, "provider_attempts_used", provider_attempts_used)
    object.__setattr__(provisional, "repairs_used", repairs_used)
    object.__setattr__(provisional, "obligations", obligations)
    object.__setattr__(provisional, "results", results)
    object.__setattr__(provisional, "receipts", receipts)
    continuation_digest = _continuation_value(
        turn_digest=provisional.turn_digest,
        catalog_digest=catalog.digest,
        snapshot_digest=catalog.snapshot_digest,
        source_closure_digest=catalog.source_closure_digest,
        budget_digest=budget.digest,
        round_index=round_index,
        provider_attempts_used=provider_attempts_used,
        repairs_used=repairs_used,
        obligations=obligations,
        results=results,
        receipts=receipts,
    )
    return TurnStepRequest(
        owner_principal_digest=owner_principal_digest,
        conversation_digest=conversation_digest,
        turn_identity_digest=turn_identity_digest,
        request_identity_digest=request_identity_digest,
        owner_message=owner_message,
        catalog=catalog,
        budget=budget,
        continuation_digest=continuation_digest,
        round_index=round_index,
        provider_attempts_used=provider_attempts_used,
        repairs_used=repairs_used,
        obligations=obligations,
        results=results,
        receipts=receipts,
    )


def create_turn_step(
    *,
    owner_principal_id: str,
    conversation_id: str,
    turn_id: str,
    request_id: str,
    owner_message: str,
    catalog: MemoryCatalog,
    budget: TurnBudget,
) -> TurnStepRequest:
    owner_digest = _identity_digest(
        b"myuna-memory-turn-owner-v1", owner_principal_id, "owner_id_invalid"
    )
    conversation_digest = _identity_digest(
        b"myuna-memory-turn-conversation-v1",
        conversation_id,
        "conversation_id_invalid",
    )
    turn_identity_digest = _identity_digest(
        b"myuna-memory-turn-identity-v1",
        turn_id,
        "turn_id_invalid",
    )
    request_digest = _identity_digest(
        b"myuna-memory-turn-request-identity-v1",
        request_id,
        "request_id_invalid",
    )
    obligations = derive_obligations(owner_message, catalog, include_exact_claims=True)
    return _build_turn(
        owner_principal_digest=owner_digest,
        conversation_digest=conversation_digest,
        turn_identity_digest=turn_identity_digest,
        request_identity_digest=request_digest,
        owner_message=owner_message,
        catalog=catalog,
        budget=budget,
        round_index=0,
        provider_attempts_used=0,
        repairs_used=0,
        obligations=obligations,
        results=(),
        receipts=(),
    )


_BINDING_KEYS = {
    "budget_digest",
    "catalog_digest",
    "continuation_digest",
    "conversation_digest",
    "obligation_digest",
    "ordered_receipt_digest",
    "ordered_result_digest",
    "owner_message_digest",
    "owner_principal_digest",
    "provider_attempts_used",
    "repairs_used",
    "request_identity_digest",
    "round_index",
    "snapshot_digest",
    "source_closure_digest",
    "turn_digest",
    "turn_identity_digest",
}


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MemoryAwareTurnError("provider_duplicate_field", repairable=True)
        result[key] = value
    return result


def _parse_json(value: str | bytes, budget: TurnBudget) -> Mapping[str, object]:
    if isinstance(value, bytes):
        if len(value) > budget.max_utf8_bytes:
            raise MemoryAwareTurnError("provider_response_budget_exhausted", repairable=True)
        try:
            selected = value.decode("utf-8")
        except UnicodeDecodeError:
            raise MemoryAwareTurnError(
                "provider_response_encoding_invalid",
                repairable=True,
            ) from None
    elif isinstance(value, str):
        selected = value
    else:
        raise MemoryAwareTurnError("provider_response_type_invalid", repairable=True)
    if (
        len(selected) > budget.max_characters
        or len(selected.encode("utf-8")) > budget.max_utf8_bytes
    ):
        raise MemoryAwareTurnError("provider_response_budget_exhausted", repairable=True)
    try:
        payload = json.loads(selected, object_pairs_hook=_reject_duplicate_pairs)
    except MemoryAwareTurnError:
        raise
    except (json.JSONDecodeError, UnicodeEncodeError):
        raise MemoryAwareTurnError("provider_response_invalid", repairable=True) from None
    if not isinstance(payload, Mapping):
        raise MemoryAwareTurnError("provider_response_invalid", repairable=True)
    return payload


def _require_bindings(payload: object, turn: TurnStepRequest) -> None:
    selected = _exact_mapping(payload, _BINDING_KEYS, "provider_bindings_invalid")
    if dict(selected) != turn.bindings_payload():
        raise MemoryAwareTurnError("provider_binding_mismatch")


def parse_provider_step(
    value: str | bytes,
    turn: TurnStepRequest,
) -> MemoryRequest | FinalBranch:
    payload = _parse_json(value, turn.budget)
    schema = payload.get("schema")
    branch = payload.get("branch")
    if schema != STEP_RESPONSE_SCHEMA:
        raise MemoryAwareTurnError("provider_schema_invalid", repairable=True)
    if branch == "memory_request":
        selected = _exact_mapping(
            payload,
            {"bindings", "branch", "memory_request", "schema"},
            "provider_memory_branch_invalid",
        )
        _require_bindings(selected["bindings"], turn)
        request_payload = _exact_mapping(
            selected["memory_request"],
            {
                "operation",
                "parent_receipt_digest",
                "query",
                "scope_id",
                "selection_digest",
            },
            "provider_memory_request_invalid",
        )
        request = MemoryRequest(
            operation=request_payload["operation"],  # type: ignore[arg-type]
            scope_id=request_payload["scope_id"],  # type: ignore[arg-type]
            query=request_payload["query"],  # type: ignore[arg-type]
            turn_digest=turn.turn_digest,
            catalog_digest=turn.catalog.digest,
            snapshot_digest=turn.catalog.snapshot_digest,
            source_closure_digest=turn.catalog.source_closure_digest,
            continuation_digest=turn.continuation_digest,
            budget_digest=turn.budget.digest,
            obligation_digest=turn.obligation_digest,
            round_index=turn.round_index,
            selection_digest=request_payload["selection_digest"],  # type: ignore[arg-type]
            parent_receipt_digest=request_payload[
                "parent_receipt_digest"
            ],  # type: ignore[arg-type]
        )
        validate_memory_request(turn, request)
        return request
    if branch == "final":
        selected = _exact_mapping(
            payload,
            {"bindings", "branch", "final", "schema"},
            "provider_final_branch_invalid",
        )
        _require_bindings(selected["bindings"], turn)
        final_payload = _exact_mapping(
            selected["final"],
            {
                "owner_message",
                "receipt_digests",
                "resolution",
                "server_intents",
                "uncertainty_statuses",
            },
            "provider_final_invalid",
        )
        raw_receipts = final_payload["receipt_digests"]
        raw_statuses = final_payload["uncertainty_statuses"]
        raw_intents = final_payload["server_intents"]
        if (
            not isinstance(raw_receipts, list)
            or not isinstance(raw_statuses, list)
            or not isinstance(raw_intents, list)
        ):
            raise MemoryAwareTurnError("provider_final_invalid", repairable=True)
        intents: list[ServerIntentProposal] = []
        for raw_intent in raw_intents:
            if not isinstance(raw_intent, Mapping):
                raise MemoryAwareTurnError(
                    "provider_server_intent_invalid", repairable=True
                )
            profile_intent = raw_intent.get("kind") == "profile_state_proposal"
            intent = _exact_mapping(
                raw_intent,
                (
                    {
                        "action",
                        "field_id",
                        "intent_id",
                        "kind",
                        "proposal_digest",
                        "reason_category",
                        "requested_delta",
                        "source_interval_id",
                    }
                    if profile_intent
                    else {"intent_id", "kind", "proposal_digest"}
                ),
                "provider_server_intent_invalid",
            )
            intents.append(
                ServerIntentProposal(
                    intent_id=intent["intent_id"],  # type: ignore[arg-type]
                    kind=intent["kind"],  # type: ignore[arg-type]
                    proposal_digest=intent["proposal_digest"],  # type: ignore[arg-type]
                    action=intent.get("action"),  # type: ignore[arg-type]
                    field_id=intent.get("field_id"),  # type: ignore[arg-type]
                    reason_category=intent.get("reason_category"),  # type: ignore[arg-type]
                    requested_delta=intent.get("requested_delta"),  # type: ignore[arg-type]
                    source_interval_id=intent.get("source_interval_id"),  # type: ignore[arg-type]
                )
            )
        return FinalBranch(
            owner_message=final_payload["owner_message"],  # type: ignore[arg-type]
            resolution=final_payload["resolution"],  # type: ignore[arg-type]
            receipt_digests=tuple(raw_receipts),  # type: ignore[arg-type]
            uncertainty_statuses=tuple(raw_statuses),  # type: ignore[arg-type]
            server_intents=tuple(intents),
        )
    raise MemoryAwareTurnError("provider_branch_invalid", repairable=True)


def validate_memory_request(turn: TurnStepRequest, request: MemoryRequest) -> None:
    if request.binding_payload() != {
        "budget_digest": turn.budget.digest,
        "catalog_digest": turn.catalog.digest,
        "continuation_digest": turn.continuation_digest,
        "obligation_digest": turn.obligation_digest,
        "round_index": turn.round_index,
        "snapshot_digest": turn.catalog.snapshot_digest,
        "source_closure_digest": turn.catalog.source_closure_digest,
        "turn_digest": turn.turn_digest,
    }:
        raise MemoryAwareTurnError("memory_request_binding_mismatch")
    if turn.round_index >= turn.budget.max_retrieval_rounds:
        raise MemoryAwareTurnError("retrieval_round_budget_exhausted")
    turn.catalog.require(request.operation, request.scope_id)
    if request.operation == "p07_fetch_sources":
        parent = next(
            (
                receipt
                for receipt in turn.receipts
                if receipt.digest == request.parent_receipt_digest
            ),
            None,
        )
        if (
            parent is None
            or parent.operation != "p07_search_references"
            or parent.status != "available"
            or parent.selection_digest != request.selection_digest
            or parent.turn_digest != turn.turn_digest
        ):
            raise MemoryAwareTurnError("fetch_search_binding_mismatch")


def preflight_memory_request(
    turn: TurnStepRequest,
    request: MemoryRequest,
    *,
    provider_attempts: int,
) -> int:
    """Validate a request and its prospective provider-attempt charge before I/O."""

    validate_memory_request(turn, request)
    _canonical_progress_text(request.query)
    attempts = _bounded_integer(
        provider_attempts,
        "provider_attempt_count_invalid",
        minimum=1,
        maximum=5,
    )
    total_attempts = turn.provider_attempts_used + attempts
    if total_attempts > turn.budget.max_provider_attempts:
        raise MemoryAwareTurnError("provider_attempt_budget_exhausted")
    return total_attempts


def create_memory_outcome(
    request: MemoryRequest,
    *,
    status: MemoryStatus,
    values: tuple[str, ...] = (),
    selection_digest: str | None = None,
) -> tuple[MemoryResult, MemoryReceipt]:
    if request.operation == "p07_search_references" and status == "available":
        if selection_digest is None:
            selection_digest = _digest(
                b"myuna-memory-turn-selection-v1",
                {"query_digest": request.query_digest, "values": list(values)},
            )
    elif request.operation == "p07_fetch_sources":
        if selection_digest is None:
            selection_digest = request.selection_digest
    elif selection_digest is not None:
        raise MemoryAwareTurnError("result_selection_unexpected")
    result = MemoryResult(
        request_digest=request.digest,
        operation=request.operation,
        scope_id=request.scope_id,
        status=status,
        values=values,
        snapshot_digest=request.snapshot_digest,
        source_closure_digest=request.source_closure_digest,
        selection_digest=selection_digest,
        parent_receipt_digest=request.parent_receipt_digest,
    )
    receipt_seed = _digest(
        b"myuna-memory-turn-receipt-id-v1",
        {
            "request_digest": request.digest,
            "result_digest": result.digest,
            "status": status,
        },
    )[:32]
    receipt = MemoryReceipt(
        receipt_id="receipt-" + receipt_seed,
        request_digest=request.digest,
        result_digest=result.digest,
        operation=request.operation,
        scope_id=request.scope_id,
        status=status,
        turn_digest=request.turn_digest,
        snapshot_digest=request.snapshot_digest,
        source_closure_digest=request.source_closure_digest,
        continuation_digest=request.continuation_digest,
        query_digest=request.query_digest,
        result_count=len(values),
        selection_digest=selection_digest,
        parent_receipt_digest=request.parent_receipt_digest,
    )
    return result, receipt


def validate_memory_outcome(
    turn: TurnStepRequest,
    request: MemoryRequest,
    result: MemoryResult,
    receipt: MemoryReceipt,
) -> None:
    validate_memory_request(turn, request)
    entry = turn.catalog.require(request.operation, request.scope_id)
    if entry.availability != "available" and result.status != entry.availability:
        raise MemoryAwareTurnError("result_availability_mismatch")
    if (
        result.request_digest != request.digest
        or result.operation != request.operation
        or result.scope_id != request.scope_id
        or result.snapshot_digest != request.snapshot_digest
        or result.source_closure_digest != request.source_closure_digest
        or result.parent_receipt_digest != request.parent_receipt_digest
    ):
        raise MemoryAwareTurnError("result_binding_mismatch")
    if result.operation == "p07_search_references" and result.status == "available":
        if result.selection_digest is None:
            raise MemoryAwareTurnError("search_selection_missing")
    elif result.operation == "p07_fetch_sources":
        if result.selection_digest != request.selection_digest:
            raise MemoryAwareTurnError("fetch_selection_mismatch")
    elif result.selection_digest is not None:
        raise MemoryAwareTurnError("result_selection_unexpected")
    _validate_result_budgets(turn.budget, turn.results + (result,))
    expected_receipt = create_memory_outcome(
        request,
        status=result.status,
        values=result.values,
        selection_digest=result.selection_digest,
    )[1]
    if receipt != expected_receipt:
        raise MemoryAwareTurnError("receipt_binding_mismatch")


def advance_with_memory(
    turn: TurnStepRequest,
    request: MemoryRequest,
    result: MemoryResult,
    receipt: MemoryReceipt,
    *,
    provider_attempts: int,
) -> TurnStepRequest:
    new_attempts = preflight_memory_request(
        turn,
        request,
        provider_attempts=provider_attempts,
    )
    validate_memory_outcome(turn, request, result, receipt)
    return _build_turn(
        owner_principal_digest=turn.owner_principal_digest,
        conversation_digest=turn.conversation_digest,
        turn_identity_digest=turn.turn_identity_digest,
        request_identity_digest=turn.request_identity_digest,
        owner_message=turn.owner_message,
        catalog=turn.catalog,
        budget=turn.budget,
        round_index=turn.round_index + 1,
        provider_attempts_used=new_attempts,
        repairs_used=turn.repairs_used,
        obligations=turn.obligations,
        results=turn.results + (result,),
        receipts=turn.receipts + (receipt,),
    )


def advance_for_repair(
    turn: TurnStepRequest,
    *,
    provider_attempts: int,
) -> TurnStepRequest:
    attempts = _bounded_integer(
        provider_attempts,
        "provider_attempt_count_invalid",
        minimum=1,
        maximum=5,
    )
    if turn.repairs_used >= turn.budget.max_repairs:
        raise MemoryAwareTurnError("repair_budget_exhausted")
    new_attempts = turn.provider_attempts_used + attempts
    if new_attempts >= turn.budget.max_provider_attempts:
        raise MemoryAwareTurnError("provider_attempt_budget_exhausted")
    return _build_turn(
        owner_principal_digest=turn.owner_principal_digest,
        conversation_digest=turn.conversation_digest,
        turn_identity_digest=turn.turn_identity_digest,
        request_identity_digest=turn.request_identity_digest,
        owner_message=turn.owner_message,
        catalog=turn.catalog,
        budget=turn.budget,
        round_index=turn.round_index,
        provider_attempts_used=new_attempts,
        repairs_used=turn.repairs_used + 1,
        obligations=turn.obligations,
        results=turn.results,
        receipts=turn.receipts,
    )


def _obligation_satisfied(
    obligation: RetrievalObligation,
    receipts: tuple[MemoryReceipt, ...],
    *,
    uncertain: bool,
) -> bool:
    if obligation.availability == "unavailable":
        return uncertain
    matching = tuple(
        receipt
        for receipt in receipts
        if receipt.operation == obligation.operation and receipt.scope_id == obligation.scope_id
    )
    if any(receipt.status == "available" for receipt in matching):
        return True
    return uncertain and any(receipt.status != "available" for receipt in matching)


def complete_turn(
    turn: TurnStepRequest,
    final: FinalBranch,
    *,
    provider_attempts: int,
) -> FinalValue:
    attempts = _bounded_integer(
        provider_attempts,
        "provider_attempt_count_invalid",
        minimum=1,
        maximum=5,
    )
    total_attempts = turn.provider_attempts_used + attempts
    if total_attempts > turn.budget.max_provider_attempts:
        raise MemoryAwareTurnError("provider_attempt_budget_exhausted")
    if (
        len(final.owner_message) > turn.budget.max_characters
        or len(final.owner_message.encode("utf-8")) > turn.budget.max_utf8_bytes
    ):
        raise MemoryAwareTurnError("final_output_budget_exhausted")
    expected_receipts = tuple(receipt.digest for receipt in turn.receipts)
    if final.receipt_digests != expected_receipts:
        raise MemoryAwareTurnError("final_receipt_binding_mismatch", repairable=True)
    final_obligations = derive_obligations(
        final.owner_message,
        turn.catalog,
        include_exact_claims=True,
    )
    all_obligations = {item.digest: item for item in turn.obligations + final_obligations}
    uncertainty_statuses = {
        receipt.status for receipt in turn.receipts if receipt.status != "available"
    }
    if any(item.availability == "unavailable" for item in all_obligations.values()):
        uncertainty_statuses.add("unavailable")
    expected_uncertainty = tuple(sorted(uncertainty_statuses))
    if final.uncertainty_statuses != expected_uncertainty:
        raise MemoryAwareTurnError("final_uncertainty_binding_mismatch", repairable=True)
    if expected_uncertainty and final.resolution == "answer":
        raise MemoryAwareTurnError("uncertain_evidence_answer_rejected")
    uncertain = final.resolution in {"uncertain", "clarify", "abstain"}
    if any(
        not _obligation_satisfied(item, turn.receipts, uncertain=uncertain)
        for item in all_obligations.values()
    ):
        raise MemoryAwareTurnError("final_obligation_unsatisfied", repairable=True)
    return FinalValue(
        owner_message=final.owner_message,
        resolution=final.resolution,
        server_intents=final.server_intents,
        receipt_digests=final.receipt_digests,
        turn_digest=turn.turn_digest,
        continuation_digest=turn.continuation_digest,
        provider_attempts_used=total_attempts,
        retrieval_rounds=turn.round_index,
    )


def provider_response_payload(
    turn: TurnStepRequest,
    branch: MemoryRequest | FinalBranch,
) -> dict[str, object]:
    """Build deterministic synthetic provider output for focused tests only."""

    if isinstance(branch, MemoryRequest):
        return {
            "bindings": turn.bindings_payload(),
            "branch": "memory_request",
            "memory_request": {
                "operation": branch.operation,
                "parent_receipt_digest": branch.parent_receipt_digest,
                "query": branch.query,
                "scope_id": branch.scope_id,
                "selection_digest": branch.selection_digest,
            },
            "schema": STEP_RESPONSE_SCHEMA,
        }
    if isinstance(branch, FinalBranch):
        return {
            "bindings": turn.bindings_payload(),
            "branch": "final",
            "final": branch.as_payload(),
            "schema": STEP_RESPONSE_SCHEMA,
        }
    raise MemoryAwareTurnError("provider_branch_type_invalid")


def request_for_turn(
    turn: TurnStepRequest,
    *,
    operation: MemoryOperation,
    scope_id: str,
    query: str,
    selection_digest: str | None = None,
    parent_receipt_digest: str | None = None,
) -> MemoryRequest:
    """Construct a trusted synthetic request with the current exact bindings."""

    request = MemoryRequest(
        operation=operation,
        scope_id=scope_id,
        query=query,
        turn_digest=turn.turn_digest,
        catalog_digest=turn.catalog.digest,
        snapshot_digest=turn.catalog.snapshot_digest,
        source_closure_digest=turn.catalog.source_closure_digest,
        continuation_digest=turn.continuation_digest,
        budget_digest=turn.budget.digest,
        obligation_digest=turn.obligation_digest,
        round_index=turn.round_index,
        selection_digest=selection_digest,
        parent_receipt_digest=parent_receipt_digest,
    )
    validate_memory_request(turn, request)
    return request


def final_for_turn(
    turn: TurnStepRequest,
    *,
    owner_message: str,
    resolution: FinalResolution = "answer",
    server_intents: tuple[ServerIntentProposal, ...] = (),
) -> FinalBranch:
    """Construct a trusted synthetic final branch with exact receipt evidence."""

    final_obligations = derive_obligations(
        owner_message,
        turn.catalog,
        include_exact_claims=True,
    )
    uncertainty_statuses = {
        receipt.status for receipt in turn.receipts if receipt.status != "available"
    }
    if any(
        item.availability == "unavailable"
        for item in turn.obligations + final_obligations
    ):
        uncertainty_statuses.add("unavailable")
    return FinalBranch(
        owner_message=owner_message,
        resolution=resolution,
        receipt_digests=tuple(receipt.digest for receipt in turn.receipts),
        uncertainty_statuses=tuple(sorted(uncertainty_statuses)),
        server_intents=server_intents,
    )
