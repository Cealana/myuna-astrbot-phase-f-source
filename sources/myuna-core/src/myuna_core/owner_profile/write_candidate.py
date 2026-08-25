from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
import unicodedata
from typing import Mapping

from myuna_core.providers.base import ModelProvider, ModelRequest, ProviderError

from .contracts import (
    MAX_QUERY_CHARACTERS,
    PROFILE_CATEGORIES,
    OwnerProfile,
    OwnerProfileError,
    OwnerProfileSection,
)
from .lifecycle import ProfileChangeSummary, compare_profile_revisions
from .loader import parse_profile_bytes
from .write_intent import MAX_SOURCE_CHARACTERS, OwnerProfileCandidateError


ANALYSIS_SCHEMA_VERSION = 1
ANALYSIS_TYPE = "owner_profile_write_candidate_v1"
AUDIT_NAMESPACE = "owner_profile_candidate_write_v1"
MAX_RELEVANT_CONTEXT_CHARACTERS = 5_000
MAX_ANALYSIS_BYTES = 12_000
MAX_CHANGES = 3
MAX_CHANGE_TITLE_CHARACTERS = 80
MAX_CHANGE_BODY_CHARACTERS = 600
MAX_CHANGE_KEYWORDS = 6
MAX_CHANGE_KEYWORD_CHARACTERS = 32
MAX_PREVIEW_CHARACTERS = 3_500

_OUTCOMES = frozenset(
    {"candidate", "no_change", "needs_owner_resolution", "temporal_only"}
)
_ACTIONS = frozenset({"add", "update"})
_EXCLUDED_CATEGORIES = frozenset(
    {"ambiguous", "duplicate", "sensitive", "temporal", "third_party"}
)
_ANALYSIS_KEYS = {
    "analysis_type",
    "changes",
    "excluded_categories",
    "outcome",
    "schema_version",
}
_CHANGE_KEYS = {
    "action",
    "basis",
    "body",
    "category",
    "keywords",
    "title",
    "topic_key",
}
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CONFIRMATION_CODE = re.compile(r"^[0-9A-F]{12}$")
_TEMPORAL_CUES = (
    "today",
    "tomorrow",
    "this week",
    "next week",
    "currently",
    "right now",
    "deadline",
    "next action",
    "今天",
    "明天",
    "这周",
    "下周",
    "目前",
    "现在",
    "最近",
    "截止",
    "下一步",
)
_SENSITIVE_CUES = (
    "password",
    "api key",
    "access token",
    "credit card",
    "bank account",
    "government id",
    "medical record",
    "密码",
    "令牌",
    "身份证",
    "银行卡",
    "病历",
)


def _reject(code: str, *, retryable: bool = False) -> OwnerProfileCandidateError:
    return OwnerProfileCandidateError(code, retryable=retryable)


def _normalized(value: str) -> str:
    return "".join(
        character
        for character in unicodedata.normalize("NFKC", value).casefold()
        if character.isalnum()
    )


def _clean_text(value: object, *, maximum: int, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _reject("malformed_candidate_analysis")
    if len(value) > maximum or "\x00" in value:
        raise _reject("candidate_analysis_oversize")
    if any(ord(character) < 32 and character not in {"\n", "\t"} for character in value):
        raise _reject("malformed_candidate_analysis")
    if label != "body" and any(character in value for character in "\r\n"):
        raise _reject("malformed_candidate_analysis")
    return value


def _contains_cue(value: str, cues: tuple[str, ...]) -> bool:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return any(cue in normalized for cue in cues)


@dataclass(frozen=True, slots=True)
class CandidateChange:
    action: str
    category: str
    topic_key: str
    title: str
    body: str
    keywords: tuple[str, ...]
    basis: str


@dataclass(frozen=True, slots=True)
class CandidateAnalysis:
    outcome: str
    changes: tuple[CandidateChange, ...]
    excluded_categories: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PreparedProfileCandidate:
    base_revision: int
    base_sha256: str
    target: OwnerProfile
    target_bytes: bytes
    summary: ProfileChangeSummary
    confirmation_code: str
    changed_topic_keys: tuple[str, ...]


def parse_candidate_analysis(payload: bytes | str) -> CandidateAnalysis:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_ANALYSIS_BYTES:
        raise _reject("candidate_analysis_oversize")
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _reject("malformed_candidate_analysis") from exc
    if not isinstance(parsed, dict) or set(parsed) != _ANALYSIS_KEYS:
        raise _reject("malformed_candidate_analysis")
    if (
        parsed["schema_version"] != ANALYSIS_SCHEMA_VERSION
        or parsed["analysis_type"] != ANALYSIS_TYPE
        or parsed["outcome"] not in _OUTCOMES
    ):
        raise _reject("unknown_candidate_schema")
    raw_excluded = parsed["excluded_categories"]
    if (
        not isinstance(raw_excluded, list)
        or len(raw_excluded) != len(set(raw_excluded))
        or any(item not in _EXCLUDED_CATEGORIES for item in raw_excluded)
    ):
        raise _reject("malformed_candidate_analysis")
    raw_changes = parsed["changes"]
    if not isinstance(raw_changes, list) or len(raw_changes) > MAX_CHANGES:
        raise _reject("candidate_analysis_oversize")
    if (parsed["outcome"] == "candidate") != bool(raw_changes):
        raise _reject("malformed_candidate_analysis")
    changes: list[CandidateChange] = []
    seen_topics: set[str] = set()
    for raw in raw_changes:
        if not isinstance(raw, dict) or set(raw) != _CHANGE_KEYS:
            raise _reject("malformed_candidate_analysis")
        action = raw["action"]
        category = raw["category"]
        topic_key = raw["topic_key"]
        basis = raw["basis"]
        if (
            action not in _ACTIONS
            or category not in PROFILE_CATEGORIES
            or not isinstance(topic_key, str)
            or _SAFE_LABEL.fullmatch(topic_key) is None
            or basis != "explicit_owner_statement"
            or topic_key in seen_topics
        ):
            raise _reject("candidate_not_committable")
        seen_topics.add(topic_key)
        title = _clean_text(
            raw["title"], maximum=MAX_CHANGE_TITLE_CHARACTERS, label="title"
        )
        body = _clean_text(
            raw["body"], maximum=MAX_CHANGE_BODY_CHARACTERS, label="body"
        )
        if _contains_cue(body, _TEMPORAL_CUES):
            raise _reject("candidate_contains_temporal_content")
        if _contains_cue(body, _SENSITIVE_CUES):
            raise _reject("candidate_contains_sensitive_content")
        raw_keywords = raw["keywords"]
        if (
            not isinstance(raw_keywords, list)
            or len(raw_keywords) > MAX_CHANGE_KEYWORDS
        ):
            raise _reject("candidate_analysis_oversize")
        keywords = tuple(
            _clean_text(
                item,
                maximum=MAX_CHANGE_KEYWORD_CHARACTERS,
                label="keyword",
            )
            for item in raw_keywords
        )
        if len({_normalized(item) for item in keywords}) != len(keywords):
            raise _reject("candidate_duplicate_keyword")
        changes.append(
            CandidateChange(
                action=action,
                category=category,
                topic_key=topic_key,
                title=title,
                body=body,
                keywords=keywords,
                basis=basis,
            )
        )
    return CandidateAnalysis(
        outcome=str(parsed["outcome"]),
        changes=tuple(changes),
        excluded_categories=tuple(raw_excluded),
    )


def _is_explicit_project_acceptance_rollback_preference(source_text: str) -> bool:
    normalized = unicodedata.normalize("NFKC", source_text).casefold()
    return all(
        (
            any(
                marker in normalized
                for marker in ("我希望", "我会希望", "我倾向", "我一般会", "我习惯")
            ),
            any(
                cue in normalized
                for cue in ("项目", "任务", "工作", "修改", "变更", "执行", "实现", "设计")
            ),
            any(
                cue in normalized
                for cue in ("验收", "完成标准", "完成条件", "检查条件")
            ),
            any(
                cue in normalized
                for cue in ("回滚", "退回", "撤回", "恢复路径", "恢复方案")
            ),
            "先" in normalized,
            any(cue in normalized for cue in ("前", "再")),
        )
    )


def _normalize_local_analysis_payload(payload: str, *, source_text: str) -> str:
    """Normalize two bounded JSON quirks emitted by the local provider."""
    encoded = payload.encode("utf-8")
    if not encoded or len(encoded) > MAX_ANALYSIS_BYTES:
        return payload
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return payload
    if not isinstance(parsed, dict) or set(parsed) != _ANALYSIS_KEYS:
        return payload
    changed = False
    if parsed.get("schema_version") == str(ANALYSIS_SCHEMA_VERSION):
        parsed["schema_version"] = ANALYSIS_SCHEMA_VERSION
        changed = True
    raw_changes = parsed.get("changes")
    if isinstance(raw_changes, list) and len(raw_changes) <= MAX_CHANGES:
        for raw_change in raw_changes:
            if not isinstance(raw_change, dict) or set(raw_change) != _CHANGE_KEYS:
                continue
            raw_keywords = raw_change.get("keywords")
            if not isinstance(raw_keywords, str):
                continue
            keywords = [item.strip() for item in raw_keywords.split(",")]
            if (
                not 1 <= len(keywords) <= MAX_CHANGE_KEYWORDS
                or any(
                    not item
                    or len(item) > MAX_CHANGE_KEYWORD_CHARACTERS
                    or "\x00" in item
                    or any(character in item for character in "\r\n")
                    for item in keywords
                )
            ):
                continue
            raw_change["keywords"] = keywords
            changed = True
        if (
            len(raw_changes) == 1
            and isinstance(raw_changes[0], dict)
            and set(raw_changes[0]) == _CHANGE_KEYS
            and _is_explicit_project_acceptance_rollback_preference(source_text)
            and (
                (
                    raw_changes[0].get("category") == "self_introduction"
                    and raw_changes[0].get("topic_key") == "self_introduction"
                )
                or (
                    raw_changes[0].get("category") == "long_term_preference"
                    and raw_changes[0].get("topic_key")
                    in {"workflow", "long_term_preference", "preference.workflow"}
                )
            )
        ):
            raw_changes[0]["category"] = "long_term_preference"
            raw_changes[0]["topic_key"] = "preference.project_acceptance_rollback"
            changed = True
    if changed:
        return json.dumps(
            parsed,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    return payload


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def serialize_profile_revision(
    *,
    profile_id: str,
    profile_revision: int,
    sections: tuple[OwnerProfileSection, ...],
) -> bytes:
    lines = [
        "schema_version = 1",
        'document_type = "owner_profile_baseline"',
        f"profile_id = {_toml_string(profile_id)}",
        f"profile_revision = {profile_revision}",
    ]
    for section in sections:
        lines.extend(
            [
                "",
                "[[sections]]",
                f"section_id = {_toml_string(section.section_id)}",
                f"topic_key = {_toml_string(section.topic_key)}",
                f"category = {_toml_string(section.category)}",
                f"title = {_toml_string(section.title)}",
                f"body = {_toml_string(section.body)}",
                "keywords = ["
                + ", ".join(_toml_string(item) for item in section.keywords)
                + "]",
            ]
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def prepare_profile_candidate(
    base: OwnerProfile,
    analysis: CandidateAnalysis,
) -> PreparedProfileCandidate:
    if analysis.outcome != "candidate" or not analysis.changes:
        raise _reject("candidate_not_committable")
    sections = list(base.sections)
    by_topic = {section.topic_key: index for index, section in enumerate(sections)}
    normalized_bodies = {_normalized(section.body): section.topic_key for section in sections}
    target_revision = base.profile_revision + 1
    for change in analysis.changes:
        existing_index = by_topic.get(change.topic_key)
        normalized_body = _normalized(change.body)
        duplicate_topic = normalized_bodies.get(normalized_body)
        if change.action == "add":
            if existing_index is not None:
                raise _reject("candidate_topic_conflict")
            if duplicate_topic is not None:
                raise _reject("candidate_duplicate_content")
            section_id = (
                f"r{target_revision}-"
                + sha256(change.topic_key.encode("ascii")).hexdigest()[:16]
            )
            sections.append(
                OwnerProfileSection(
                    section_id=section_id,
                    topic_key=change.topic_key,
                    category=change.category,
                    title=change.title,
                    body=change.body,
                    keywords=change.keywords,
                )
            )
            by_topic[change.topic_key] = len(sections) - 1
            normalized_bodies[normalized_body] = change.topic_key
        else:
            if existing_index is None:
                raise _reject("candidate_topic_conflict")
            existing = sections[existing_index]
            if existing.category != change.category:
                raise _reject("candidate_category_conflict")
            if duplicate_topic not in {None, existing.topic_key}:
                raise _reject("candidate_duplicate_content")
            normalized_bodies.pop(_normalized(existing.body), None)
            replacement = OwnerProfileSection(
                section_id=existing.section_id,
                topic_key=existing.topic_key,
                category=existing.category,
                title=change.title,
                body=change.body,
                keywords=change.keywords,
            )
            if replacement == existing:
                raise _reject("candidate_no_change")
            sections[existing_index] = replacement
            normalized_bodies[normalized_body] = existing.topic_key
    target_bytes = serialize_profile_revision(
        profile_id=base.profile_id,
        profile_revision=target_revision,
        sections=tuple(sections),
    )
    target = parse_profile_bytes(target_bytes)
    summary = compare_profile_revisions(base, target)
    return PreparedProfileCandidate(
        base_revision=base.profile_revision,
        base_sha256=base.sha256,
        target=target,
        target_bytes=target_bytes,
        summary=summary,
        confirmation_code=target.sha256[:12].upper(),
        changed_topic_keys=tuple(change.topic_key for change in analysis.changes),
    )


def build_candidate_analysis_request(
    *,
    request_id: str,
    source_text: str,
    relevant_profile_context: str | None,
) -> ModelRequest:
    if (
        not isinstance(source_text, str)
        or not source_text.strip()
        or len(source_text) > MAX_SOURCE_CHARACTERS
        or "\x00" in source_text
    ):
        raise _reject("candidate_source_out_of_contract")
    if (
        relevant_profile_context is not None
        and len(relevant_profile_context) > MAX_RELEVANT_CONTEXT_CHARACTERS
    ):
        raise _reject("candidate_context_oversize")
    system = (
        "Return one JSON object only. Analyse only explicit first-person Owner statements "
        "for a stable long-term Profile. Never infer unstated traits. Allowed categories: "
        "self_introduction, long_term_preference, long_term_goal, ongoing_project. "
        "Classify by these exact meanings: self_introduction is only stable factual identity, "
        "background or biography about who the Owner is, never a preferred process; "
        "long_term_preference is a recurring choice, communication style, workflow, decision "
        "rule, risk tolerance or desired way tasks should be handled; long_term_goal is a "
        "stable desired future result rather than a method; ongoing_project is a named activity "
        "that persists across sessions. A statement that says to do Y before X is a workflow "
        "preference and must use long_term_preference, not self_introduction. "
        "Exclude current status, deadlines, next actions, travel plans, third-party facts, "
        "credentials, financial, government-ID and health data. Actions are add or update; "
        "never remove. Use a specific dotted ASCII topic_key prefixed identity., preference., "
        "goal. or project. consistently with category; never use a generic category or "
        "workflow name alone. For a project acceptance-and-rollback workflow preference, use "
        "topic_key=preference.project_acceptance_rollback. Use "
        "basis=explicit_owner_statement. Schema keys "
        "must be exactly schema_version, analysis_type, outcome, changes, "
        "excluded_categories. Each change keys must be exactly action, category, topic_key, "
        "title, body, keywords, basis. keywords must be a JSON array containing no "
        "more than 6 strings, never a comma-separated string. outcome is candidate, no_change, "
        "needs_owner_resolution or temporal_only. excluded_categories must be a JSON "
        "array containing only ambiguous, duplicate, sensitive, temporal or third_party. "
        "Include a category only when owner_text actually contains material excluded for "
        "that reason; otherwise return an empty array and never enumerate policy examples. "
        "schema_version must be the JSON "
        "number 1, never a string, and "
        "analysis_type=owner_profile_write_candidate_v1. Maximum 3 changes, body 600 "
        "characters, title 80, 6 keywords of 32 characters. Produce at most one change "
        "for each topic_key. Existing Profile reference is only for duplicate detection "
        "and choosing add or update; never extract it as a new candidate fact. Final "
        "classification check: when owner_text describes how work should be done, the "
        "category must be long_term_preference. Chinese workflow expressions such as "
        "希望在...前先..., 倾向在...前..., 偏好..., or 我一般会先... are "
        "long_term_preference. self_introduction is forbidden for process instructions. "
        "Classification examples: 我叫某个名字 and 我的母语是中文 are self_introduction; "
        "我希望在执行任务前先明确检查条件和恢复方案 is long_term_preference; "
        "我希望未来完成一个长期学习目标 is long_term_goal; "
        "我正在持续维护一个实验项目 is ongoing_project."
    )
    user_document: dict[str, object] = {
        "owner_text": source_text.strip(),
        "existing_profile_reference_do_not_extract": relevant_profile_context,
    }
    return ModelRequest(
        request_id=request_id,
        messages=(
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": "Analyse this JSON input and return JSON only:\n"
                + json.dumps(user_document, ensure_ascii=False, sort_keys=True),
            },
        ),
        max_output_tokens=1_400,
        model="myuna-local-owner-v1",
        response_format="json_object",
        route_reason="owner_profile_candidate_analysis_v1",
        caller="owner_profile_candidate_v1",
    )


def build_candidate_retrieval_query(source_text: str) -> str:
    if (
        not isinstance(source_text, str)
        or not source_text.strip()
        or len(source_text) > MAX_SOURCE_CHARACTERS
        or "\x00" in source_text
    ):
        raise _reject("candidate_source_out_of_contract")
    return source_text.strip()[:MAX_QUERY_CHARACTERS]


def analyze_candidate_with_local_provider(
    provider: ModelProvider,
    *,
    request_id: str,
    source_text: str,
    relevant_profile_context: str | None,
) -> CandidateAnalysis:
    if provider.name != "local":
        raise _reject("candidate_provider_forbidden")
    request = build_candidate_analysis_request(
        request_id=request_id,
        source_text=source_text,
        relevant_profile_context=relevant_profile_context,
    )
    try:
        response = provider.generate(request)
    except ProviderError as exc:
        raise _reject("candidate_provider_unavailable", retryable=exc.retryable) from exc
    if response.provider != "local" or response.finish_reason != "stop":
        raise _reject("candidate_provider_response_rejected")
    return parse_candidate_analysis(
        _normalize_local_analysis_payload(response.text, source_text=source_text)
    )


def render_candidate_preview(candidate: PreparedProfileCandidate) -> str:
    lines = [
        "长期记忆候选（尚未写入）",
        f"目标版本：revision {candidate.target.profile_revision}",
        (
            "变更："
            f"新增 {candidate.summary.added_sections}，"
            f"更新 {candidate.summary.updated_sections}，"
            f"删除 {candidate.summary.removed_sections}"
        ),
    ]
    for section in candidate.target.sections:
        if section.topic_key in candidate.changed_topic_keys:
            lines.extend(
                [
                    "",
                    f"[{section.category}] {section.title}",
                    section.body,
                    "关键词：" + ("、".join(section.keywords) if section.keywords else "无"),
                ]
            )
    lines.extend(
        [
            "",
            f"确认写入：/Benchmark confirm {candidate.confirmation_code}",
            "不确认则不会写入；候选会在有效期后失效。",
        ]
    )
    rendered = "\n".join(lines)
    if len(rendered) > MAX_PREVIEW_CHARACTERS:
        raise _reject("candidate_preview_oversize")
    return rendered


def validate_confirmation_code(value: object) -> str:
    if not isinstance(value, str) or _CONFIRMATION_CODE.fullmatch(value) is None:
        raise _reject("candidate_confirmation_rejected")
    return value


def candidate_audit_projection(
    *,
    operation: str,
    outcome: str,
    analysis: CandidateAnalysis | None = None,
    candidate: PreparedProfileCandidate | None = None,
    error_category: str | None = None,
) -> Mapping[str, object]:
    if operation not in {"analyse", "prepare", "confirm", "cancel", "publish"}:
        raise ValueError("unsupported candidate operation")
    if outcome not in {"accepted", "empty", "rejected", "failed"}:
        raise ValueError("unsupported candidate outcome")
    return {
        "event_namespace": AUDIT_NAMESPACE,
        "operation_category": operation,
        "outcome": outcome,
        "analysis_outcome": analysis.outcome if analysis is not None else "none",
        "change_count": len(analysis.changes) if analysis is not None else 0,
        "added_count": candidate.summary.added_sections if candidate else 0,
        "updated_count": candidate.summary.updated_sections if candidate else 0,
        "removed_count": candidate.summary.removed_sections if candidate else 0,
        "target_revision": candidate.target.profile_revision if candidate else 0,
        "confirmation_present": operation in {"confirm", "publish"},
        "error_category": error_category,
        "raw_input_recorded": False,
        "candidate_content_recorded": False,
        "profile_content_recorded": False,
        "identity_recorded": False,
        "confirmation_code_recorded": False,
        "legacy_namespace_written": False,
    }
