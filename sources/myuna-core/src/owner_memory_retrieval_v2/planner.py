from __future__ import annotations

from hashlib import sha256
import re

from .concepts import contains_phrase, detect_query_concepts
from .contracts import QueryPlan


POLICY_VERSION = "owner-memory-retrieval-v2-deterministic-zh-candidate"

EXPLICIT_RECALL_PHRASES = (
    "还记得",
    "记不记得",
    "回忆一下",
    "想一想以前",
    "以前",
    "过去",
    "当时",
    "最开始",
    "曾经",
    "说过",
    "原话",
    "第一次",
)

CURRENT_CONTEXT_PHRASES = (
    "今天",
    "现在",
    "刚才",
    "刚刚",
    "这会儿",
    "目前正在",
)

QUESTION_OR_POLICY_PHRASES = (
    "怎样",
    "怎么",
    "为什么",
    "是不是",
    "要不要",
    "能不能",
    "是否",
    "可以",
    "如何",
    "以后",
    "应该",
    "默认",
    "我希望",
    "我的偏好",
    "我们定",
    "我们决定",
)

SELF_OR_HISTORY_POLICY_PHRASES = (
    "我希望",
    "我的",
    "我说过",
    "我们",
    "之前",
    "当时",
    "偏好",
    "习惯",
    "决定",
)

DURABLE_CONCEPTS = frozenset(
    {
        "anchor_preference",
        "exact_quote",
        "firsts",
        "important_moment",
        "lossless_source",
        "ask_when_uncertain",
        "rationale",
        "decision_context",
        "causality",
        "timeline",
        "correction",
        "forget_semantics",
        "deletion_boundary",
        "namespace_isolation",
        "identity",
        "friend_namespace",
        "anti_impersonation",
        "prompt_injection",
        "modularity",
        "extensibility",
        "versioned_policy",
        "runtime_tuning",
        "full_archive",
        "one_to_one",
        "local_organizer",
        "retrieval",
        "deep_recall",
        "deployment",
    }
)


def plan_query(query: str) -> QueryPlan:
    """Create a content-free, deterministic retrieval plan."""

    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be non-empty text")
    if len(query) > 256 or "\x00" in query:
        raise ValueError("query is outside the v2 contract")

    query = query.strip()
    concepts = detect_query_concepts(query)
    concept_set = set(concepts)
    explicit_recall = contains_phrase(query, EXPLICIT_RECALL_PHRASES)
    current_context = contains_phrase(query, CURRENT_CONTEXT_PHRASES)
    policy_question = contains_phrase(query, QUESTION_OR_POLICY_PHRASES)
    owner_policy_reference = contains_phrase(query, SELF_OR_HISTORY_POLICY_PHRASES)
    exact_quote = "exact_quote" in concept_set
    durable_topic = bool(concept_set & DURABLE_CONCEPTS)
    specific_durable_topic = bool(
        (concept_set & DURABLE_CONCEPTS) - {"anchor_preference"}
    )

    reasons: list[str] = []
    if exact_quote:
        intent = "exact_quote_recall"
        horizon = "deep"
        reasons.append("exact_quote_intent")
    elif explicit_recall:
        intent = "historical_recall"
        horizon = "deep"
        reasons.append("explicit_recall_phrase")
    elif durable_topic and policy_question and (
        owner_policy_reference or specific_durable_topic
    ):
        intent = "durable_policy"
        horizon = "deep"
        reasons.append("durable_topic_question")
    elif current_context:
        intent = "current_context"
        horizon = "recent"
        reasons.append("current_context_phrase")
    else:
        intent = "ordinary_context"
        horizon = "recent"
        reasons.append("ordinary_recent_default")

    # The engine supports a bounded fallback, but v2 does not authorize it from
    # a broad topic match alone. Explicit recall and durable-policy questions are
    # planned as deep up front. This prevents operational questions containing
    # words such as "长期记忆" from scanning all Owner history.
    allow_fallback = False
    if allow_fallback:
        reasons.append("bounded_deep_fallback_authorized")

    return QueryPlan(
        policy_version=POLICY_VERSION,
        intent=intent,
        primary_horizon=horizon,
        allow_deep_fallback=allow_fallback,
        max_results=3 if horizon == "deep" else 1,
        concepts=concepts,
        reason_codes=tuple(reasons),
        query_fingerprint=sha256(query.encode("utf-8")).hexdigest(),
        query_characters=len(query),
    )


def safe_label(value: str) -> bool:
    return re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", value) is not None
