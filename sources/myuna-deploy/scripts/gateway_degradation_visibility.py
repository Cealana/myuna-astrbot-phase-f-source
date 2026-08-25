"""Deterministic, evidence-bound visibility gate for Natural Degradation R2D-0.

This module does not read R3D traces and cannot activate a category by itself.
An empty policy preserves the legacy unavailable reply for every category.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Mapping

from gateway_degradation_protocol import (
    CANONICAL_DEGRADATION_REPLIES,
    GatewayDegradationProtocolError,
    safe_degraded_reply_payload,
    validate_safe_degradation,
)


VISIBILITY_POLICY_SCHEMA = "myuna.degradation-visibility-policy.v1"
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_POLICY_FIELDS = frozenset({"schema", "enabled_categories"})
_AUTHORIZATION_FIELDS = frozenset(
    {"category", "evidence_receipt_sha256", "approval_plan_digest"}
)
_UNSENDABLE_ON_SAME_QQ_CHANNEL = frozenset(
    {"onebot_or_napcat_offline", "host_or_network_unreachable"}
)


class VisibilityPolicyError(ValueError):
    """A content-free policy rejection safe to audit by fixed error class."""


class VisibilityMode(str, Enum):
    LEGACY_UNAVAILABLE = "legacy_unavailable"
    SAFE_DEGRADED_REPLY = "safe_degraded_reply"


@dataclass(frozen=True, slots=True)
class CategoryAuthorization:
    category: str
    evidence_receipt_sha256: str
    approval_plan_digest: str

    def __post_init__(self) -> None:
        if self.category not in CANONICAL_DEGRADATION_REPLIES:
            raise VisibilityPolicyError("visibility authorization rejected")
        if self.category in _UNSENDABLE_ON_SAME_QQ_CHANNEL:
            raise VisibilityPolicyError("visibility authorization rejected")
        if _DIGEST.fullmatch(self.evidence_receipt_sha256) is None:
            raise VisibilityPolicyError("visibility authorization rejected")
        if _DIGEST.fullmatch(self.approval_plan_digest) is None:
            raise VisibilityPolicyError("visibility authorization rejected")


@dataclass(frozen=True, slots=True)
class VisibilityPolicy:
    authorizations: tuple[CategoryAuthorization, ...]

    def __post_init__(self) -> None:
        categories = [item.category for item in self.authorizations]
        if len(categories) != len(set(categories)):
            raise VisibilityPolicyError("duplicate visibility authorization")

    def authorization_for(self, category: str) -> CategoryAuthorization | None:
        for item in self.authorizations:
            if item.category == category:
                return item
        return None


@dataclass(frozen=True, slots=True)
class VisibilityDecision:
    mode: VisibilityMode
    category: str
    reason: str
    response: dict[str, object] | None = None

    def __post_init__(self) -> None:
        if self.mode is VisibilityMode.LEGACY_UNAVAILABLE and self.response is not None:
            raise VisibilityPolicyError("legacy decision cannot include a response")
        if self.mode is VisibilityMode.SAFE_DEGRADED_REPLY and self.response is None:
            raise VisibilityPolicyError("visible decision requires a response")


def load_visibility_policy(payload: object) -> VisibilityPolicy:
    if not isinstance(payload, Mapping) or set(payload) != _POLICY_FIELDS:
        raise VisibilityPolicyError("visibility policy rejected")
    if payload["schema"] != VISIBILITY_POLICY_SCHEMA:
        raise VisibilityPolicyError("visibility policy rejected")
    entries = payload["enabled_categories"]
    if not isinstance(entries, list):
        raise VisibilityPolicyError("visibility policy rejected")
    authorizations: list[CategoryAuthorization] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != _AUTHORIZATION_FIELDS:
            raise VisibilityPolicyError("visibility policy rejected")
        if any(not isinstance(entry[field], str) for field in _AUTHORIZATION_FIELDS):
            raise VisibilityPolicyError("visibility policy rejected")
        authorizations.append(
            CategoryAuthorization(
                category=entry["category"],
                evidence_receipt_sha256=entry["evidence_receipt_sha256"],
                approval_plan_digest=entry["approval_plan_digest"],
            )
        )
    return VisibilityPolicy(tuple(authorizations))


def decide_visible_degradation(
    projection: object,
    policy: VisibilityPolicy,
) -> VisibilityDecision:
    if not isinstance(policy, VisibilityPolicy):
        raise TypeError("policy must be a VisibilityPolicy")
    try:
        validated = validate_safe_degradation(projection)
    except GatewayDegradationProtocolError as exc:
        raise VisibilityPolicyError("safe degradation projection rejected") from exc
    category = str(validated["category"])
    authorization = policy.authorization_for(category)
    if authorization is None:
        return VisibilityDecision(
            mode=VisibilityMode.LEGACY_UNAVAILABLE,
            category=category,
            reason="category_not_authorized",
        )
    if validated["recovery_state"] != "active":
        return VisibilityDecision(
            mode=VisibilityMode.LEGACY_UNAVAILABLE,
            category=category,
            reason="recovery_notice_not_authorized",
        )
    return VisibilityDecision(
        mode=VisibilityMode.SAFE_DEGRADED_REPLY,
        category=category,
        reason="category_authorized",
        response=safe_degraded_reply_payload(validated),
    )

