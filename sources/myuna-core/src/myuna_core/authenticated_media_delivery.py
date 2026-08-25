from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Mapping

from .authenticated_conversation import AuthenticatedConversationContext
from .channel_capability import ChannelAuthorizationDecision
from .channel_gateway import SUPPORTED_CHANNELS
from .vision_input import (
    INPUT_SCHEMA_VERSION,
    VisionInputEnvelope,
    VisionMediaDescriptor,
)


DELIVERY_SCHEMA_VERSION = "myuna.authenticated-media-delivery.v1"
POLICY_SCHEMA_VERSION = 1
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ANALYSIS_MODES = frozenset({"describe", "question_answer", "ocr_assist"})


class AuthenticatedMediaDeliveryError(PermissionError):
    """Fail-closed delivery error without identity or media disclosure."""


def _reject() -> AuthenticatedMediaDeliveryError:
    return AuthenticatedMediaDeliveryError("authenticated media delivery rejected")


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a safe opaque identifier")
    return value


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone offset")
    return value.astimezone(timezone.utc)


def _question(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("user question must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > 4000 or "\x00" in normalized:
        raise ValueError("user question is outside the supported range")
    return normalized


@dataclass(frozen=True, slots=True)
class AuthenticatedMediaDelivery:
    """Media metadata bound to an already authenticated conversation context."""

    schema_version: str
    delivery_id: str
    context: AuthenticatedConversationContext
    media: tuple[VisionMediaDescriptor, ...]
    user_question: str
    analysis_modes: tuple[str, ...]
    received_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != DELIVERY_SCHEMA_VERSION:
            raise ValueError("unsupported authenticated media delivery schema")
        _safe_id(self.delivery_id, "delivery_id")
        if not self.context.consent_media_processing:
            raise _reject()
        if not 1 <= len(self.media) <= 4:
            raise ValueError("media delivery must contain one to four images")
        if len(self.media) != len({item.media_id for item in self.media}):
            raise ValueError("media delivery identifiers must be unique")
        object.__setattr__(self, "user_question", _question(self.user_question))
        if (
            not self.analysis_modes
            or len(self.analysis_modes) != len(set(self.analysis_modes))
            or any(value not in _ANALYSIS_MODES for value in self.analysis_modes)
        ):
            raise ValueError("media delivery analysis modes are invalid")
        received_at = _utc(self.received_at, "received_at")
        if received_at < self.context.occurred_at:
            raise ValueError("media delivery cannot precede the authenticated event")
        object.__setattr__(self, "received_at", received_at)

    def audit_metadata(self) -> dict[str, object]:
        """Exclude the question, image bytes, paths, URLs, and raw platform IDs."""

        return {
            **self.context.audit_details(),
            "analysis_modes": list(self.analysis_modes),
            "delivery_id": self.delivery_id,
            "media": [item.audit_metadata() for item in self.media],
            "media_count": len(self.media),
            "received_at": self.received_at.isoformat(timespec="microseconds"),
        }

    def to_vision_envelope(self) -> VisionInputEnvelope:
        return VisionInputEnvelope(
            schema_version=INPUT_SCHEMA_VERSION,
            context=self.context,
            media=self.media,
            user_question=self.user_question,
            analysis_modes=self.analysis_modes,
        )


@dataclass(frozen=True, slots=True)
class AuthenticatedMediaDeliveryPolicy:
    schema_version: int
    policy_id: str
    status: str
    allowed_channel_kinds: frozenset[str]
    allowed_conversation_kinds: frozenset[str]
    allowed_authority_levels: frozenset[str]
    required_capability: str
    maximum_age_seconds: int
    maximum_future_skew_seconds: int
    maximum_media_count: int

    @classmethod
    def from_document(cls, document: object) -> AuthenticatedMediaDeliveryPolicy:
        try:
            if not isinstance(document, Mapping) or set(document) != {
                "schema_version",
                "policy_id",
                "status",
                "subject",
                "required_capability",
                "maximum_age_seconds",
                "maximum_future_skew_seconds",
                "maximum_media_count",
            }:
                raise ValueError("authenticated media policy fields do not match v1")
            if document["schema_version"] != POLICY_SCHEMA_VERSION:
                raise ValueError("unsupported authenticated media policy schema")
            if document["status"] != "inactive_candidate":
                raise ValueError("authenticated media policy must remain inactive")
            subject = document["subject"]
            if not isinstance(subject, Mapping) or set(subject) != {
                "channel_kinds",
                "conversation_kinds",
                "authority_levels",
            }:
                raise ValueError("authenticated media subject is invalid")
            channels = subject["channel_kinds"]
            conversations = subject["conversation_kinds"]
            authorities = subject["authority_levels"]
            if (
                not isinstance(channels, list)
                or not channels
                or len(channels) != len(set(channels))
                or not set(channels) <= SUPPORTED_CHANNELS
            ):
                raise ValueError("authenticated media channels are invalid")
            if conversations != ["private"] or authorities != ["owner"]:
                raise ValueError("v1 authenticated media is Owner private only")
            if document["required_capability"] != "vision":
                raise ValueError("v1 authenticated media requires vision capability")
            age = document["maximum_age_seconds"]
            skew = document["maximum_future_skew_seconds"]
            count = document["maximum_media_count"]
            if not isinstance(age, int) or not 30 <= age <= 900:
                raise ValueError("media delivery age window is invalid")
            if not isinstance(skew, int) or not 0 <= skew <= 60:
                raise ValueError("media delivery future skew is invalid")
            if not isinstance(count, int) or not 1 <= count <= 4:
                raise ValueError("media delivery count is invalid")
            return cls(
                schema_version=POLICY_SCHEMA_VERSION,
                policy_id=_safe_id(document["policy_id"], "policy_id"),
                status="inactive_candidate",
                allowed_channel_kinds=frozenset(channels),
                allowed_conversation_kinds=frozenset({"private"}),
                allowed_authority_levels=frozenset({"owner"}),
                required_capability="vision",
                maximum_age_seconds=age,
                maximum_future_skew_seconds=skew,
                maximum_media_count=count,
            )
        except (KeyError, TypeError, ValueError):
            raise _reject() from None

    @classmethod
    def load(cls, path: Path) -> AuthenticatedMediaDeliveryPolicy:
        try:
            return cls.from_document(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise _reject() from None

    def evaluate_offline(
        self,
        delivery: AuthenticatedMediaDelivery,
        decision: ChannelAuthorizationDecision,
        *,
        now: datetime,
    ) -> VisionInputEnvelope:
        """Validate a candidate chain; R1 has no live activation entry point."""

        try:
            current = _utc(now, "now")
            context = delivery.context
            if (
                context.channel_kind not in self.allowed_channel_kinds
                or context.conversation_kind not in self.allowed_conversation_kinds
                or context.authority_level not in self.allowed_authority_levels
                or decision.channel_kind != context.channel_kind
                or decision.principal_id != context.principal_id
                or decision.namespace_id != context.namespace_id
                or self.required_capability not in decision.granted_capabilities
                or len(delivery.media) > self.maximum_media_count
                or context.occurred_at
                < current - timedelta(seconds=self.maximum_age_seconds)
                or context.occurred_at
                > current + timedelta(seconds=self.maximum_future_skew_seconds)
                or delivery.received_at < current - timedelta(seconds=self.maximum_age_seconds)
                or delivery.received_at
                > current + timedelta(seconds=self.maximum_future_skew_seconds)
            ):
                raise _reject()
            return delivery.to_vision_envelope()
        except (TypeError, ValueError, AuthenticatedMediaDeliveryError):
            raise _reject() from None
