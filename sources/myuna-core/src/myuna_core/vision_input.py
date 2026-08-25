from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping, Protocol, Sequence

from .authenticated_conversation import AuthenticatedConversationContext
from .channel_capability import ChannelAuthorizationDecision


INPUT_SCHEMA_VERSION = "myuna.vision-input-envelope.v1"
OBSERVATION_SCHEMA_VERSION = "myuna.vision-observation.v1"
POLICY_SCHEMA_VERSION = 1
INSTRUCTION_TRUST = "untrusted_media_content"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MIME_TYPES = frozenset({"image/jpeg", "image/png", "image/webp"})
_ANALYSIS_MODES = frozenset({"describe", "question_answer", "ocr_assist"})
_ABSOLUTE_MAX_MEDIA = 4
_ABSOLUTE_MAX_BYTES = 16 * 1024 * 1024
_ABSOLUTE_MAX_DIMENSION = 16384


class VisionInputContractError(PermissionError):
    """Fail-closed error without media, identity, or provider disclosure."""


def _reject() -> VisionInputContractError:
    return VisionInputContractError("vision input contract rejected")


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a safe opaque identifier")
    return value


def _bounded_text(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or "\x00" in normalized:
        raise ValueError(f"{label} is outside the supported range")
    return normalized


@dataclass(frozen=True, slots=True)
class VisionMediaDescriptor:
    """Metadata for bytes held behind a separate, short-lived media source port."""

    media_id: str
    content_sha256: str
    mime_type: str
    byte_length: int
    width: int
    height: int

    def __post_init__(self) -> None:
        _safe_id(self.media_id, "media_id")
        if _SHA256.fullmatch(self.content_sha256) is None:
            raise ValueError("content_sha256 must be lowercase SHA-256")
        if self.mime_type not in _MIME_TYPES:
            raise ValueError("unsupported image MIME type")
        if not isinstance(self.byte_length, int) or not 1 <= self.byte_length <= _ABSOLUTE_MAX_BYTES:
            raise ValueError("image byte length is outside the absolute limit")
        for value in (self.width, self.height):
            if not isinstance(value, int) or not 1 <= value <= _ABSOLUTE_MAX_DIMENSION:
                raise ValueError("image dimensions are outside the absolute limit")

    def audit_metadata(self) -> dict[str, object]:
        return {
            "byte_length": self.byte_length,
            "content_sha256": self.content_sha256,
            "height": self.height,
            "media_id": self.media_id,
            "mime_type": self.mime_type,
            "width": self.width,
        }


@dataclass(frozen=True, slots=True)
class VisionInputEnvelope:
    schema_version: str
    context: AuthenticatedConversationContext
    media: tuple[VisionMediaDescriptor, ...]
    user_question: str
    analysis_modes: tuple[str, ...] = ("question_answer",)

    def __post_init__(self) -> None:
        if self.schema_version != INPUT_SCHEMA_VERSION:
            raise ValueError("unsupported vision input schema")
        if not self.context.consent_media_processing:
            raise _reject()
        if not 1 <= len(self.media) <= _ABSOLUTE_MAX_MEDIA:
            raise ValueError("vision input must contain one to four images")
        media_ids = [item.media_id for item in self.media]
        if len(media_ids) != len(set(media_ids)):
            raise ValueError("media identifiers must be unique")
        object.__setattr__(
            self,
            "user_question",
            _bounded_text(self.user_question, label="user_question", maximum=4000),
        )
        if (
            not self.analysis_modes
            or len(self.analysis_modes) != len(set(self.analysis_modes))
            or any(mode not in _ANALYSIS_MODES for mode in self.analysis_modes)
        ):
            raise ValueError("analysis modes are invalid")

    def audit_metadata(self) -> dict[str, object]:
        """Return metadata only: no question, image bytes, path, URL, or account ID."""

        return {
            **self.context.audit_details(),
            "analysis_modes": list(self.analysis_modes),
            "media": [item.audit_metadata() for item in self.media],
            "media_count": len(self.media),
        }


@dataclass(frozen=True, slots=True)
class VisionInputPolicy:
    schema_version: int
    policy_id: str
    status: str
    allowed_mime_types: frozenset[str]
    max_media_count: int
    max_bytes_per_media: int
    max_total_bytes: int
    max_dimension: int
    allowed_analysis_modes: frozenset[str]
    provider_id: str
    model_registry_key: str
    allow_remote_url_fetch: bool
    allow_memory_write: bool
    allow_tools: bool
    allow_external_actions: bool

    @classmethod
    def from_document(cls, document: object) -> VisionInputPolicy:
        try:
            if not isinstance(document, Mapping):
                raise ValueError("vision policy must be an object")
            required = {
                "schema_version",
                "policy_id",
                "status",
                "limits",
                "allowed_analysis_modes",
                "provider_id",
                "model_registry_key",
                "side_effects",
            }
            if set(document) != required or document["schema_version"] != POLICY_SCHEMA_VERSION:
                raise ValueError("vision policy fields do not match v1")
            if document["status"] != "inactive_candidate":
                raise ValueError("v1 vision policy must remain inactive")
            limits = document["limits"]
            if not isinstance(limits, Mapping) or set(limits) != {
                "allowed_mime_types",
                "max_media_count",
                "max_bytes_per_media",
                "max_total_bytes",
                "max_dimension",
            }:
                raise ValueError("vision limits are invalid")
            mime_types = limits["allowed_mime_types"]
            if (
                not isinstance(mime_types, list)
                or not mime_types
                or len(mime_types) != len(set(mime_types))
                or not set(mime_types) <= _MIME_TYPES
            ):
                raise ValueError("allowed MIME types are invalid")
            modes = document["allowed_analysis_modes"]
            if (
                not isinstance(modes, list)
                or not modes
                or len(modes) != len(set(modes))
                or not set(modes) <= _ANALYSIS_MODES
            ):
                raise ValueError("allowed analysis modes are invalid")
            max_count = limits["max_media_count"]
            max_per_media = limits["max_bytes_per_media"]
            max_total = limits["max_total_bytes"]
            max_dimension = limits["max_dimension"]
            if not isinstance(max_count, int) or not 1 <= max_count <= _ABSOLUTE_MAX_MEDIA:
                raise ValueError("max_media_count is invalid")
            if not isinstance(max_per_media, int) or not 1 <= max_per_media <= _ABSOLUTE_MAX_BYTES:
                raise ValueError("max_bytes_per_media is invalid")
            if not isinstance(max_total, int) or not max_per_media <= max_total <= _ABSOLUTE_MAX_BYTES:
                raise ValueError("max_total_bytes is invalid")
            if not isinstance(max_dimension, int) or not 1 <= max_dimension <= _ABSOLUTE_MAX_DIMENSION:
                raise ValueError("max_dimension is invalid")
            side_effects = document["side_effects"]
            if not isinstance(side_effects, Mapping) or set(side_effects) != {
                "allow_remote_url_fetch",
                "allow_memory_write",
                "allow_tools",
                "allow_external_actions",
            }:
                raise ValueError("vision side-effect policy is invalid")
            if any(not isinstance(value, bool) for value in side_effects.values()):
                raise ValueError("vision side-effect grants must be boolean")
            if any(side_effects.values()):
                raise ValueError("v1 vision side effects must remain disabled")
            return cls(
                schema_version=POLICY_SCHEMA_VERSION,
                policy_id=_safe_id(document["policy_id"], "policy_id"),
                status="inactive_candidate",
                allowed_mime_types=frozenset(mime_types),
                max_media_count=max_count,
                max_bytes_per_media=max_per_media,
                max_total_bytes=max_total,
                max_dimension=max_dimension,
                allowed_analysis_modes=frozenset(modes),
                provider_id=_safe_id(document["provider_id"], "provider_id"),
                model_registry_key=_safe_id(document["model_registry_key"], "model_registry_key"),
                allow_remote_url_fetch=False,
                allow_memory_write=False,
                allow_tools=False,
                allow_external_actions=False,
            )
        except (KeyError, TypeError, ValueError):
            raise _reject() from None

    @classmethod
    def load(cls, path: Path) -> VisionInputPolicy:
        try:
            return cls.from_document(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise _reject() from None

    def authorize(
        self,
        envelope: VisionInputEnvelope,
        decision: ChannelAuthorizationDecision,
    ) -> VisionAdapterRequest:
        try:
            if "vision" not in decision.granted_capabilities:
                raise _reject()
            if (
                decision.channel_kind != envelope.context.channel_kind
                or decision.principal_id != envelope.context.principal_id
                or decision.namespace_id != envelope.context.namespace_id
            ):
                raise _reject()
            if len(envelope.media) > self.max_media_count:
                raise _reject()
            if any(
                item.mime_type not in self.allowed_mime_types
                or item.byte_length > self.max_bytes_per_media
                or item.width > self.max_dimension
                or item.height > self.max_dimension
                for item in envelope.media
            ):
                raise _reject()
            if sum(item.byte_length for item in envelope.media) > self.max_total_bytes:
                raise _reject()
            if not set(envelope.analysis_modes) <= self.allowed_analysis_modes:
                raise _reject()
            return VisionAdapterRequest(
                request_id=envelope.context.request_id,
                correlation_id=envelope.context.correlation_id,
                trace_id=envelope.context.trace_id,
                media=envelope.media,
                user_question=envelope.user_question,
                analysis_modes=envelope.analysis_modes,
                provider_id=self.provider_id,
                model_registry_key=self.model_registry_key,
            )
        except (KeyError, TypeError, ValueError, VisionInputContractError):
            raise _reject() from None


@dataclass(frozen=True, slots=True)
class VisionAdapterRequest:
    request_id: str
    correlation_id: str
    trace_id: str
    media: tuple[VisionMediaDescriptor, ...]
    user_question: str
    analysis_modes: tuple[str, ...]
    provider_id: str
    model_registry_key: str

    def provider_text(self) -> str:
        return self.user_question

    def audit_metadata(self) -> dict[str, object]:
        return {
            "analysis_modes": list(self.analysis_modes),
            "correlation_id": self.correlation_id,
            "media": [item.audit_metadata() for item in self.media],
            "model_registry_key": self.model_registry_key,
            "provider_id": self.provider_id,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
        }


class VisionMediaSourcePort(Protocol):
    def read_verified_bytes(
        self,
        descriptor: VisionMediaDescriptor,
        *,
        maximum_bytes: int,
    ) -> bytes: ...


class VisionAdapterPort(Protocol):
    def analyze(
        self,
        request: VisionAdapterRequest,
        media_source: VisionMediaSourcePort,
    ) -> VisionObservation: ...


def verify_media_bytes(descriptor: VisionMediaDescriptor, content: bytes) -> None:
    if len(content) != descriptor.byte_length:
        raise _reject()
    if hashlib.sha256(content).hexdigest() != descriptor.content_sha256:
        raise _reject()


@dataclass(frozen=True, slots=True)
class VisionClaim:
    text: str
    confidence: float
    evidence_media_ids: tuple[str, ...]
    uncertain: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "text", _bounded_text(self.text, label="claim", maximum=2000))
        if (
            not isinstance(self.confidence, (int, float))
            or isinstance(self.confidence, bool)
            or not math.isfinite(self.confidence)
            or not 0.0 <= self.confidence <= 1.0
        ):
            raise ValueError("claim confidence must be finite and between zero and one")
        if not self.evidence_media_ids or len(self.evidence_media_ids) != len(set(self.evidence_media_ids)):
            raise ValueError("claim evidence media IDs must be non-empty and unique")
        for media_id in self.evidence_media_ids:
            _safe_id(media_id, "evidence_media_id")
        if not isinstance(self.uncertain, bool):
            raise ValueError("claim uncertainty must be boolean")


@dataclass(frozen=True, slots=True)
class VisionObservation:
    schema_version: str
    request_id: str
    summary: str
    claims: tuple[VisionClaim, ...]
    warnings: tuple[str, ...]
    provider_id: str
    model_registry_key: str
    instruction_trust: str = INSTRUCTION_TRUST

    def __post_init__(self) -> None:
        if self.schema_version != OBSERVATION_SCHEMA_VERSION:
            raise ValueError("unsupported vision observation schema")
        _safe_id(self.request_id, "request_id")
        _safe_id(self.provider_id, "provider_id")
        _safe_id(self.model_registry_key, "model_registry_key")
        object.__setattr__(self, "summary", _bounded_text(self.summary, label="summary", maximum=8000))
        if not 1 <= len(self.claims) <= 64:
            raise ValueError("vision observation claims are outside the supported range")
        if len(self.warnings) > 16:
            raise ValueError("too many vision warnings")
        normalized_warnings = tuple(
            _bounded_text(value, label="warning", maximum=500) for value in self.warnings
        )
        object.__setattr__(self, "warnings", normalized_warnings)
        if self.instruction_trust != INSTRUCTION_TRUST:
            raise ValueError("media-derived text must remain untrusted")

    def as_model_evidence(self) -> Mapping[str, object]:
        """Return bounded evidence, never instructions, authority, tools, or memory writes."""

        return MappingProxyType(
            {
                "claims": [
                    {
                        "confidence": claim.confidence,
                        "evidence_media_ids": list(claim.evidence_media_ids),
                        "text": claim.text,
                        "uncertain": claim.uncertain,
                    }
                    for claim in self.claims
                ],
                "instruction_trust": self.instruction_trust,
                "summary": self.summary,
                "warnings": list(self.warnings),
            }
        )
