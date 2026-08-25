from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Callable, Mapping, Protocol

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.owner_profile.access import (
    EXTERNAL_PROFILE_EGRESS_PURPOSE,
    OwnerProfileExternalEgressPolicy,
)
from myuna_core.owner_profile.contracts import (
    MAX_QUERY_CHARACTERS,
    OwnerProfileError,
    RetrievalResult,
)

from .contracts import (
    ExternalContextEnvelope,
    ExternalContextError,
    MAX_REPLY_CHARACTERS,
)
from .projection import ExternalProjection, ExternalProjectionBuilder
from .safety import enforce_external_egress_safety


_REPAIR_INSTRUCTION = (
    "Return one non-empty plain-text reply within the reply limit. "
    "Use only the same approved projection; do not add or infer missing context."
)
VISUAL_INTERPRETATION_RESULT_SCHEMA = "myuna.visual-interpretation-result.v1"
_VISUAL_CONFIDENCE = frozenset({"low", "medium", "high"})


def _bounded_profile_query(current_message: str) -> str:
    query = current_message.strip()
    if len(query) <= MAX_QUERY_CHARACTERS:
        return query
    head = (MAX_QUERY_CHARACTERS - 1) // 2
    tail = MAX_QUERY_CHARACTERS - head - 1
    return query[:head] + "…" + query[-tail:]


class ExternalGenerationProvider(Protocol):
    name: str
    default_model: str

    def generate(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
        repair_instruction: str | None,
    ) -> str: ...

    def generate_structured(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
    ) -> str: ...


class ExternalProfileRetriever(Protocol):
    def retrieve(
        self,
        query: str,
        *,
        request_id: str,
        channel_kind: str,
    ) -> RetrievalResult: ...


class ExternalProviderFailure(RuntimeError):
    """Safe adapter-to-coordinator provider failure without provider imports."""

    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class HybridGenerationError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        attempts: int = 1,
        provider_code: str | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.attempts = attempts
        self.provider_code = provider_code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class HybridGenerationResult:
    reply: str
    projection: ExternalProjection
    attempts: int
    repaired: bool
    visual_confidence: str | None = None
    visual_uncertainty_present: bool = False

    def audit_projection(self) -> dict[str, object]:
        return {
            **self.projection.audit_projection(),
            "attempts": self.attempts,
            "repaired": self.repaired,
            "reply_characters": len(self.reply),
            "visual_confidence": self.visual_confidence,
            "visual_uncertainty_present": self.visual_uncertainty_present,
        }


class HybridExternalGenerationCoordinator:
    """Source-only coordinator; callers inject a fake or separately approved provider."""

    def __init__(
        self,
        *,
        access_policy: OwnerProfileExternalEgressPolicy,
        projection_builder: ExternalProjectionBuilder,
        profile_retriever: ExternalProfileRetriever,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.access_policy = access_policy
        self.projection_builder = projection_builder
        self.profile_retriever = profile_retriever
        self.monotonic = monotonic

    @staticmethod
    def _valid_reply(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        reply = value.strip()
        if not reply or len(reply) > MAX_REPLY_CHARACTERS or "\x00" in reply:
            return None
        return reply

    @classmethod
    def _parse_visual_result(cls, value: object) -> tuple[str, str, bool]:
        if not isinstance(value, str) or len(value) > 16_000:
            raise HybridGenerationError("visual_interpretation_result_rejected")
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            raise HybridGenerationError("visual_interpretation_result_rejected") from None
        required = {"confidence", "final_reply", "focus", "schema", "uncertainty"}
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise HybridGenerationError("visual_interpretation_result_rejected")
        if payload["schema"] != VISUAL_INTERPRETATION_RESULT_SCHEMA:
            raise HybridGenerationError("visual_interpretation_result_rejected")
        confidence = payload["confidence"]
        focus = payload["focus"]
        uncertainty = payload["uncertainty"]
        if confidence not in _VISUAL_CONFIDENCE:
            raise HybridGenerationError("visual_interpretation_result_rejected")
        if (
            not isinstance(focus, str)
            or not focus.strip()
            or len(focus) > 1_000
            or "\x00" in focus
        ):
            raise HybridGenerationError("visual_interpretation_result_rejected")
        if uncertainty is not None and (
            not isinstance(uncertainty, str)
            or not uncertainty.strip()
            or len(uncertainty) > 1_000
            or "\x00" in uncertainty
        ):
            raise HybridGenerationError("visual_interpretation_result_rejected")
        if confidence == "low" and uncertainty is None:
            raise HybridGenerationError("visual_interpretation_result_rejected")
        reply = cls._valid_reply(payload["final_reply"])
        if reply is None:
            raise HybridGenerationError("visual_interpretation_result_rejected")
        return reply, confidence, uncertainty is not None

    def generate(
        self,
        *,
        context: AuthenticatedConversationContext,
        envelope_payload: object,
        definition: str,
        definition_digest: str,
        provider: ExternalGenerationProvider,
        timeout_seconds: float,
    ) -> HybridGenerationResult:
        if not 0.05 <= timeout_seconds <= 180.0:
            raise HybridGenerationError("generation_timeout_out_of_contract")
        started = self.monotonic()
        try:
            envelope = ExternalContextEnvelope.from_payload(
                envelope_payload,
                context=context,
            )
            enforce_external_egress_safety(
                envelope.current_message,
                envelope.safety,
            )
            if envelope.visual_evidence is not None:
                enforce_external_egress_safety(
                    envelope.visual_evidence.observation,
                    envelope.safety,
                )
            self.access_policy.authorize(
                context,
                provider_name=provider.name,
                model_name=provider.default_model,
                egress_purpose=EXTERNAL_PROFILE_EGRESS_PURPOSE,
                projection_policy_version=envelope.projection_policy_version,
            )
            profile = self.profile_retriever.retrieve(
                _bounded_profile_query(envelope.current_message),
                request_id=f"{context.request_id}-owner-profile",
                channel_kind=context.channel_kind,
            )
            projection = self.projection_builder.build(
                definition=definition,
                definition_digest=definition_digest,
                envelope=envelope,
                profile=profile,
            )
        except (ExternalContextError, OwnerProfileError) as exc:
            raise HybridGenerationError(exc.code) from None
        except PermissionError as exc:
            code = getattr(exc, "code", "external_profile_egress_rejected")
            raise HybridGenerationError(code) from None

        if envelope.visual_evidence is not None:
            remaining = timeout_seconds - (self.monotonic() - started)
            if remaining <= 0:
                raise HybridGenerationError("external_generation_timeout")
            try:
                candidate = provider.generate_structured(
                    projection.messages,
                    timeout_seconds=remaining,
                )
            except TimeoutError:
                raise HybridGenerationError("external_generation_timeout") from None
            except (OSError, RuntimeError):
                raise HybridGenerationError("external_provider_unavailable") from None
            reply, confidence, uncertainty_present = self._parse_visual_result(candidate)
            return HybridGenerationResult(
                reply=reply,
                projection=projection,
                attempts=1,
                repaired=False,
                visual_confidence=confidence,
                visual_uncertainty_present=uncertainty_present,
            )

        attempts = 0
        transient_retry_used = False
        for repair_instruction in (None, _REPAIR_INSTRUCTION):
            while True:
                remaining = timeout_seconds - (self.monotonic() - started)
                if remaining <= 0:
                    raise HybridGenerationError(
                        "external_generation_timeout",
                        attempts=max(1, attempts),
                    )
                attempts += 1
                try:
                    candidate = provider.generate(
                        projection.messages,
                        timeout_seconds=remaining,
                        repair_instruction=repair_instruction,
                    )
                    break
                except ExternalProviderFailure as exc:
                    if exc.retryable and not transient_retry_used:
                        transient_retry_used = True
                        continue
                    raise HybridGenerationError(
                        "external_provider_failure",
                        attempts=attempts,
                        provider_code=exc.code,
                        retryable=exc.retryable,
                    ) from None
                except TimeoutError:
                    if transient_retry_used:
                        raise HybridGenerationError(
                            "external_generation_timeout",
                            attempts=attempts,
                        ) from None
                    transient_retry_used = True
                except (OSError, RuntimeError):
                    if transient_retry_used:
                        raise HybridGenerationError(
                            "external_provider_unavailable",
                            attempts=attempts,
                        ) from None
                    transient_retry_used = True
            reply = self._valid_reply(candidate)
            if reply is not None:
                return HybridGenerationResult(
                    reply=reply,
                    projection=projection,
                    attempts=attempts,
                    repaired=repair_instruction is not None,
                )
        raise HybridGenerationError("external_reply_repair_exhausted")
