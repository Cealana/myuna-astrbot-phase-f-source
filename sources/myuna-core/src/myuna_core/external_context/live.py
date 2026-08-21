from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from hashlib import sha256
import os
from pathlib import Path
from typing import Mapping

from myuna_core.audit import AuditLogger
from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.channel_capability import ChannelNeutralCapabilityProfile
from myuna_core.config import Settings
from myuna_core.conversation import (
    ConversationError,
    ConversationGuardError,
    ConversationPreProviderError,
    ConversationProfileError,
    DevConversationEngine,
    assemble_runtime_prompt,
    parse_conversation_input,
)
from myuna_core.owner_profile.access import OwnerProfileExternalEgressPolicy
from myuna_core.owner_profile.client import (
    AuditedOwnerProfileReadRuntime,
    UnixSocketOwnerProfileClient,
)
from myuna_core.providers.base import ModelRequest, ModelResponse, ProviderError
from myuna_core.providers.registry import get_model_spec
from myuna_core.providers.runtime import build_deepseek_runtime_provider
from myuna_core.episodic_memory.runtime_context import (
    RUNTIME_CONTEXT_SCHEMA,
    EpisodicProjectionBuilder,
    EpisodicRuntimeContext,
    EpisodicTurnProvenance,
)
from myuna_core.episodic_memory.context import ContextLimits
from myuna_core.episodic_memory.contracts import (
    EpisodicMemoryError,
    semantic_digest,
)
from myuna_core.episodic_memory.diary_generation import (
    DIARY_MAX_OUTPUT_TOKENS,
    DIARY_PROVIDER_TIMEOUT_SECONDS,
    DiaryGenerationJob,
    DiaryGenerationResult,
    ReflectiveDiaryGenerationCoordinator,
)
from myuna_core.episodic_memory.owner_day import (
    OWNER_DAY_PREVIEW_PURPOSE,
    OwnerDayDiaryJob,
)
from myuna_core.episodic_memory.owner_day_generation import (
    OwnerDayDiaryGenerationCoordinator,
    OwnerDayDiaryGenerationResult,
)

from .contracts import (
    EXTERNAL_VISUAL_PROJECTION_POLICY,
    ExternalContextEnvelope,
    ExternalSummaryCandidate,
    ExternalSummaryJob,
    ExternalTurnProvenance,
)
from .lifecycle_v3 import (
    RELEASE_BOUND_CONTEXT_OVERLAY_SCHEMA,
    RELEASE_BOUND_CONTEXT_SCHEMA,
    ReleaseBoundExternalContext,
    ReleaseBoundLifecycleRejected,
    ReleaseBoundSummaryCandidate,
    ReleaseBoundSummaryJob,
    ReleaseBoundTurnProvenance,
)
from .policy_overlay import (
    PolicyOverlay,
    projection_policy_contract,
)
from .projection import ExternalProjectionBuilder, ProjectionBudget
from .release_set import P07DReleaseSet
from .runtime import (
    ExternalProviderFailure,
    HybridExternalGenerationCoordinator,
    HybridGenerationError,
)
from .summary import ExternalSummaryCoordinator


HYBRID_MODEL = "deepseek-v4-flash"
HYBRID_ROUTE_REASON = "p07_hybrid_external_generation"
HYBRID_CALLER = "myuna_core_p07_hybrid"
SUMMARY_ROUTE_REASON = "p07_external_rolling_summary"
SUMMARY_CALLER = "myuna_core_p07_summary"
VISUAL_ROUTE_REASON = "p01b_contextual_visual_interpretation"
VISUAL_CALLER = "myuna_core_p01b_visual"
DIARY_ROUTE_REASON = "p07_external_reflective_diary"
DIARY_CALLER = "myuna_core_p07_reflective_diary"
OWNER_DAY_DIARY_ROUTE_REASON = "p07_external_owner_day_reflective_diary_v2"
OWNER_DAY_DIARY_CALLER = "myuna_core_p07_owner_day_reflective_diary_v2"
HYBRID_TIMEOUT_SECONDS = 75.0
HYBRID_MAX_OUTPUT_TOKENS = 768
HYBRID_PROVIDER_MAX_INPUT_CHARACTERS = 200_000
HYBRID_REPAIR_HEADROOM_CHARACTERS = 1_000
HYBRID_PROJECTION_MAX_CHARACTERS = (
    HYBRID_PROVIDER_MAX_INPUT_CHARACTERS - HYBRID_REPAIR_HEADROOM_CHARACTERS
)
HYBRID_SERIALIZED_BYTES_PER_CHARACTER = 6
HYBRID_SERIALIZED_OVERHEAD_BYTES = 4_096
_PROFILE_PROJECTION_FAILURES = frozenset(
    {
        "malformed_worker_response",
        "profile_digest_mismatch",
        "profile_permission_drift",
        "profile_timeout",
        "profile_type_drift",
        "profile_unavailable",
        "receipt_mismatch",
        "release_identity_mismatch",
    }
)


def hybrid_projection_budget() -> ProjectionBudget:
    """Bind external projection limits to the provider request contract."""

    model = get_model_spec(HYBRID_MODEL, provider="deepseek")
    if model.context_tokens <= HYBRID_MAX_OUTPUT_TOKENS:
        raise ValueError("hybrid model context is smaller than output reservation")
    return ProjectionBudget(
        max_total_characters=HYBRID_PROJECTION_MAX_CHARACTERS,
        max_serialized_bytes=(
            HYBRID_SERIALIZED_BYTES_PER_CHARACTER
            * HYBRID_PROJECTION_MAX_CHARACTERS
            + HYBRID_SERIALIZED_OVERHEAD_BYTES
        ),
        max_input_tokens=model.context_tokens - HYBRID_MAX_OUTPUT_TOKENS,
    )


def _typed_hybrid_conversation_failure(
    exc: HybridGenerationError,
) -> ConversationError | ProviderError:
    if exc.code in _PROFILE_PROJECTION_FAILURES:
        return ConversationProfileError(exc.code, retryable=exc.retryable)
    if exc.code == "external_generation_timeout":
        return ProviderError(
            "transport_failure",
            "external generation timed out",
            retryable=True,
            attempts=exc.attempts,
        )
    if exc.code == "external_provider_unavailable":
        return ProviderError(
            "upstream_server_error",
            "external provider unavailable",
            retryable=True,
            attempts=exc.attempts,
        )
    if exc.code == "external_provider_failure" and exc.provider_code is not None:
        return ProviderError(
            exc.provider_code,
            "external provider request failed",
            retryable=exc.retryable,
            attempts=exc.attempts,
        )
    if exc.code in {
        "external_reply_repair_exhausted",
        "visual_interpretation_result_rejected",
    }:
        return ConversationGuardError(exc.code)
    return ConversationPreProviderError(exc.code)


def _hybrid_provider_environ(environ: Mapping[str, str]) -> dict[str, str]:
    scoped = dict(environ)
    scoped["MYUNA_DEEPSEEK_MODEL"] = HYBRID_MODEL
    return scoped


def _token_upper_bound(messages: tuple[Mapping[str, str], ...]) -> int:
    # Every model token consumes at least one serialized UTF-8 byte.  Counting
    # content bytes therefore gives a deterministic conservative upper bound
    # without adding a tokenizer dependency to the trusted runtime.
    return max(1, sum(len(item["content"].encode("utf-8")) for item in messages))


class _ExternalProviderAdapter:
    name = "deepseek"
    default_model = HYBRID_MODEL

    def __init__(self, provider: object, *, request_id: str) -> None:
        if getattr(provider, "name", None) != self.name:
            raise ValueError("hybrid provider name drifted")
        if getattr(provider, "default_model", None) != self.default_model:
            raise ValueError("hybrid provider model drifted")
        self.provider = provider
        self.request_id = request_id
        self.attempt = 0
        self.last_response: ModelResponse | None = None

    def generate(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
        repair_instruction: str | None,
    ) -> str:
        return self._generate(
            messages,
            timeout_seconds=timeout_seconds,
            repair_instruction=repair_instruction,
            response_format="text",
            route_reason=HYBRID_ROUTE_REASON,
            caller=HYBRID_CALLER,
            request_suffix="p07",
        )

    def _generate(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
        repair_instruction: str | None,
        response_format: str,
        route_reason: str,
        caller: str,
        request_suffix: str,
        max_output_tokens: int = HYBRID_MAX_OUTPUT_TOKENS,
    ) -> str:
        if timeout_seconds <= 0:
            raise TimeoutError("hybrid deadline expired")
        self.attempt += 1
        projected = messages
        if repair_instruction is not None:
            projected = (*messages, {"role": "system", "content": repair_instruction})
        try:
            response = self.provider.generate(
                ModelRequest(
                    request_id=f"{self.request_id}-{request_suffix}-{self.attempt}",
                    messages=projected,
                    model=HYBRID_MODEL,
                    max_output_tokens=max_output_tokens,
                    max_input_characters=HYBRID_PROVIDER_MAX_INPUT_CHARACTERS,
                    thinking="disabled",
                    response_format=response_format,
                    route_reason=route_reason,
                    caller=caller,
                )
            )
        except ProviderError as exc:
            raise ExternalProviderFailure(
                exc.code,
                retryable=exc.retryable,
            ) from None
        self.last_response = response
        return response.text

    def generate_structured(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
    ) -> str:
        return self._generate(
            messages,
            timeout_seconds=timeout_seconds,
            repair_instruction=None,
            response_format="json_object",
            route_reason=VISUAL_ROUTE_REASON,
            caller=VISUAL_CALLER,
            request_suffix="p01b",
        )

    def generate_summary(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
    ) -> str:
        return self._generate(
            messages,
            timeout_seconds=timeout_seconds,
            repair_instruction=None,
            response_format="text",
            route_reason=SUMMARY_ROUTE_REASON,
            caller=SUMMARY_CALLER,
            request_suffix="p07-summary",
        )

    def generate_diary(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
    ) -> str:
        return self._generate(
            messages,
            timeout_seconds=timeout_seconds,
            repair_instruction=None,
            response_format="json_object",
            route_reason=DIARY_ROUTE_REASON,
            caller=DIARY_CALLER,
            request_suffix="p07-diary",
            max_output_tokens=DIARY_MAX_OUTPUT_TOKENS,
        )

    def generate_owner_day_diary(
        self,
        messages: tuple[Mapping[str, str], ...],
        *,
        timeout_seconds: float,
    ) -> str:
        return self._generate(
            messages,
            timeout_seconds=timeout_seconds,
            repair_instruction=None,
            response_format="json_object",
            route_reason=OWNER_DAY_DIARY_ROUTE_REASON,
            caller=OWNER_DAY_DIARY_CALLER,
            request_suffix="p07-owner-day-diary-v2",
            max_output_tokens=DIARY_MAX_OUTPUT_TOKENS,
        )


@dataclass(frozen=True, slots=True)
class HybridPublicResult:
    request_id: str
    reply: str
    response: ModelResponse
    repaired: bool
    external_turn_provenance: ExternalTurnProvenance | ReleaseBoundTurnProvenance | EpisodicTurnProvenance | None = None
    route_reason: str = HYBRID_ROUTE_REASON

    def public_payload(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "reply": self.reply,
            "provider": self.response.provider,
            "model": self.response.model,
            "route_reason": self.route_reason,
            "repaired": self.repaired,
            "usage": {
                "input_tokens": self.response.input_tokens,
                "output_tokens": self.response.output_tokens,
                "reasoning_tokens": self.response.reasoning_tokens,
            },
            "actual_cost_usd": str(self.response.cost_usd or Decimal(0)),
            "budget_accounted_usd": str(
                self.response.budget_accounted_usd or Decimal(0)
            ),
            "external_turn_provenance": (
                None
                if self.external_turn_provenance is None
                else self.external_turn_provenance.as_payload()
            ),
            "synthetic_memory": {
                "used": False,
                "hit_ids": [],
                "mode_used": None,
                "degraded_reason": None,
                "fixture_sha256": None,
            },
            "owner_memory": {
                "used": isinstance(self.external_turn_provenance, EpisodicTurnProvenance),
                "hit_count": (
                    sum(
                        end - start + 1
                        for start, end in self.external_turn_provenance.source_ranges
                    )
                    if isinstance(self.external_turn_provenance, EpisodicTurnProvenance)
                    else 0
                ),
                "mode_used": (
                    "historical_raw_recall_v1"
                    if isinstance(self.external_turn_provenance, EpisodicTurnProvenance)
                    else None
                ),
                "degraded_reason": None,
                "policy_version": None,
            },
        }


@dataclass(frozen=True, slots=True)
class SummaryPublicResult:
    candidate: ExternalSummaryCandidate | ReleaseBoundSummaryCandidate
    response: ModelResponse

    def public_payload(self) -> dict[str, object]:
        return {
            "actual_cost_usd": str(self.response.cost_usd or Decimal(0)),
            "budget_accounted_usd": str(
                self.response.budget_accounted_usd or Decimal(0)
            ),
            "model": self.response.model,
            "provider": self.response.provider,
            "route_reason": SUMMARY_ROUTE_REASON,
            "summary_candidate": self.candidate.as_payload(),
            "usage": {
                "input_tokens": self.response.input_tokens,
                "output_tokens": self.response.output_tokens,
                "reasoning_tokens": self.response.reasoning_tokens,
            },
        }


@dataclass(frozen=True, slots=True)
class DiaryPublicResult:
    result: DiaryGenerationResult
    response: ModelResponse | None

    def public_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "candidate": (
                None
                if self.result.candidate is None
                else self.result.candidate.as_payload()
            ),
            "capacity": self.result.capacity.audit_projection(),
            "job_digest": self.result.job_digest,
            "provider_called": self.result.provider_called,
            "route_reason": DIARY_ROUTE_REASON,
            "status": self.result.status,
        }
        if self.response is None:
            payload.update(
                {
                    "actual_cost_usd": "0",
                    "budget_accounted_usd": "0",
                    "model": HYBRID_MODEL,
                    "provider": "deepseek",
                    "usage": {
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "reasoning_tokens": 0,
                    },
                }
            )
        else:
            payload.update(
                {
                    "actual_cost_usd": str(
                        self.response.cost_usd or Decimal(0)
                    ),
                    "budget_accounted_usd": str(
                        self.response.budget_accounted_usd or Decimal(0)
                    ),
                    "model": self.response.model,
                    "provider": self.response.provider,
                    "usage": {
                        "input_tokens": self.response.input_tokens,
                        "output_tokens": self.response.output_tokens,
                        "reasoning_tokens": self.response.reasoning_tokens,
                    },
                }
            )
        return payload


@dataclass(frozen=True, slots=True)
class OwnerDayDiaryPublicResult:
    result: OwnerDayDiaryGenerationResult
    response: ModelResponse | None

    def public_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "candidate": (
                None
                if self.result.candidate is None
                else self.result.candidate.as_payload()
            ),
            "capacity": self.result.capacity.audit_projection(),
            "job_digest": self.result.job_digest,
            "provider_called": self.result.provider_called,
            "route_reason": OWNER_DAY_DIARY_ROUTE_REASON,
            "status": self.result.status,
        }
        if self.response is None:
            payload.update(
                {
                    "actual_cost_usd": "0",
                    "budget_accounted_usd": "0",
                    "model": HYBRID_MODEL,
                    "provider": "deepseek",
                    "usage": {
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "reasoning_tokens": 0,
                    },
                }
            )
        else:
            payload.update(
                {
                    "actual_cost_usd": str(self.response.cost_usd or Decimal(0)),
                    "budget_accounted_usd": str(
                        self.response.budget_accounted_usd or Decimal(0)
                    ),
                    "model": self.response.model,
                    "provider": self.response.provider,
                    "usage": {
                        "input_tokens": self.response.input_tokens,
                        "output_tokens": self.response.output_tokens,
                        "reasoning_tokens": self.response.reasoning_tokens,
                    },
                }
            )
        return payload


class LiveHybridConversationEngine:
    """Telegram-only adapter over the reviewed P07 source coordinator."""

    def __init__(
        self,
        settings: Settings,
        audit: AuditLogger,
        conversation_engine: DevConversationEngine,
        *,
        provider: object | None = None,
        release_set: P07DReleaseSet | None = None,
        policy_overlay: PolicyOverlay | None = None,
        episodic_overlay_id: str | None = None,
        episodic_memory_release_set_id: str | None = None,
        reflective_diary_egress_binding_digest: str | None = None,
        owner_day_diary_closed_egress_binding_digest: str | None = None,
        owner_day_diary_preview_egress_binding_digest: str | None = None,
    ) -> None:
        if not settings.owner_profile_read_enabled:
            raise ConversationError("hybrid generation requires Owner Profile read")
        profile_path = settings.owner_profile_capability_profile_path
        if profile_path is None:
            raise ConversationError("hybrid capability profile is unavailable")
        capability_profile = ChannelNeutralCapabilityProfile.load(profile_path)
        retriever = AuditedOwnerProfileReadRuntime(
            UnixSocketOwnerProfileClient(settings.owner_profile_worker_socket),
            audit,
            timeout_seconds=settings.owner_profile_timeout_ms / 1000,
        )
        projection_budget = hybrid_projection_budget()
        projection_builder = ExternalProjectionBuilder(
            projection_budget,
            token_counter=_token_upper_bound,
        )
        self.settings = settings
        self.audit = audit
        self.conversation_engine = conversation_engine
        if provider is None:
            provider = build_deepseek_runtime_provider(
                data_dir=settings.data_dir,
                audit=audit,
                environ=_hybrid_provider_environ(os.environ),
            )
        self.provider = provider
        self.release_set = release_set
        self.policy_overlay = policy_overlay
        self.episodic_overlay_id = episodic_overlay_id
        self.episodic_memory_release_set_id = episodic_memory_release_set_id
        self.reflective_diary_egress_binding_digest = (
            reflective_diary_egress_binding_digest
        )
        self.owner_day_diary_closed_egress_binding_digest = (
            owner_day_diary_closed_egress_binding_digest
        )
        self.owner_day_diary_preview_egress_binding_digest = (
            owner_day_diary_preview_egress_binding_digest
        )
        if (
            owner_day_diary_closed_egress_binding_digest is None
        ) != (owner_day_diary_preview_egress_binding_digest is None):
            raise ConversationError("owner-day diary binding is incomplete")
        if (episodic_overlay_id is None) != (episodic_memory_release_set_id is None):
            raise ConversationError("episodic memory binding is incomplete")
        if policy_overlay is not None:
            if release_set is None:
                raise ConversationError("policy overlay requires parent release set")
            if (
                policy_overlay.parent["release_set_id"]
                != release_set.release_set_id
            ):
                raise ConversationError("policy overlay parent release set mismatch")
            policy = projection_policy_contract()
            if (
                policy_overlay.policy != policy
                or policy["max_projection_characters"]
                != projection_budget.max_total_characters
                or policy["max_serialized_bytes"]
                != projection_budget.max_serialized_bytes
                or policy["max_input_tokens"]
                != projection_budget.max_input_tokens
            ):
                raise ConversationError("policy overlay projection oracle mismatch")
        self.coordinator = HybridExternalGenerationCoordinator(
            access_policy=OwnerProfileExternalEgressPolicy(capability_profile),
            projection_builder=projection_builder,
            profile_retriever=retriever,
            episodic_projection_builder=EpisodicProjectionBuilder(
                projection_budget,
                token_counter=_token_upper_bound,
                context_limits=ContextLimits(
                    request_characters=HYBRID_PROVIDER_MAX_INPUT_CHARACTERS,
                    projection_characters=HYBRID_PROJECTION_MAX_CHARACTERS,
                    serialized_bytes=projection_budget.max_serialized_bytes,
                    input_tokens=projection_budget.max_input_tokens,
                    output_reserve_characters=0,
                    output_reserve_bytes=0,
                    output_reserve_tokens=0,
                ),
            ),
        )

    @property
    def release_set_id(self) -> str | None:
        return None if self.release_set is None else self.release_set.release_set_id

    @property
    def policy_overlay_id(self) -> str | None:
        return (
            None
            if self.policy_overlay is None
            else self.policy_overlay.overlay_id
        )

    def converse_external(
        self,
        conversation_payload: object,
        external_context_payload: Mapping[str, object],
        *,
        request_id: str,
        authenticated_context: AuthenticatedConversationContext,
    ) -> HybridPublicResult:
        release_bound_context: ReleaseBoundExternalContext | None = None
        episodic_context: EpisodicRuntimeContext | None = None
        effective_external_context = external_context_payload
        if external_context_payload.get("schema") == RUNTIME_CONTEXT_SCHEMA:
            if self.release_set is None or self.episodic_overlay_id is None:
                raise ConversationError("episodic_runtime_context_not_selected")
            try:
                episodic_context = EpisodicRuntimeContext.from_payload(
                    external_context_payload,
                    authenticated_context=authenticated_context,
                )
            except Exception as exc:
                code = getattr(exc, "code", "episodic_runtime_context_rejected")
                raise ConversationError(code) from None
            if (
                episodic_context.parent_release_set_id != self.release_set.release_set_id
                or episodic_context.policy_overlay_id != self.episodic_overlay_id
            ):
                raise ConversationError("episodic_runtime_context_binding_mismatch")
        elif self.release_set is not None:
            try:
                release_bound_context = ReleaseBoundExternalContext.from_payload(
                    external_context_payload,
                    context=authenticated_context,
                )
            except ReleaseBoundLifecycleRejected as exc:
                raise ConversationError(exc.code) from None
            if release_bound_context.release_set_id != self.release_set.release_set_id:
                raise ConversationError("release_bound_context_release_set_mismatch")
            if release_bound_context.policy_overlay_id != self.policy_overlay_id:
                raise ConversationError(
                    "release_bound_context_policy_overlay_mismatch"
                )
            expected_policy = (
                EXTERNAL_VISUAL_PROJECTION_POLICY
                if release_bound_context.envelope.visual_evidence is not None
                else (
                    self.release_set.projection_policy_version
                    if self.policy_overlay is None
                    else self.policy_overlay.policy["policy_version"]
                )
            )
            if (
                release_bound_context.envelope.projection_policy_version
                != expected_policy
            ):
                raise ConversationError(
                    "release_bound_context_projection_policy_mismatch"
                )
            effective_external_context = release_bound_context.envelope.as_payload()
        elif external_context_payload.get("schema") in {
            RELEASE_BOUND_CONTEXT_SCHEMA,
            RELEASE_BOUND_CONTEXT_OVERLAY_SCHEMA,
        }:
            raise ConversationError("release_bound_context_without_release_set")
        request = parse_conversation_input(
            conversation_payload,
            context_policy=self.conversation_engine.context_policy,
        )
        if (
            len(request.messages) != 1
            or request.mode not in {"auto", "myuna"}
            or request.task_class != "ordinary_chat"
            or request.synthetic_memory
        ):
            raise ConversationError("hybrid request scope rejected")
        if episodic_context is not None and request.messages[0]["content"] != episodic_context.current_message:
            raise ConversationError("episodic_current_message_mismatch")
        definition = assemble_runtime_prompt(
            self.conversation_engine.release,
            self.conversation_engine.manifest,
            request,
            prompt_budget=self.conversation_engine.prompt_budget,
        )
        adapter = _ExternalProviderAdapter(self.provider, request_id=request_id)
        try:
            generated = self.coordinator.generate(
                context=authenticated_context,
                envelope_payload=effective_external_context,
                definition=definition,
                definition_digest=sha256(definition.encode("utf-8")).hexdigest(),
                provider=adapter,
                timeout_seconds=HYBRID_TIMEOUT_SECONDS,
                episodic_context=episodic_context,
                trace_marker=lambda stage, status, attempt: self.audit.emit_trace_marker(
                    trace_id=authenticated_context.trace_id,
                    stage=stage,
                    status=status,
                    attempt_ordinal=attempt,
                ),
            )
        except HybridGenerationError as exc:
            raise _typed_hybrid_conversation_failure(exc) from None
        response = adapter.last_response
        if response is None:
            raise ConversationError("hybrid provider response unavailable")
        envelope = (
            release_bound_context.envelope
            if release_bound_context is not None
            else None if episodic_context is not None else ExternalContextEnvelope.from_payload(
                effective_external_context,
                context=authenticated_context,
            )
        )
        provenance: ExternalTurnProvenance | ReleaseBoundTurnProvenance | EpisodicTurnProvenance
        if episodic_context is not None:
            if generated.episodic_provenance is None:
                raise ConversationError("episodic_turn_provenance_unavailable")
            provenance = generated.episodic_provenance
        else:
            generated_provenance = generated.projection.turn_provenance(envelope)  # type: ignore[arg-type]
            provenance = (
                generated_provenance
                if self.release_set is None
                else ReleaseBoundTurnProvenance(
                    self.release_set.release_set_id,
                    generated_provenance,
                    policy_overlay_id=self.policy_overlay_id,
                )
            )
        self.audit.emit(
            "hybrid_external_generation",
            request_id=request_id,
            details=generated.audit_projection(),
        )
        return HybridPublicResult(
            request_id=request_id,
            reply=generated.reply,
            response=response,
            repaired=generated.repaired,
            external_turn_provenance=provenance,
            route_reason=(
                VISUAL_ROUTE_REASON
                if generated.projection.visual_evidence_present
                else HYBRID_ROUTE_REASON
            ),
        )

    def summarize_external(
        self,
        summary_job_payload: Mapping[str, object],
        *,
        request_id: str,
    ) -> SummaryPublicResult:
        try:
            release_bound_job: ReleaseBoundSummaryJob | None = None
            if self.release_set is None:
                job = ExternalSummaryJob.from_payload(summary_job_payload)
            else:
                release_bound_job = ReleaseBoundSummaryJob.from_payload(summary_job_payload)
                if release_bound_job.release_set_id != self.release_set.release_set_id:
                    raise ReleaseBoundLifecycleRejected(
                        "release_bound_summary_job_release_set_mismatch"
                    )
                job = release_bound_job.job
            adapter = _ExternalProviderAdapter(self.provider, request_id=request_id)
            generated = ExternalSummaryCoordinator().generate(
                job,
                adapter,
                timeout_seconds=HYBRID_TIMEOUT_SECONDS,
            )
        except (ValueError, TypeError) as exc:
            raise ConversationError(str(exc)) from None
        response = adapter.last_response
        if response is None:
            raise ConversationError("summary provider response unavailable")
        self.audit.emit(
            "external_rolling_summary",
            request_id=request_id,
            details=generated.audit_projection(),
        )
        candidate: ExternalSummaryCandidate | ReleaseBoundSummaryCandidate
        candidate = generated.candidate
        if release_bound_job is not None:
            candidate = ReleaseBoundSummaryCandidate(
                release_bound_job.release_set_id,
                release_bound_job.digest,
                generated.candidate.summary,
            )
        return SummaryPublicResult(candidate=candidate, response=response)

    def _reflective_diary_persona_context(self) -> str:
        request = parse_conversation_input(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": "Compose the bound closed-day reflective diary.",
                    }
                ],
                "mode": "myuna",
                "task_class": "ordinary_chat",
            },
            context_policy=self.conversation_engine.context_policy,
        )
        return assemble_runtime_prompt(
            self.conversation_engine.release,
            self.conversation_engine.manifest,
            request,
            prompt_budget=self.conversation_engine.prompt_budget,
            definition_projection="local_core_sections",
        )

    def generate_reflective_diary(
        self,
        diary_job_payload: Mapping[str, object],
        *,
        request_id: str,
    ) -> DiaryPublicResult:
        try:
            job = DiaryGenerationJob.from_payload(diary_job_payload)
            if (
                self.release_set is None
                or self.episodic_overlay_id is None
                or self.episodic_memory_release_set_id is None
                or self.reflective_diary_egress_binding_digest is None
                or job.parent_release_set_id != self.release_set.release_set_id
                or job.policy_overlay_id != self.episodic_overlay_id
                or job.memory_release_set_id
                != self.episodic_memory_release_set_id
                or job.egress_binding_digest
                != self.reflective_diary_egress_binding_digest
            ):
                raise EpisodicMemoryError("diary_release_binding_rejected")
            persona_context = self._reflective_diary_persona_context()
            persona_digest = semantic_digest(
                "myuna-p07-reflective-diary-persona-context-v1",
                {"persona_context": persona_context},
            )
            if persona_digest != job.persona_digest:
                raise EpisodicMemoryError("diary_persona_context_drifted")
            projection_budget = hybrid_projection_budget()
            adapter = _ExternalProviderAdapter(self.provider, request_id=request_id)
            generated = ReflectiveDiaryGenerationCoordinator(
                limits=ContextLimits(
                    request_characters=HYBRID_PROVIDER_MAX_INPUT_CHARACTERS,
                    projection_characters=HYBRID_PROJECTION_MAX_CHARACTERS,
                    serialized_bytes=projection_budget.max_serialized_bytes,
                    input_tokens=projection_budget.max_input_tokens,
                    output_reserve_characters=4_000,
                    output_reserve_bytes=16_000,
                    output_reserve_tokens=DIARY_MAX_OUTPUT_TOKENS,
                ),
                token_counter=_token_upper_bound,
            ).generate(
                job,
                persona_context=persona_context,
                provider=adapter,
                created_at_utc=datetime.now(timezone.utc),
                timeout_seconds=DIARY_PROVIDER_TIMEOUT_SECONDS,
            )
        except EpisodicMemoryError as exc:
            if exc.retryable:
                raise ConversationError(exc.code) from None
            raise ConversationGuardError(exc.code) from None
        self.audit.emit(
            "external_reflective_diary",
            request_id=request_id,
            details=generated.audit_projection(),
        )
        return DiaryPublicResult(result=generated, response=adapter.last_response)

    def generate_owner_day_diary(
        self,
        diary_job_payload: Mapping[str, object],
        *,
        request_id: str,
    ) -> OwnerDayDiaryPublicResult:
        try:
            job = OwnerDayDiaryJob.from_payload(diary_job_payload)
            expected_binding = (
                self.owner_day_diary_preview_egress_binding_digest
                if job.purpose == OWNER_DAY_PREVIEW_PURPOSE
                else self.owner_day_diary_closed_egress_binding_digest
            )
            if (
                self.release_set is None
                or self.episodic_overlay_id is None
                or self.episodic_memory_release_set_id is None
                or expected_binding is None
                or job.parent_release_set_id != self.release_set.release_set_id
                or job.policy_overlay_id != self.episodic_overlay_id
                or job.memory_release_set_id != self.episodic_memory_release_set_id
                or job.egress_binding_digest != expected_binding
            ):
                raise EpisodicMemoryError("owner_day_diary_release_binding_rejected")
            persona_context = self._reflective_diary_persona_context()
            persona_digest = semantic_digest(
                "myuna-p07-owner-day-diary-persona-context-v2",
                {"persona_context": persona_context},
            )
            if persona_digest != job.persona_digest:
                raise EpisodicMemoryError("owner_day_diary_persona_context_drifted")
            projection_budget = hybrid_projection_budget()
            adapter = _ExternalProviderAdapter(self.provider, request_id=request_id)
            generated = OwnerDayDiaryGenerationCoordinator(
                limits=ContextLimits(
                    request_characters=HYBRID_PROVIDER_MAX_INPUT_CHARACTERS,
                    projection_characters=HYBRID_PROJECTION_MAX_CHARACTERS,
                    serialized_bytes=projection_budget.max_serialized_bytes,
                    input_tokens=projection_budget.max_input_tokens,
                    output_reserve_characters=4_000,
                    output_reserve_bytes=16_000,
                    output_reserve_tokens=DIARY_MAX_OUTPUT_TOKENS,
                ),
                token_counter=_token_upper_bound,
            ).generate(
                job,
                persona_context=persona_context,
                provider=adapter,
                created_at_utc=job.as_of_utc,
                timeout_seconds=DIARY_PROVIDER_TIMEOUT_SECONDS,
            )
        except EpisodicMemoryError as exc:
            if exc.retryable:
                raise ConversationError(exc.code) from None
            raise ConversationGuardError(exc.code) from None
        self.audit.emit(
            "external_owner_day_reflective_diary_v2",
            request_id=request_id,
            details=generated.audit_projection(),
        )
        return OwnerDayDiaryPublicResult(result=generated, response=adapter.last_response)


def hybrid_live_enabled(environ: Mapping[str, str]) -> bool:
    raw = environ.get("MYUNA_P07_HYBRID_EXTERNAL_ENABLED", "false").strip().lower()
    if raw not in {"true", "false"}:
        raise ValueError("MYUNA_P07_HYBRID_EXTERNAL_ENABLED must be true or false")
    return raw == "true"
