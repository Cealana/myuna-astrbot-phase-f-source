from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal
import json
import unittest

from myuna_core.active_temporal_context.time import TrustedTimeSample
from myuna_core.external_context.live import (
    DIARY_CALLER,
    DIARY_ROUTE_REASON,
    HYBRID_CALLER,
    HYBRID_MODEL,
    HYBRID_ROUTE_REASON,
    OWNER_DAY_DIARY_CALLER,
    OWNER_DAY_DIARY_ROUTE_REASON,
    SUMMARY_CALLER,
    SUMMARY_ROUTE_REASON,
    VISUAL_CALLER,
    VISUAL_ROUTE_REASON,
    HybridPublicResult,
    LiveHybridConversationEngine,
    _ExternalProviderAdapter,
    _hybrid_provider_environ,
    _typed_hybrid_conversation_failure,
    hybrid_live_enabled,
)
from tests.test_p07_reflective_diary_generation import (
    PERSONA,
    candidate_text,
    job_for_day,
)
from myuna_core.external_context.contracts import ExternalTurnProvenance
from myuna_core.external_context.lifecycle_v3 import ReleaseBoundTurnProvenance
from myuna_core.external_context.lifecycle_v3 import ReleaseBoundSummaryJob
from myuna_core.external_context.contracts import ExternalTurn, ZERO_DIGEST
from myuna_core.external_context.release_set import P07DReleaseSet
from tests.test_external_context_release_set import sample_fields
from myuna_core.providers.base import ModelResponse, ProviderError
from myuna_core.conversation import (
    ConversationError,
    ConversationGuardError,
    ConversationPreProviderError,
    ConversationProfileError,
)
from myuna_core.external_context.runtime import HybridGenerationError
from myuna_core.episodic_memory import (
    OWNER_DAY_PREVIEW_PURPOSE,
    OwnerDayPolicy,
    build_owner_day_diary_job,
)
from myuna_core.episodic_memory.contracts import semantic_digest
from tests.episodic_memory_fixtures import make_turn


class FakeProvider:
    name = "deepseek"
    default_model = "deepseek-v4-flash"

    def __init__(self) -> None:
        self.requests = []

    def generate(self, request):
        self.requests.append(request)
        return ModelResponse(
            provider="deepseek",
            model="deepseek-v4-flash",
            text="synthetic reply",
            input_tokens=10,
            output_tokens=4,
            cache_hit_tokens=0,
            cache_miss_tokens=10,
            reasoning_tokens=0,
            finish_reason="stop",
            cost_usd=Decimal("0.0001"),
            budget_accounted_usd=Decimal("0.0001"),
        )


class FakeAudit:
    def __init__(self) -> None:
        self.events = []

    def emit(self, event, **fields):
        self.events.append((event, fields))


class ExternalContextLiveWiringTests(unittest.TestCase):
    def test_hybrid_failure_projection_preserves_safe_typed_subcause(self) -> None:
        timeout = _typed_hybrid_conversation_failure(
            HybridGenerationError("external_generation_timeout", attempts=2)
        )
        self.assertIsInstance(timeout, ProviderError)
        self.assertEqual(timeout.code, "transport_failure")
        self.assertTrue(timeout.retryable)
        self.assertEqual(timeout.attempts, 2)

        unavailable = _typed_hybrid_conversation_failure(
            HybridGenerationError("external_provider_unavailable", attempts=2)
        )
        self.assertIsInstance(unavailable, ProviderError)
        self.assertEqual(unavailable.code, "upstream_server_error")

        authentication = _typed_hybrid_conversation_failure(
            HybridGenerationError(
                "external_provider_failure",
                provider_code="authentication_failed",
                retryable=False,
            )
        )
        self.assertIsInstance(authentication, ProviderError)
        self.assertEqual(authentication.code, "authentication_failed")
        self.assertFalse(authentication.retryable)

        repair = _typed_hybrid_conversation_failure(
            HybridGenerationError("external_reply_repair_exhausted")
        )
        self.assertIsInstance(repair, ConversationGuardError)

        policy = _typed_hybrid_conversation_failure(
            HybridGenerationError("external_profile_egress_rejected")
        )
        self.assertIsInstance(policy, ConversationError)
        self.assertIsInstance(policy, ConversationPreProviderError)
        self.assertNotIsInstance(policy, ConversationGuardError)

        profile = _typed_hybrid_conversation_failure(
            HybridGenerationError("profile_timeout", retryable=True)
        )
        self.assertIsInstance(profile, ConversationProfileError)

    def test_activation_gate_is_exact_and_defaults_off(self) -> None:
        self.assertFalse(hybrid_live_enabled({}))
        self.assertTrue(hybrid_live_enabled({"MYUNA_P07_HYBRID_EXTERNAL_ENABLED": "true"}))
        with self.assertRaises(ValueError):
            hybrid_live_enabled({"MYUNA_P07_HYBRID_EXTERNAL_ENABLED": "yes"})

    def test_adapter_pins_flash_and_bounded_non_thinking_request(self) -> None:
        provider = FakeProvider()
        adapter = _ExternalProviderAdapter(provider, request_id="synthetic-request")
        reply = adapter.generate(
            (
                {"role": "system", "content": "synthetic definition"},
                {"role": "user", "content": "synthetic current message"},
            ),
            timeout_seconds=60,
            repair_instruction=None,
        )
        self.assertEqual(reply, "synthetic reply")
        request = provider.requests[0]
        self.assertEqual(request.model, HYBRID_MODEL)
        self.assertEqual(request.route_reason, HYBRID_ROUTE_REASON)
        self.assertEqual(request.caller, HYBRID_CALLER)
        self.assertEqual(request.max_output_tokens, 768)
        self.assertEqual(request.thinking, "disabled")
        self.assertEqual(
            [item["content"] for item in request.messages],
            ["synthetic definition", "synthetic current message"],
        )

    def test_visual_adapter_uses_one_json_object_request(self) -> None:
        provider = FakeProvider()
        adapter = _ExternalProviderAdapter(provider, request_id="synthetic-request")
        adapter.generate_structured(
            (
                {
                    "role": "system",
                    "content": "Return exactly one JSON object for synthetic evidence.",
                },
                {"role": "user", "content": "synthetic current message"},
            ),
            timeout_seconds=60,
        )
        self.assertEqual(len(provider.requests), 1)
        request = provider.requests[0]
        self.assertEqual(request.response_format, "json_object")
        self.assertEqual(request.route_reason, VISUAL_ROUTE_REASON)
        self.assertEqual(request.caller, VISUAL_CALLER)
        self.assertEqual(request.request_id, "synthetic-request-p01b-1")

    def test_summary_adapter_uses_distinct_typed_route(self) -> None:
        provider = FakeProvider()
        adapter = _ExternalProviderAdapter(provider, request_id="synthetic-request")
        adapter.generate_summary(
            (
                {"role": "system", "content": "synthetic summary instruction"},
                {"role": "user", "content": "synthetic authorized turn"},
            ),
            timeout_seconds=60,
        )
        request = provider.requests[0]
        self.assertEqual(request.response_format, "text")
        self.assertEqual(request.route_reason, SUMMARY_ROUTE_REASON)
        self.assertEqual(request.caller, SUMMARY_CALLER)
        self.assertEqual(request.request_id, "synthetic-request-p07-summary-1")

    def test_diary_adapter_uses_one_bounded_json_object_request(self) -> None:
        provider = FakeProvider()
        adapter = _ExternalProviderAdapter(provider, request_id="synthetic-request")
        adapter.generate_diary(
            (
                {
                    "role": "system",
                    "content": "Return exactly one strict JSON object for the synthetic diary.",
                },
                {"role": "user", "content": "synthetic closed day"},
            ),
            timeout_seconds=60,
        )
        request = provider.requests[0]
        self.assertEqual(request.response_format, "json_object")
        self.assertEqual(request.route_reason, DIARY_ROUTE_REASON)
        self.assertEqual(request.caller, DIARY_CALLER)
        self.assertEqual(request.request_id, "synthetic-request-p07-diary-1")
        self.assertEqual(request.max_output_tokens, 4_000)

    def test_owner_day_diary_adapter_has_distinct_typed_route(self) -> None:
        provider = FakeProvider()
        adapter = _ExternalProviderAdapter(provider, request_id="synthetic-request")
        adapter.generate_owner_day_diary(
            (
                {
                    "role": "system",
                    "content": "Return exactly one JSON object for the synthetic owner-day diary.",
                },
                {"role": "user", "content": "synthetic owner-day turns"},
            ),
            timeout_seconds=60,
        )
        request = provider.requests[0]
        self.assertEqual(request.response_format, "json_object")
        self.assertEqual(request.route_reason, OWNER_DAY_DIARY_ROUTE_REASON)
        self.assertEqual(request.caller, OWNER_DAY_DIARY_CALLER)
        self.assertEqual(
            request.request_id,
            "synthetic-request-p07-owner-day-diary-v2-1",
        )
        self.assertEqual(request.max_output_tokens, 4_000)

    def test_hybrid_model_override_is_scoped_copy(self) -> None:
        source = {"MYUNA_DEEPSEEK_MODEL": "legacy-model", "UNCHANGED": "value"}
        scoped = _hybrid_provider_environ(source)
        self.assertEqual(scoped["MYUNA_DEEPSEEK_MODEL"], HYBRID_MODEL)
        self.assertEqual(scoped["UNCHANGED"], "value")
        self.assertEqual(source["MYUNA_DEEPSEEK_MODEL"], "legacy-model")

    def test_public_projection_reports_no_legacy_memory_use(self) -> None:
        response = FakeProvider().generate(None)
        payload = HybridPublicResult(
            request_id="synthetic-request",
            reply="synthetic reply",
            response=response,
            repaired=False,
        ).public_payload()
        self.assertEqual(payload["model"], HYBRID_MODEL)
        self.assertEqual(payload["synthetic_memory"]["used"], False)
        self.assertEqual(payload["owner_memory"]["used"], False)

    def test_public_projection_preserves_release_bound_provenance(self) -> None:
        response = FakeProvider().generate(None)
        provenance = ReleaseBoundTurnProvenance(
            "a" * 64,
            ExternalTurnProvenance(
                epoch_id="telegram-owner-private-external-d-reset-v1",
                epoch_revision=0,
                projection_digest="b" * 64,
                sources=("owner_current_message",),
                profile_revisions=(),
                summary_version=None,
                recent_turn_start=None,
                recent_turn_end=None,
            ),
        )
        payload = HybridPublicResult(
            request_id="synthetic-request",
            reply="synthetic reply",
            response=response,
            repaired=False,
            external_turn_provenance=provenance,
        ).public_payload()
        self.assertEqual(
            payload["external_turn_provenance"]["schema"],
            "myuna.external-turn-provenance.v2",
        )
        self.assertEqual(
            payload["external_turn_provenance"]["release_set_id"],
            "a" * 64,
        )

    def test_summary_endpoint_returns_release_bound_candidate(self) -> None:
        release_set = P07DReleaseSet.create(**sample_fields())
        turn = ExternalTurn.create(
            sequence=1,
            parent_digest=ZERO_DIGEST,
            user_message="synthetic user",
            assistant_reply="synthetic assistant",
        )
        job = ReleaseBoundSummaryJob.create(
            release_set_id=release_set.release_set_id,
            epoch_id="telegram-owner-private-external-d-reset-v1",
            base_revision=1,
            summary_version=1,
            covered_end=1,
            covered_terminal_digest=turn.digest,
            profile_revisions=(),
            prior_summary=None,
            turns=(turn,),
        )
        engine = LiveHybridConversationEngine.__new__(LiveHybridConversationEngine)
        engine.release_set = release_set
        engine.provider = FakeProvider()
        engine.audit = FakeAudit()
        result = engine.summarize_external(
            job.as_payload(),
            request_id="synthetic-summary-request",
        )
        result.candidate.validate_for(job)
        self.assertEqual(result.candidate.release_set_id, release_set.release_set_id)
        self.assertEqual(engine.audit.events[0][0], "external_rolling_summary")

    def test_diary_generation_requires_exact_memory_binding_and_is_audited(self) -> None:
        job = job_for_day()

        class DiaryProvider(FakeProvider):
            def generate(self, request):
                response = super().generate(request)
                return ModelResponse(
                    provider=response.provider,
                    model=response.model,
                    text=candidate_text(job),
                    input_tokens=response.input_tokens,
                    output_tokens=response.output_tokens,
                    cache_hit_tokens=response.cache_hit_tokens,
                    cache_miss_tokens=response.cache_miss_tokens,
                    reasoning_tokens=response.reasoning_tokens,
                    finish_reason=response.finish_reason,
                    cost_usd=response.cost_usd,
                    budget_accounted_usd=response.budget_accounted_usd,
                )

        engine = LiveHybridConversationEngine.__new__(LiveHybridConversationEngine)
        engine.release_set = type(
            "ReleaseSet",
            (),
            {"release_set_id": job.parent_release_set_id},
        )()
        engine.episodic_overlay_id = job.policy_overlay_id
        engine.episodic_memory_release_set_id = job.memory_release_set_id
        engine.reflective_diary_egress_binding_digest = job.egress_binding_digest
        engine.provider = DiaryProvider()
        engine.audit = FakeAudit()
        engine._reflective_diary_persona_context = lambda: PERSONA
        result = engine.generate_reflective_diary(
            job.as_payload(),
            request_id="synthetic-diary-request",
        )
        self.assertEqual(result.result.status, "completed")
        self.assertTrue(result.result.provider_called)
        self.assertEqual(engine.audit.events[0][0], "external_reflective_diary")
        self.assertNotIn("synthetic owner", str(engine.audit.events))

        engine.reflective_diary_egress_binding_digest = None
        with self.assertRaisesRegex(ConversationGuardError, "diary_release_binding_rejected"):
            engine.generate_reflective_diary(
                job.as_payload(),
                request_id="synthetic-diary-disabled",
            )

        engine.reflective_diary_egress_binding_digest = "e" * 64
        with self.assertRaisesRegex(ConversationGuardError, "diary_release_binding_rejected"):
            engine.generate_reflective_diary(
                job.as_payload(),
                request_id="synthetic-diary-binding-drifted",
            )

        engine.reflective_diary_egress_binding_digest = job.egress_binding_digest

        engine.episodic_memory_release_set_id = "f" * 64
        with self.assertRaisesRegex(ConversationGuardError, "diary_release_binding_rejected"):
            engine.generate_reflective_diary(
                job.as_payload(),
                request_id="synthetic-diary-rejected",
            )

    def test_owner_day_diary_generation_requires_purpose_specific_binding(self) -> None:
        persona = "Synthetic Myuna owner-day persona"
        first = make_turn(
            1,
            "0" * 64,
            owner="synthetic owner event",
            assistant="synthetic Myuna response",
            instant=datetime(2026, 8, 8, 1, tzinfo=timezone.utc),
        )
        job = build_owner_day_diary_job(
            turns=(first,),
            effective_bindings={1: first.draft.time_binding},
            owner_day=date(2026, 8, 8),
            policy=OwnerDayPolicy(),
            purpose=OWNER_DAY_PREVIEW_PURPOSE,
            generation_time_sample=TrustedTimeSample(
                instant=datetime(2026, 8, 8, 2, tzinfo=timezone.utc),
                source="myuna-trusted-local-v1",
                source_class="trusted_local",
                sequence=81,
                authority="systemd-timesyncd",
                uncertainty_microseconds=1_000,
                synchronized=True,
                boot_id="synthetic-owner-day-boot",
                monotonic_ns=81_000,
            ),
            target_revision=1,
            supersedes_revision=None,
            memory_release_set_id="1" * 64,
            parent_release_set_id="2" * 64,
            policy_overlay_id="3" * 64,
            archive_id="synthetic-owner-day-archive",
            persona_digest=semantic_digest(
                "myuna-p07-owner-day-diary-persona-context-v2",
                {"persona_context": persona},
            ),
        )

        class OwnerDayProvider(FakeProvider):
            def generate(self, request):
                response = super().generate(request)
                statement = {
                    "kind": "factual_observation",
                    "source_episode_digests": [],
                    "source_sequences": [1],
                    "source_turn_digests": [first.turn_digest],
                    "statement_id": "owner-day-statement-1",
                    "text": "Synthetic source-bound fact",
                }
                return ModelResponse(
                    provider=response.provider,
                    model=response.model,
                    text=json.dumps(
                        {
                            "job_digest": job.job_digest,
                            "schema": "myuna.p07-owner-day-diary-candidate.v2",
                            "statements": [statement],
                        }
                    ),
                    input_tokens=response.input_tokens,
                    output_tokens=response.output_tokens,
                    cache_hit_tokens=response.cache_hit_tokens,
                    cache_miss_tokens=response.cache_miss_tokens,
                    reasoning_tokens=response.reasoning_tokens,
                    finish_reason=response.finish_reason,
                    cost_usd=response.cost_usd,
                    budget_accounted_usd=response.budget_accounted_usd,
                )

        engine = LiveHybridConversationEngine.__new__(LiveHybridConversationEngine)
        engine.release_set = type(
            "ReleaseSet", (), {"release_set_id": job.parent_release_set_id}
        )()
        engine.episodic_overlay_id = job.policy_overlay_id
        engine.episodic_memory_release_set_id = job.memory_release_set_id
        engine.owner_day_diary_closed_egress_binding_digest = "4" * 64
        engine.owner_day_diary_preview_egress_binding_digest = job.egress_binding_digest
        engine.provider = OwnerDayProvider()
        engine.audit = FakeAudit()
        engine._reflective_diary_persona_context = lambda: persona
        result = engine.generate_owner_day_diary(
            job.as_payload(), request_id="synthetic-owner-day-request"
        )
        self.assertEqual(result.result.status, "completed")
        self.assertEqual(
            engine.audit.events[0][0], "external_owner_day_reflective_diary_v2"
        )
        engine.owner_day_diary_preview_egress_binding_digest = "5" * 64
        with self.assertRaisesRegex(
            ConversationGuardError, "owner_day_diary_release_binding_rejected"
        ):
            engine.generate_owner_day_diary(
                job.as_payload(), request_id="synthetic-owner-day-rejected"
            )


if __name__ == "__main__":
    unittest.main()
