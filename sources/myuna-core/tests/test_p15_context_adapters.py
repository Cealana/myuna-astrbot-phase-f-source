from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from myuna_core.affinity import AffinityCapabilityContract, P15AffinityRelevancePort
from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.context_orchestration.adapters import (
    AffinityCapabilityBinding,
    GENERATION12_CORE_COMMIT,
    GENERATION12_DEPLOY_COMMIT,
    Generation12Binding,
    P09_CAPABILITY_DIGEST,
    P09_P15_PORT,
    P09_SOURCE_MAIN_COMMIT,
    P09_SOURCE_MAIN_TREE,
    adapt_affinity_projection,
    adapt_current_message,
    adapt_definition,
    adapt_external_context,
    adapt_profile,
    adapt_temporal,
    adapt_trusted_time,
    adapt_visual_observation,
)
from myuna_core.context_orchestration.contracts import P15ContractError
from myuna_core.definition import DefinitionRelease
from myuna_core.external_context.contracts import (
    EgressSafetySignals,
    ExternalContextEnvelope,
    ExternalTurn,
    VisualEvidence,
    ZERO_DIGEST,
)
from myuna_core.external_context.release_set import P07DReleaseSet
from myuna_core.owner_profile.contracts import (
    RetrievedProfileSection,
    RetrievalResult as ProfileRetrievalResult,
)
from myuna_core.active_temporal_context.contracts import (
    TemporalFact,
    TemporalRetrievalResult,
)
from myuna_core.trusted_time.contracts import (
    SynchronizationEvidence,
    TrustedTimeWatermark,
    UtcObservation,
)


NOW = datetime(2026, 8, 5, tzinfo=timezone.utc)


def authenticated_context() -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version="myuna.authenticated-conversation-context.v1",
        request_id="request-1",
        correlation_id="correlation-1",
        client_id="client-1",
        channel_kind="astrbot_telegram",
        binding_id="binding-1",
        principal_id="principal-1",
        namespace_id="namespace-1",
        authority_level="owner",
        channel_instance="telegram-owner",
        conversation_id="conversation-1",
        conversation_kind="private",
        event_id="event-1",
        trace_id="trace-1",
        occurred_at=NOW,
        delivery_capabilities=("text",),
    )


class P15AdapterTests(unittest.TestCase):
    def test_generation12_binding_accepts_only_exact_source_identity(self) -> None:
        release = object.__new__(P07DReleaseSet)
        object.__setattr__(release, "schema", "myuna.p07-d-release-set.v1")
        object.__setattr__(release, "generation", 12)
        object.__setattr__(release, "release_set_id", "e" * 64)
        object.__setattr__(
            release,
            "epoch",
            {
                "schema": "myuna.external-authorized-epoch.v3",
                "schema_version": 3,
                "epoch_id": "telegram-owner-private-external-d-reset-v6",
            },
        )
        combined = {
            "schema": "myuna.p08-p07-combined-release-set.v1",
            "p07": {
                "core_release_digest": "1" * 64,
                "credential_projection_digest": "2" * 64,
                "epoch_id": "telegram-owner-private-external-d-reset-v6",
                "epoch_path": "/synthetic/epoch.db",
                "generation": 12,
                "release_set_id": "e" * 64,
                "runtime_config_digest": "3" * 64,
                "runtime_release_digest": "4" * 64,
                "selector_digest": "5" * 64,
            },
            "p08": {},
            "release_set_id": "6" * 64,
            "rollback": {},
            "telegram_plugin": {},
        }
        binding = Generation12Binding.validate(
            release,
            combined,
            core_commit=GENERATION12_CORE_COMMIT,
            deploy_commit=GENERATION12_DEPLOY_COMMIT,
        )
        self.assertEqual(binding.generation, 12)
        self.assertEqual(binding.epoch_id, "telegram-owner-private-external-d-reset-v6")
        with self.assertRaisesRegex(P15ContractError, "generation12_source_identity_mismatch"):
            Generation12Binding.validate(
                release,
                combined,
                core_commit="0" * 40,
                deploy_commit=GENERATION12_DEPLOY_COMMIT,
            )

    def test_p09_binding_is_path_independent_and_projection_stays_inactive(self) -> None:
        contract = AffinityCapabilityContract.phase_b_foundation()
        binding = AffinityCapabilityBinding.validate(
            contract,
            source_main_commit=P09_SOURCE_MAIN_COMMIT,
            source_main_tree=P09_SOURCE_MAIN_TREE,
        )
        self.assertEqual(binding.capability_digest, P09_CAPABILITY_DIGEST)
        self.assertIs(P09_P15_PORT, P15AffinityRelevancePort)
        self.assertFalse(binding.prompt_projection_active)
        with self.assertRaisesRegex(P15ContractError, "p09_prompt_projection_unavailable"):
            adapt_affinity_projection(
                binding,
                ("style",),
                revision=1,
                source_ref="affinity:1",
                relevance=50,
            )
        with self.assertRaisesRegex(P15ContractError, "p09_source_main_identity_mismatch"):
            AffinityCapabilityBinding.validate(
                contract,
                source_main_commit="0" * 40,
                source_main_tree=P09_SOURCE_MAIN_TREE,
            )

    def test_definition_current_and_profile_stay_separate(self) -> None:
        release = DefinitionRelease(
            Path("/definition"),
            Path("/definition/current"),
            "definition-v1",
            "v1",
            "build-1",
            "A" * 64,
            ("test",),
            1,
        )
        definition = adapt_definition(release, "policy bytes")
        current = adapt_current_message(authenticated_context(), "owner bytes")
        profile = adapt_profile(
            ProfileRetrievalResult(
                "available",
                7,
                "b" * 64,
                5,
                (
                    RetrievedProfileSection(
                        1,
                        "long_term_preference",
                        "title",
                        "profile bytes",
                        "profile:1",
                    ),
                ),
                "unused aggregate",
            )
        )
        self.assertEqual(definition.candidate.content_fragments, ("policy bytes",))
        self.assertEqual(current.candidate.content_fragments, ("owner bytes",))
        self.assertEqual(profile[0].candidate.content_fragments, ("profile bytes",))
        self.assertEqual(profile[0].candidate.provenance.source_revision, 7)

    def test_temporal_and_trusted_time_bind_expiry_without_rewriting(self) -> None:
        fact = TemporalFact(
            "fact-1",
            2,
            "deadline",
            "deadline-1",
            "temporary bytes",
            "owner_statement",
            "telegram",
            "event:1",
            NOW,
            NOW,
            None,
            NOW + timedelta(days=1),
            "active",
            None,
        )
        temporal = adapt_temporal(TemporalRetrievalResult("available", 4, (fact,), None))
        self.assertEqual(temporal[0].candidate.content_fragments, ("temporary bytes",))
        self.assertEqual(temporal[0].expires_at, NOW + timedelta(days=1))

        observation = UtcObservation(
            NOW,
            1,
            "boot-1",
            SynchronizationEvidence(True, timedelta(milliseconds=1), "kernel"),
        )
        watermark = TrustedTimeWatermark("trusted-local", 3, NOW)
        available = adapt_trusted_time(observation, watermark)
        self.assertEqual(available.status, "available")
        unsynchronized = UtcObservation(
            NOW,
            1,
            "boot-1",
            SynchronizationEvidence(False, timedelta(0), "kernel"),
        )
        self.assertEqual(adapt_trusted_time(unsynchronized, watermark).status, "unavailable")

    def test_external_turn_fragments_are_not_flattened_and_reset_is_normal(self) -> None:
        turn = ExternalTurn.create(
            sequence=1,
            parent_digest=ZERO_DIGEST,
            user_message="user bytes",
            assistant_reply="assistant bytes",
        )
        envelope = ExternalContextEnvelope(
            "telegram-owner-private-external-d-reset-v6",
            1,
            1,
            turn.digest,
            "astrbot_telegram",
            "principal-1",
            "namespace-1",
            "current",
            "c" * 64,
            None,
            (turn,),
            EgressSafetySignals(),
        )
        binding = Generation12Binding(
            GENERATION12_CORE_COMMIT,
            GENERATION12_DEPLOY_COMMIT,
            "myuna.p07-d-release-set.v1",
            "myuna.p08-p07-combined-release-set.v1",
            12,
            "myuna.external-authorized-epoch.v3",
            3,
            "telegram-owner-private-external-d-reset-v6",
        )
        adapted = adapt_external_context(envelope, binding, continuity_reset=True)
        self.assertEqual(
            adapted.recent_turns[0].candidate.content_fragments,
            ("user bytes", "assistant bytes"),
        )
        self.assertTrue(adapted.continuity_reset)
        self.assertEqual(adapted.reset_reason, "authorized_generation_transition")

    def test_visual_evidence_remains_untrusted_observation_lane(self) -> None:
        evidence = VisualEvidence("observed bytes", False, "d" * 64)
        lane = adapt_visual_observation(
            evidence,
            confidence=0.8,
            relevance=70,
            essential_for_current=False,
        )
        self.assertEqual(lane.candidate.source_kind, "visual_observation")
        self.assertEqual(lane.candidate.semantic_domain, "visual_evidence")
        self.assertEqual(lane.candidate.content_fragments, ("observed bytes",))


if __name__ == "__main__":
    unittest.main()
