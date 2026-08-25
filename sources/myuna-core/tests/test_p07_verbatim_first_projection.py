from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as AUTH_SCHEMA,
    AuthenticatedConversationContext,
)
from myuna_core.external_context import (
    EXTERNAL_PROJECTION_POLICY,
    EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
    EgressSafetySignals,
    ExternalContextEnvelope,
    ExternalContextError,
    ExternalProjectionBuilder,
    ExternalSummary,
    ExternalTurn,
    ProjectionBudget,
    current_message_digest,
)
from myuna_core.external_context.contracts import (
    MAX_VERBATIM_RECENT_CHARACTERS,
    ZERO_DIGEST,
)
from myuna_core.external_context.live import HYBRID_PROJECTION_MAX_CHARACTERS


def context() -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=AUTH_SCHEMA,
        request_id="request-verbatim-synthetic",
        correlation_id="correlation-verbatim-synthetic",
        client_id="telegram-owner-private",
        channel_kind="astrbot_telegram",
        binding_id="binding-verbatim-synthetic",
        principal_id="principal-verbatim-synthetic",
        namespace_id="namespace-verbatim-synthetic",
        authority_level="owner",
        channel_instance="telegram-synthetic",
        conversation_id="conversation-verbatim-synthetic",
        conversation_kind="private",
        event_id="event-verbatim-synthetic",
        trace_id="trace-verbatim-synthetic",
        occurred_at=datetime(2026, 8, 7, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
    )


def turns(count: int = 64) -> tuple[ExternalTurn, ...]:
    parent = ZERO_DIGEST
    result = []
    for sequence in range(1, count + 1):
        turn = ExternalTurn.create(
            sequence=sequence,
            parent_digest=parent,
            user_message=f"synthetic user {sequence:02d} " + "u" * 24,
            assistant_reply=f"synthetic assistant {sequence:02d} " + "a" * 24,
        )
        result.append(turn)
        parent = turn.digest
    return tuple(result)


def envelope(
    history: tuple[ExternalTurn, ...],
    *,
    summary: ExternalSummary | None = None,
    policy: str = EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
) -> ExternalContextEnvelope:
    auth = context()
    message = "synthetic current owner message"
    return ExternalContextEnvelope(
        epoch_id="epoch-verbatim-synthetic",
        epoch_revision=len(history),
        turn_sequence=len(history),
        parent_digest=ZERO_DIGEST if not history else history[-1].digest,
        channel_kind=auth.channel_kind,
        principal_id=auth.principal_id,
        namespace_id=auth.namespace_id,
        current_message=message,
        current_message_digest=current_message_digest(auth, message),
        summary=summary,
        recent_turns=history,
        safety=EgressSafetySignals(classifier_available=True),
        projection_policy_version=policy,
    )


def builder(maximum: int) -> ExternalProjectionBuilder:
    return ExternalProjectionBuilder(
        ProjectionBudget(
            max_total_characters=maximum,
            max_serialized_bytes=maximum * 6 + 4096,
            max_input_tokens=maximum * 6 + 4096,
        ),
        token_counter=lambda messages: max(
            1,
            len(
                str([(item["role"], item["content"]) for item in messages]).encode(
                    "utf-8"
                )
            ),
        ),
    )


def approved_definition() -> tuple[str, str]:
    value = "Synthetic approved Definition for verbatim-first projection tests."
    return value, sha256(value.encode("utf-8")).hexdigest()


class P07VerbatimFirstProjectionTests(unittest.TestCase):
    def test_verbatim_character_ceiling_matches_reviewed_projection_oracle(self) -> None:
        self.assertEqual(
            MAX_VERBATIM_RECENT_CHARACTERS,
            HYBRID_PROJECTION_MAX_CHARACTERS,
        )

    def test_sixty_four_complete_turns_are_projected_verbatim_without_summary(self) -> None:
        history = turns()
        fallback = ExternalSummary.create(
            summary_version=1,
            covered_start=1,
            covered_end=60,
            covered_terminal_digest=history[59].digest,
            profile_revisions=(),
            content="synthetic overflow fallback summary",
        )
        definition, digest = approved_definition()
        result = builder(20_000).build(
            definition=definition,
            definition_digest=digest,
            envelope=envelope(history, summary=fallback),
            profile=None,
        )

        self.assertEqual(result.recent_turn_count, 64)
        self.assertEqual(result.recent_turn_start, 1)
        self.assertEqual(result.recent_turn_end, 64)
        self.assertIsNone(result.summary_version)
        self.assertNotIn("profile_derived_summary", result.component_order)
        self.assertEqual(
            result.projection_policy_version,
            EXTERNAL_VERBATIM_FIRST_PROJECTION_POLICY,
        )

    def test_actual_projection_overflow_uses_bounded_summary_and_tail(self) -> None:
        history = turns()
        fallback = ExternalSummary.create(
            summary_version=1,
            covered_start=1,
            covered_end=60,
            covered_terminal_digest=history[59].digest,
            profile_revisions=(),
            content="synthetic overflow fallback summary",
        )
        definition, digest = approved_definition()
        result = builder(900).build(
            definition=definition,
            definition_digest=digest,
            envelope=envelope(history, summary=fallback),
            profile=None,
        )

        self.assertEqual(result.summary_version, 1)
        self.assertEqual(result.recent_turn_count, 4)
        self.assertEqual(result.recent_turn_start, 61)
        self.assertEqual(result.recent_turn_end, 64)
        self.assertIn("profile_derived_summary", result.component_order)
        provenance = result.turn_provenance(envelope(history, summary=fallback))
        self.assertEqual(provenance.recent_turn_start, 61)
        self.assertEqual(provenance.recent_turn_end, 64)

    def test_overflow_without_summary_fails_closed_before_provider(self) -> None:
        definition, digest = approved_definition()
        with self.assertRaises(ExternalContextError) as caught:
            builder(900).build(
                definition=definition,
                definition_digest=digest,
                envelope=envelope(turns()),
                profile=None,
            )
        self.assertEqual(
            caught.exception.code,
            "verbatim_projection_overflow_without_summary",
        )

    def test_serialized_byte_overflow_falls_back_before_provider(self) -> None:
        history = turns()
        fallback = ExternalSummary.create(
            summary_version=1,
            covered_start=1,
            covered_end=60,
            covered_terminal_digest=history[59].digest,
            profile_revisions=(),
            content="synthetic byte fallback summary",
        )
        definition, digest = approved_definition()
        selected = ExternalProjectionBuilder(
            ProjectionBudget(
                max_total_characters=20_000,
                max_serialized_bytes=1_200,
                max_input_tokens=20_000,
            ),
            token_counter=lambda messages: 1,
        ).build(
            definition=definition,
            definition_digest=digest,
            envelope=envelope(history, summary=fallback),
            profile=None,
        )
        self.assertEqual(selected.summary_version, 1)
        self.assertEqual(selected.recent_turn_count, 4)

    def test_token_overflow_falls_back_before_provider(self) -> None:
        history = turns()
        fallback = ExternalSummary.create(
            summary_version=1,
            covered_start=1,
            covered_end=60,
            covered_terminal_digest=history[59].digest,
            profile_revisions=(),
            content="synthetic token fallback summary",
        )
        definition, digest = approved_definition()
        selected = ExternalProjectionBuilder(
            ProjectionBudget(
                max_total_characters=20_000,
                max_serialized_bytes=200_000,
                max_input_tokens=100,
            ),
            token_counter=lambda messages: 10_000 if len(messages) > 10 else 10,
        ).build(
            definition=definition,
            definition_digest=digest,
            envelope=envelope(history, summary=fallback),
            profile=None,
        )
        self.assertEqual(selected.summary_version, 1)
        self.assertEqual(selected.input_tokens, 10)

    def test_fallback_summary_must_bind_to_verbatim_chain(self) -> None:
        history = turns()
        fallback = ExternalSummary.create(
            summary_version=1,
            covered_start=1,
            covered_end=60,
            covered_terminal_digest="f" * 64,
            profile_revisions=(),
            content="synthetic mismatched fallback summary",
        )
        with self.assertRaises(ExternalContextError) as caught:
            envelope(history, summary=fallback)
        self.assertEqual(
            caught.exception.code,
            "verbatim_summary_chain_mismatch",
        )

    def test_verbatim_contract_is_bounded_at_sixty_four_turns(self) -> None:
        with self.assertRaises(ExternalContextError) as caught:
            envelope(turns(65))
        self.assertEqual(caught.exception.code, "recent_turn_count_exceeded")

    def test_compressed_rollback_policy_keeps_six_turn_limit(self) -> None:
        with self.assertRaises(ExternalContextError) as caught:
            envelope(turns(7), policy=EXTERNAL_PROJECTION_POLICY)
        self.assertEqual(caught.exception.code, "recent_turn_count_exceeded")


if __name__ == "__main__":
    unittest.main()
