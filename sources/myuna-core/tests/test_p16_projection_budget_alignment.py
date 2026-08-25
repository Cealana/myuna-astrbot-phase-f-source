from __future__ import annotations

from hashlib import sha256
import unittest

from myuna_core.external_context.contracts import (
    EgressSafetySignals,
    ExternalContextError,
)
from myuna_core.external_context.live import (
    HYBRID_MAX_OUTPUT_TOKENS,
    HYBRID_MODEL,
    HYBRID_PROJECTION_MAX_CHARACTERS,
    HYBRID_PROVIDER_MAX_INPUT_CHARACTERS,
    HYBRID_REPAIR_HEADROOM_CHARACTERS,
    _ExternalProviderAdapter,
    _token_upper_bound,
    hybrid_projection_budget,
)
from myuna_core.external_context.projection import (
    ExternalProjectionBuilder,
    ProjectionBudget,
)
from myuna_core.external_context.runtime import _REPAIR_INSTRUCTION
from myuna_core.providers.registry import get_model_spec
from tests.test_external_context_hybrid import empty_envelope
from tests.test_external_context_live_wiring import FakeProvider


class P16ProjectionBudgetAlignmentTests(unittest.TestCase):
    def test_runtime_budget_matches_provider_and_registry_contracts(self) -> None:
        budget = hybrid_projection_budget()
        spec = get_model_spec(HYBRID_MODEL)
        self.assertEqual(HYBRID_PROVIDER_MAX_INPUT_CHARACTERS, 200_000)
        self.assertEqual(
            HYBRID_PROJECTION_MAX_CHARACTERS,
            HYBRID_PROVIDER_MAX_INPUT_CHARACTERS
            - HYBRID_REPAIR_HEADROOM_CHARACTERS,
        )
        self.assertGreaterEqual(
            HYBRID_REPAIR_HEADROOM_CHARACTERS,
            len(_REPAIR_INSTRUCTION),
        )
        self.assertEqual(
            budget.max_total_characters,
            HYBRID_PROJECTION_MAX_CHARACTERS,
        )
        self.assertGreaterEqual(
            budget.max_serialized_bytes,
            6 * HYBRID_PROJECTION_MAX_CHARACTERS,
        )
        self.assertEqual(
            budget.max_input_tokens,
            spec.context_tokens - HYBRID_MAX_OUTPUT_TOKENS,
        )

    def test_regression_over_legacy_80k_proceeds_offline(self) -> None:
        definition = "D" * 80_100
        legacy_builder = ExternalProjectionBuilder(
            ProjectionBudget(
                max_total_characters=80_000,
                max_serialized_bytes=240_000,
                max_input_tokens=80_000,
            ),
            token_counter=_token_upper_bound,
        )
        with self.assertRaises(ExternalContextError) as caught:
            legacy_builder.build(
                definition=definition,
                definition_digest=sha256(definition.encode("utf-8")).hexdigest(),
                envelope=empty_envelope(message="synthetic relational ordinary turn"),
                profile=None,
            )
        self.assertEqual(caught.exception.code, "projection_character_budget_exceeded")
        builder = ExternalProjectionBuilder(
            hybrid_projection_budget(),
            token_counter=_token_upper_bound,
        )
        projection = builder.build(
            definition=definition,
            definition_digest=sha256(definition.encode("utf-8")).hexdigest(),
            envelope=empty_envelope(message="synthetic relational ordinary turn"),
            profile=None,
        )
        self.assertGreater(projection.character_count, 80_000)
        self.assertLessEqual(
            projection.character_count,
            HYBRID_PROJECTION_MAX_CHARACTERS,
        )

    def test_unicode_budget_and_exact_hard_ceiling_remain_fail_closed(self) -> None:
        builder = ExternalProjectionBuilder(
            hybrid_projection_budget(),
            token_counter=_token_upper_bound,
        )
        unicode_definition = "界" * 90_000
        projection = builder.build(
            definition=unicode_definition,
            definition_digest=sha256(unicode_definition.encode("utf-8")).hexdigest(),
            envelope=empty_envelope(message="synthetic ordinary turn"),
            profile=None,
        )
        self.assertGreater(projection.serialized_bytes, projection.character_count)
        oversized_definition = "D" * HYBRID_PROJECTION_MAX_CHARACTERS
        with self.assertRaisesRegex(Exception, "projection_character_budget_exceeded"):
            builder.build(
                definition=oversized_definition,
                definition_digest=sha256(
                    oversized_definition.encode("utf-8")
                ).hexdigest(),
                envelope=empty_envelope(message="synthetic ordinary turn"),
                profile=None,
            )

    def test_adapter_uses_the_same_provider_character_ceiling(self) -> None:
        provider = FakeProvider()
        adapter = _ExternalProviderAdapter(provider, request_id="synthetic-request")
        adapter.generate(
            (
                {"role": "system", "content": "synthetic definition"},
                {"role": "user", "content": "synthetic ordinary turn"},
            ),
            timeout_seconds=60,
            repair_instruction=None,
        )
        self.assertEqual(
            provider.requests[0].max_input_characters,
            HYBRID_PROVIDER_MAX_INPUT_CHARACTERS,
        )

    def test_privacy_and_profile_limits_are_not_part_of_this_change(self) -> None:
        envelope = empty_envelope(
            message="synthetic ordinary turn",
            safety=EgressSafetySignals(
                classifier_available=True,
                third_party_private=True,
            ),
        )
        builder = ExternalProjectionBuilder(
            hybrid_projection_budget(),
            token_counter=_token_upper_bound,
        )
        with self.assertRaisesRegex(Exception, "third_party_private_content_excluded"):
            builder.build(
                definition="Synthetic Definition",
                definition_digest=sha256(b"Synthetic Definition").hexdigest(),
                envelope=envelope,
                profile=None,
            )


if __name__ == "__main__":
    unittest.main()
