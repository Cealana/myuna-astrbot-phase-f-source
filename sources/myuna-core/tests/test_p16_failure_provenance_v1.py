from __future__ import annotations

import json
import unittest

from myuna_core.degradation_bridge import CoreFailureCode
from myuna_core.degradation_http import (
    CORE_FAILURE_PROVENANCE_SCHEMA,
    CORE_FAILURE_RESPONSE_SCHEMA,
    CoreFailureProvenance,
    attach_core_failure_metadata,
    attach_provider_failure_metadata,
    output_repair_failure_provenance,
    pre_provider_failure_provenance,
    safe_pre_provider_failure_gate,
)


REQUEST_ID = "11111111-2222-4333-8444-555555555555"


class P16FailureProvenanceV1Tests(unittest.TestCase):
    def test_pre_provider_profile_provider_and_output_stages_are_distinct(self) -> None:
        cases = (
            (
                attach_core_failure_metadata(
                    {"error": "invalid_conversation_request"},
                    request_id=REQUEST_ID,
                    code=CoreFailureCode.CORE_REQUEST_REJECTED,
                    provenance=pre_provider_failure_provenance("request_parser"),
                ),
                "request_parser",
                "core_request_rejected",
                False,
                0,
            ),
            (
                attach_core_failure_metadata(
                    {"error": "profile_unavailable"},
                    request_id=REQUEST_ID,
                    code=CoreFailureCode.OWNER_MEMORY_READ_FAILED,
                    provenance=pre_provider_failure_provenance(
                        "profile_projection",
                        profile_called=True,
                        persona_grounding_class="not_evaluated",
                    ),
                ),
                "profile_projection",
                "owner_memory_read_failed",
                False,
                0,
            ),
            (
                attach_provider_failure_metadata(
                    {"error": "provider_unavailable", "retryable": True},
                    request_id=REQUEST_ID,
                    provider_code="transport_failure",
                    attempt_count=2,
                    persona_grounding_class="not_evaluated",
                ),
                "provider_request",
                "transport_failure",
                True,
                2,
            ),
            (
                attach_core_failure_metadata(
                    {"error": "reply_failed_runtime_guard"},
                    request_id=REQUEST_ID,
                    code=CoreFailureCode.REPLY_RUNTIME_GUARD_REJECTED,
                    provenance=output_repair_failure_provenance(
                        attempt_count=None,
                        persona_grounding_class="not_evaluated",
                    ),
                ),
                "output_repair",
                "reply_runtime_guard_rejected",
                True,
                None,
            ),
        )
        for payload, stage, failure_gate, provider_called, attempts in cases:
            with self.subTest(stage=stage):
                self.assertEqual(payload["failure_schema"], CORE_FAILURE_RESPONSE_SCHEMA)
                provenance = payload["failure_provenance"]
                self.assertEqual(provenance["schema"], CORE_FAILURE_PROVENANCE_SCHEMA)
                self.assertEqual(provenance["stage"], stage)
                self.assertEqual(provenance["failure_gate"], failure_gate)
                self.assertIs(provenance["provider_called"], provider_called)
                self.assertEqual(provenance["attempt_count"], attempts)

    def test_pre_provider_gate_is_allowlisted_and_unknown_values_do_not_leak(self) -> None:
        self.assertEqual(
            safe_pre_provider_failure_gate("projection_character_budget_exceeded"),
            "projection_character_budget_exceeded",
        )
        for value in (
            "unreviewed_future_gate",
            "private/path",
            "private value",
            "x" * 128,
            None,
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    safe_pre_provider_failure_gate(value),
                    "core_pre_provider_unknown",
                )

        payload = pre_provider_failure_provenance(
            "core_pre_provider",
            failure_gate=safe_pre_provider_failure_gate(
                "projection_character_budget_exceeded"
            ),
            profile_called=True,
            persona_grounding_class="not_evaluated",
        ).as_payload()
        self.assertEqual(payload["failure_gate"], "projection_character_budget_exceeded")
        self.assertNotIn("message", json.dumps(payload, sort_keys=True))

    def test_provenance_rejects_inconsistent_call_evidence(self) -> None:
        with self.assertRaises(ValueError):
            CoreFailureProvenance(
                stage="provider_request",
                provider_outcome_class="transport_failure",
                attempt_count=0,
                provider_called=True,
                model_called=True,
                profile_called=None,
                memory_called=None,
                tool_called=False,
                persona_grounding_class="unknown",
                output_guard_applied=False,
            )

    def test_provenance_is_content_free_and_fixed_field_only(self) -> None:
        payload = attach_provider_failure_metadata(
            {"error": "provider_unavailable", "retryable": True},
            request_id=REQUEST_ID,
            provider_code="local_timeout",
            attempt_count=2,
        )
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True)
        for forbidden in (
            REQUEST_ID,
            "message_text",
            "prompt",
            "provider_response",
            "profile_content",
            "database_row",
            "secret",
            "path",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_unknown_provider_or_invalid_attempt_count_degrades_to_unknown_evidence(self) -> None:
        unknown = attach_provider_failure_metadata(
            {"error": "provider_unavailable", "retryable": True},
            request_id=REQUEST_ID,
            provider_code="unfrozen_future_code",
            attempt_count=999,
        )
        self.assertEqual(
            unknown["safe_degradation"]["safe_detail_code"],
            "core-runtime-fail-closed",
        )
        self.assertEqual(unknown["failure_provenance"]["stage"], "core_runtime")
        self.assertIsNone(unknown["failure_provenance"]["attempt_count"])
        known = attach_provider_failure_metadata(
            {"error": "provider_unavailable", "retryable": True},
            request_id=REQUEST_ID,
            provider_code="transport_failure",
            attempt_count=999,
        )
        self.assertEqual(known["failure_provenance"]["stage"], "provider_request")
        self.assertIsNone(known["failure_provenance"]["attempt_count"])


if __name__ == "__main__":
    unittest.main()
