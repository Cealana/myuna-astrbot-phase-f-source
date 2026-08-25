from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

from myuna_core.degradation_bridge import CoreFailureCode
from myuna_core.user_visible_fault import (
    CODEBOOK_VERSION,
    PUBLIC_FAULT_SCHEMA,
    PUBLIC_FAULTS,
    public_fault_for_core_failure,
    public_fault_for_safe_detail,
    public_fault_for_typed_input,
)


ROOT = Path(__file__).resolve().parents[1]


class UserVisibleFaultV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.golden = json.loads(
            (ROOT / "fixtures/user_visible_fault_v1_golden.json").read_text(
                encoding="utf-8"
            )
        )

    def test_schema_and_full_codebook_match_frozen_golden(self) -> None:
        self.assertEqual(PUBLIC_FAULT_SCHEMA, self.golden["schema"])
        self.assertEqual(CODEBOOK_VERSION, self.golden["codebook_version"])
        actual = [PUBLIC_FAULTS[code].as_codebook_row() for code in PUBLIC_FAULTS]
        self.assertEqual(actual, self.golden["cases"])
        codes = [row["code"] for row in actual]
        self.assertEqual(len(codes), len(set(codes)))
        for code in codes:
            self.assertRegex(code, self.golden["code_grammar"])

    def test_every_existing_core_failure_has_an_explicit_public_mapping(self) -> None:
        mapped = {code: public_fault_for_core_failure(code) for code in CoreFailureCode}
        self.assertEqual(set(mapped), set(CoreFailureCode))
        self.assertNotIn("MYU-UNKNOWN-01", {item.code for item in mapped.values()})
        self.assertEqual(
            mapped[CoreFailureCode.LOCAL_PROVIDER_TIMEOUT].code,
            "MYU-LOCAL-01",
        )
        self.assertEqual(
            mapped[CoreFailureCode.PROVIDER_DAILY_BUDGET_EXCEEDED].code,
            "MYU-BUDGET-01",
        )
        self.assertEqual(
            mapped[CoreFailureCode.OWNER_MEMORY_READ_FAILED].code,
            "MYU-PROFILE-01",
        )

    def test_safe_detail_mapping_is_allowlisted_and_unknown_never_echoes_input(self) -> None:
        known = public_fault_for_safe_detail("local-model-not-ready")
        self.assertEqual(known.code, "MYU-LOCAL-03")
        marker = "raw-provider-message-synthetic"
        unknown = public_fault_for_safe_detail(marker)
        self.assertEqual(unknown.code, "MYU-UNKNOWN-01")
        self.assertNotIn(marker, json.dumps(unknown.as_payload(), ensure_ascii=False))

    def test_p08_and_p10b_typed_inputs_are_bounded_allowlists(self) -> None:
        self.assertEqual(
            public_fault_for_typed_input("trusted_time", "trusted_time_timeout").code,
            "MYU-TIME-01",
        )
        self.assertEqual(
            public_fault_for_typed_input(
                "trusted_time", "trusted_time_state_corrupt"
            ).code,
            "MYU-TIME-02",
        )
        self.assertEqual(
            public_fault_for_typed_input(
                "active_temporal_context", "database_unavailable"
            ).code,
            "MYU-TEMPORAL-01",
        )
        unknown = public_fault_for_typed_input(
            "active_temporal_context", "free-form-detail"
        )
        self.assertEqual(unknown.code, "MYU-UNKNOWN-01")

    def test_public_payload_is_exact_and_contains_no_internal_identifiers(self) -> None:
        payload = public_fault_for_core_failure(
            CoreFailureCode.PROVIDER_TRANSPORT_FAILURE
        ).as_payload()
        self.assertEqual(
            set(payload),
            {
                "schema",
                "codebook_version",
                "code",
                "domain",
                "category_zh",
                "retryable",
                "recovery_class",
                "recovery_gate",
            },
        )
        encoded = json.dumps(payload, ensure_ascii=False)
        for forbidden in (
            "raw_exception",
            "path",
            "secret",
            "amount",
            "reservation",
            "ledger",
            "payload",
            "message",
            "profile",
            "database",
            "fingerprint",
        ):
            self.assertNotIn(forbidden, encoded.casefold())

    def test_category_and_domain_are_bounded_public_values(self) -> None:
        for descriptor in PUBLIC_FAULTS.values():
            self.assertTrue(2 <= len(descriptor.category_zh) <= 16)
            self.assertRegex(descriptor.domain, r"^[a-z]+$")
            self.assertTrue(re.fullmatch(r"^MYU-[A-Z]+-[0-9]{2}$", descriptor.code))

    def test_new_public_projection_is_not_wired_into_legacy_core_paths(self) -> None:
        for relative in (
            "src/myuna_core/http_api.py",
            "src/myuna_core/degradation_bridge.py",
            "src/myuna_core/degradation_protocol.py",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("user_visible_fault", source, relative)


if __name__ == "__main__":
    unittest.main()
