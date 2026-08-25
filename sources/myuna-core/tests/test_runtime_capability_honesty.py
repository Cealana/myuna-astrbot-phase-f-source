from __future__ import annotations

import json
from pathlib import Path
import unittest

from myuna_core.runtime_capability_honesty import (
    CAPABILITY_HONESTY_VIOLATION_CODES,
    capability_honesty_fallback,
    capability_honesty_repair_guidance,
    capability_honesty_violations,
)


ROOT = Path(__file__).resolve().parents[1]


class FakeManifest:
    def __init__(self, enabled: set[str] | None = None) -> None:
        self.enabled = enabled or {"conversation", "long_term_memory_read", "qq_channel"}

    def capability_enabled(self, name: str) -> bool:
        return name in self.enabled


class RuntimeCapabilityHonestyTests(unittest.TestCase):
    def test_golden_matrix(self) -> None:
        document = json.loads(
            (ROOT / "fixtures/runtime_capability_honesty_v1_golden.json").read_text(
                encoding="utf-8"
            )
        )
        manifest = FakeManifest()
        for case in document["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    capability_honesty_violations(case["reply"], manifest),
                    case["expected"],
                )

    def test_enabled_capability_disables_its_rule(self) -> None:
        manifest = FakeManifest({"conversation", "vision"})
        self.assertEqual(
            capability_honesty_violations("截图发过来我可以帮你一起看", manifest),
            [],
        )

    def test_all_deterministic_fallbacks_pass_the_same_guard(self) -> None:
        manifest = FakeManifest()
        for code in sorted(CAPABILITY_HONESTY_VIOLATION_CODES):
            with self.subTest(code=code):
                fallback = capability_honesty_fallback([code])
                self.assertEqual(capability_honesty_violations(fallback, manifest), [])

    def test_repair_guidance_is_category_specific_and_content_free(self) -> None:
        value = capability_honesty_repair_guidance(
            ["scheduled_notification_claim", "vision_claim"]
        )
        self.assertIn("scheduler", value)
        self.assertIn("image input", value)
        self.assertNotIn("明晚", value)
        self.assertNotIn("截图发过来", value)


if __name__ == "__main__":
    unittest.main()
