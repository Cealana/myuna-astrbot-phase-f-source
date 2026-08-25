from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
ADR = ROOT / "docs" / "ADR-060-trusted-time-provider-v1.md"
MATRIX = ROOT / "docs" / "p10b-trusted-time-acceptance-matrix-v1.md"


class P10BTrustedTimeContractTests(unittest.TestCase):
    def test_contract_fixes_required_time_and_durability_semantics(self) -> None:
        text = ADR.read_text(encoding="utf-8")
        for required in (
            "SystemUtcObservationSource",
            "DurableTrustedTimeProvider",
            "TrustedTimeCapability",
            "timezone-aware",
            "one second",
            "two seconds",
            "BEGIN IMMEDIATE",
            "synchronous=FULL",
            "persistence_ambiguous",
            "consumer-watermark",
            "no implicit dual write",
            "content-free audit",
        ):
            self.assertIn(required.casefold(), text.casefold())

    def test_matrix_names_every_fail_closed_boundary(self) -> None:
        text = MATRIX.read_text(encoding="utf-8").casefold()
        for required in (
            "utc",
            "naive",
            "unsynchronized",
            "uncertainty",
            "restart",
            "regression",
            "drift",
            "source_drift",
            "concurrent",
            "before commit",
            "persistence_ambiguous",
            "timeout",
            "corrupt",
            "symlink",
            "audit",
            "lifecycle",
            "p08",
        ):
            self.assertIn(required, text)

    def test_layering_and_t2_boundary_remain_explicit(self) -> None:
        combined = ADR.read_text(encoding="utf-8") + MATRIX.read_text(encoding="utf-8")
        folded = combined.casefold()
        for required in (
            "P07 stable Profile",
            "P08 owns",
            "128-message session",
            "P15",
            "P10-A",
            "no real Owner content",
            "independent T2 authorization",
            "no live scheduler",
        ):
            self.assertIn(required.casefold(), folded)
        self.assertNotIn("Standard Work Authority v1 active", combined)


if __name__ == "__main__":
    unittest.main()
