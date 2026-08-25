from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
ADR = ROOT / "docs" / "ADR-059-active-temporal-context-v1.md"
THREAT = ROOT / "docs" / "p08-active-temporal-context-privacy-threat-model-v1.md"
GATES = ROOT / "docs" / "p08-active-temporal-context-integration-gates-v1.md"


class P08FoundationContractTest(unittest.TestCase):
    def test_documents_define_source_only_separation_and_time_gate(self) -> None:
        combined = "\n".join(
            path.read_text(encoding="utf-8") for path in (ADR, THREAT, GATES)
        )
        for required in (
            "myuna.active-temporal-context.v1",
            "active_temporal_context_v1",
            "P07",
            "128-message",
            "P10-B",
            "P15",
            "TrustedTimePort",
            "Telegram",
            "QQ has no writer scope",
            "synthetic",
            "no real Owner content",
        ):
            self.assertIn(required, combined)

    def test_fail_closed_matrix_is_named(self) -> None:
        combined = "\n".join(
            path.read_text(encoding="utf-8") for path in (ADR, THREAT, GATES)
        ).casefold()
        for required in (
            "unknown schema",
            "corrupt",
            "oversize",
            "permission/type drift",
            "time regression",
            "duplicate/conflict",
            "expired/stale",
            "crash/partial commit",
        ):
            self.assertIn(required, combined)

    def test_t2_and_t3_remain_explicitly_deferred(self) -> None:
        gates = GATES.read_text(encoding="utf-8")
        self.assertIn("wait for Owner approval", gates)
        self.assertIn("T2", gates)
        self.assertIn("T3", (ADR.read_text(encoding="utf-8") + gates))
        self.assertNotIn("Standard Work Authority v1 持续执行", gates)


if __name__ == "__main__":
    unittest.main()
