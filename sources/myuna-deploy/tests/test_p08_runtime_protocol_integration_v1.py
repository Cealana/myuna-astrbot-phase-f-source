from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "p08-runtime-protocol-integration-v1.md"
GATES = ROOT / "docs" / "p08-active-temporal-context-integration-gates-v1.md"


class P08RuntimeProtocolIntegrationContractTests(unittest.TestCase):
    def test_contract_freezes_auth_time_and_cross_layer_boundaries(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        flat = " ".join(text.split())
        for required in (
            "myuna.active-temporal-context-protocol.v1",
            "authenticated_telegram_owner_private_temporal_context",
            "exactly one P10-B `TrustedTimePort` sample",
            "authorization happens before trusted-time sampling",
            "memory_candidate",
            "QQ remains excluded",
            "separate T2 authority",
        ):
            self.assertIn(required, flat)

    def test_contract_does_not_claim_install_or_live_readiness(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        flat = " ".join(text.split())
        self.assertIn("source-only T1 candidate", text)
        self.assertIn("does not yet select a host synchronization probe", text)
        self.assertIn("must not be reported as Gate C live readiness", flat)

    def test_existing_gate_points_to_the_adapter_without_widening_gate_c(self) -> None:
        text = GATES.read_text(encoding="utf-8")
        flat = " ".join(text.split())
        self.assertIn("p08-runtime-protocol-integration-v1.md", text)
        self.assertIn("not evidence that Gate C has passed", flat)
        self.assertIn("Real Owner content", text)


if __name__ == "__main__":
    unittest.main()
