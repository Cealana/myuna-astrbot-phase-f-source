from __future__ import annotations

from pathlib import Path
import unittest

from myuna_core.authenticated_media_delivery import AuthenticatedMediaDeliveryPolicy


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "vision" / "authenticated-media-delivery-policy-v1.json"
ADR = ROOT / "docs" / "ADR-044-authenticated-media-delivery-and-fake-staging-v1.md"


class AuthenticatedMediaDeliveryRepositoryTests(unittest.TestCase):
    def test_policy_is_owner_private_vision_and_inactive(self) -> None:
        policy = AuthenticatedMediaDeliveryPolicy.load(POLICY)
        self.assertEqual(policy.status, "inactive_candidate")
        self.assertEqual(policy.required_capability, "vision")
        self.assertEqual(policy.allowed_authority_levels, frozenset({"owner"}))
        self.assertEqual(policy.allowed_conversation_kinds, frozenset({"private"}))

    def test_adr_preserves_identity_and_runtime_boundaries(self) -> None:
        text = ADR.read_text(encoding="utf-8")
        for required in (
            "does not create a second identity system",
            "vision=false",
            "not a production staging implementation",
            "does not download a real image",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
