from __future__ import annotations

import unittest
from pathlib import Path

from p07_d_generation11_release_set import GENERATION, protected_manifest_path, selector_payload


class Generation11ReleaseSetTests(unittest.TestCase):
    def test_selector_uses_new_isolated_epoch_and_preserves_b_rollback_identity(self) -> None:
        payload = selector_payload("a" * 64)
        self.assertEqual(GENERATION, 11)
        self.assertEqual(payload["generation"], 11)
        self.assertIn("external-d-reset-v5", payload["database_path"])
        for forbidden in (
            "external-d-reset-v4/",
            "external-d-reset-v3/",
            "external-d-reset-v2/",
            "external-d-reset-v1/",
            "external-d-v2/",
            "external-d-v1/",
        ):
            self.assertNotIn(forbidden, payload["database_path"])
        self.assertEqual(payload["previous_epoch_id"], "telegram-owner-private-external-v4")

    def test_protected_manifest_uses_service_traversable_config_root(self) -> None:
        self.assertEqual(
            protected_manifest_path(),
            Path("/etc/myuna-telegram-gateway/p07-d-release-set-v1.json"),
        )
        self.assertNotEqual(protected_manifest_path().parent, Path("/etc/myuna"))


if __name__ == "__main__":
    unittest.main()
