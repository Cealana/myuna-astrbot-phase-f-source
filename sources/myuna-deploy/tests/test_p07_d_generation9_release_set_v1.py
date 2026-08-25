from __future__ import annotations

import unittest

from p07_d_generation9_release_set import GENERATION, selector_payload


class Generation9ReleaseSetTests(unittest.TestCase):
    def test_selector_uses_new_isolated_epoch_and_preserves_b_rollback_identity(self) -> None:
        payload = selector_payload("a" * 64)
        self.assertEqual(GENERATION, 9)
        self.assertEqual(payload["generation"], 9)
        self.assertIn("external-d-reset-v3", payload["database_path"])
        for forbidden in ("external-d-reset-v2/", "external-d-reset-v1/", "external-d-v2/", "external-d-v1/"):
            self.assertNotIn(forbidden, payload["database_path"])
        self.assertEqual(payload["previous_epoch_id"], "telegram-owner-private-external-v4")


if __name__ == "__main__":
    unittest.main()
