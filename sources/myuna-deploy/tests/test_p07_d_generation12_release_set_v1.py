from __future__ import annotations

import unittest
from pathlib import Path

from p07_d_generation12_release_set import (
    GENERATION,
    PREVIOUS_EPOCH_ID,
    PREVIOUS_GENERATION,
    protected_manifest_path,
    selector_payload,
)


class Generation12ReleaseSetTests(unittest.TestCase):
    def test_selector_uses_reset_v6_and_preserves_generation11_rollback_identity(self) -> None:
        payload = selector_payload("a" * 64)
        self.assertEqual(GENERATION, 12)
        self.assertEqual(PREVIOUS_GENERATION, 11)
        self.assertEqual(payload["generation"], 12)
        self.assertEqual(
            payload["epoch_id"],
            "telegram-owner-private-external-d-reset-v6",
        )
        self.assertEqual(payload["previous_epoch_id"], PREVIOUS_EPOCH_ID)
        self.assertEqual(
            PREVIOUS_EPOCH_ID,
            "telegram-owner-private-external-d-reset-v5",
        )
        for forbidden in (
            "external-d-reset-v5/",
            "external-d-reset-v4/",
            "external-d-reset-v3/",
            "external-d-reset-v2/",
            "external-d-reset-v1/",
            "external-d-v2/",
            "external-d-v1/",
        ):
            self.assertNotIn(forbidden, payload["database_path"])

    def test_selector_rejects_unknown_or_malformed_bundle_digest(self) -> None:
        for value in ("", "A" * 64, "g" * 64, "a" * 63, "a" * 65):
            with self.subTest(value=value):
                with self.assertRaisesRegex(Exception, "generation12_bundle_digest_rejected"):
                    selector_payload(value)

    def test_protected_manifest_path_is_shared_with_generation11(self) -> None:
        self.assertEqual(
            protected_manifest_path(),
            Path("/etc/myuna-telegram-gateway/p07-d-release-set-v1.json"),
        )


if __name__ == "__main__":
    unittest.main()
