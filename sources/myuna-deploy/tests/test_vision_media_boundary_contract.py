from __future__ import annotations

from pathlib import Path
import unittest

from myuna_core.vision_media_boundary import VisionMediaStagingPolicy


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "vision" / "vision-media-staging-policy-v1.json"
ADR = ROOT / "docs" / "ADR-043-vision-media-boundary-v1.md"


class VisionMediaBoundaryRepositoryTests(unittest.TestCase):
    def test_policy_loads_inactive_and_single_read(self) -> None:
        policy = VisionMediaStagingPolicy.load(POLICY)
        self.assertEqual(policy.status, "inactive_candidate")
        self.assertEqual(policy.maximum_reads_per_media, 1)
        self.assertFalse(policy.allow_persistent_copy)
        self.assertFalse(policy.allow_remote_fetch)
        self.assertTrue(policy.secure_disposal_required)

    def test_adr_does_not_claim_physical_erasure_or_runtime_installation(self) -> None:
        text = ADR.read_text(encoding="utf-8")
        for required in (
            "unsupported physical-erasure promise",
            "does not create a staging directory",
            "single-read lease",
            "no local path",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
