from __future__ import annotations

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class P07AOwnerProfileFoundationTests(unittest.TestCase):
    def test_blank_template_is_deliberately_not_deployable(self) -> None:
        template = ROOT / "templates/owner-profile-v1.blank.toml"
        payload = tomllib.loads(template.read_text("utf-8"))
        self.assertTrue(payload["template_only"])
        self.assertEqual(payload["profile_revision"], 0)
        self.assertTrue(all(not section["body"] for section in payload["sections"]))

    def test_adr_requires_separate_profile_namespace_and_no_live_activation(self) -> None:
        text = (
            ROOT / "docs/ADR-052-owner-profile-baseline-readonly-v1.md"
        ).read_text("utf-8")
        self.assertIn("owner_profile.retrieve_v1", text)
        self.assertIn("owner_profile_read_v1", text)
        self.assertIn("repository-only", text)
        self.assertIn("SOURCE_READY_WAITING_OWNER_PROFILE", text)
        self.assertIn("`owner_memory.retrieve_v2`", text)
        self.assertIn("`/run/myuna-owner-profile-read-v1/profile.sock`", text)

    def test_filling_guide_excludes_temporal_and_third_party_content(self) -> None:
        text = (ROOT / "docs/owner-profile-v1-filling-guide.md").read_text("utf-8")
        self.assertIn("P08 Active Temporal Context", text)
        self.assertIn("private third-party facts", text)
        self.assertIn("no encryption claim is made", text)


if __name__ == "__main__":
    unittest.main()
