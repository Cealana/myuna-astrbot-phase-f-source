from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config" / "effective-runtime" / "effective-v6-owner-private-candidate-v1.json"
ADR = ROOT / "docs" / "ADR-040-effective-runtime-profile-v1.md"


class EffectiveRuntimeProfileRepositoryTests(unittest.TestCase):
    def test_profile_binds_exact_component_set_and_remains_inactive(self) -> None:
        document = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.assertEqual(
            set(document["components"]),
            {
                "core_release",
                "definition_release",
                "channel_capability_profile",
                "memory_adapter",
                "reply_contract",
                "provider_policy",
                "prompt_budget",
            },
        )
        self.assertEqual(document["state"], "inactive_candidate")
        self.assertEqual(
            document["activation"],
            {
                "automatic": False,
                "selected": False,
                "installed": False,
                "requires_new_plan_digest": True,
                "requires_live_preflight": True,
            },
        )

    def test_all_references_are_content_bound_and_non_secret(self) -> None:
        document = json.loads(PROFILE.read_text(encoding="utf-8"))
        references = [
            *document["components"].values(),
            *document["shadow_observers"],
        ]
        for reference in references:
            self.assertEqual(len(reference["content_sha256"]), 64)
            int(reference["content_sha256"], 16)
            self.assertTrue(reference["source_reference"].startswith("/srv/myuna/"))
            self.assertNotIn("secret", reference["source_reference"].casefold())
            self.assertNotIn("credential", reference["source_reference"].casefold())

    def test_profile_file_has_stable_repository_evidence_digest(self) -> None:
        digest = hashlib.sha256(PROFILE.read_bytes()).hexdigest()
        self.assertEqual(len(digest), 64)
        self.assertNotEqual(digest, "0" * 64)

    def test_adr_explicitly_preserves_separate_activation_approval(self) -> None:
        text = ADR.read_text(encoding="utf-8")
        self.assertIn("repository-only / inactive", text)
        self.assertIn("requires a new plan digest and a live preflight", text)
        self.assertIn("Shared Gateway Runtime Kernel v1", text)


if __name__ == "__main__":
    unittest.main()
