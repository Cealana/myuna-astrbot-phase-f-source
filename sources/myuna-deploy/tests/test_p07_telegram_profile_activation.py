from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import activate_p07_telegram_profile_read_v1 as activator  # noqa: E402
import build_p06_telegram_recovery_release_v1 as builder  # noqa: E402


class P07TelegramProfileActivationTests(unittest.TestCase):
    def test_candidate_contains_strict_authenticated_owner_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            digest, candidate, manifest = builder.build(ROOT, Path(temp))
            self.assertTrue(builder.verify(candidate, manifest))
            validated, _ = activator.validate_runtime_candidate(candidate)
            self.assertEqual(validated, digest)
            activator._validate_authenticated_context(candidate)
            policy = manifest["policy"]
            self.assertEqual(policy["scope"], "telegram-owner-private-only")

    def test_dropin_is_bounded_to_telegram_runtime(self) -> None:
        digest = "a" * 64
        rendered = activator.render_dropin(digest).decode("utf-8")
        self.assertIn(digest, rendered)
        self.assertIn("telegram_owner_runtime_gateway.py", rendered)
        self.assertIn("MYUNA_SESSION_CONTEXT_STORE=sqlite-v1", rendered)
        for forbidden in ("Authorization", "myuna-core@qq", "profile.json"):
            self.assertNotIn(forbidden, rendered)

    def test_activation_receipt_is_content_free_and_safety_bounded(self) -> None:
        source = (
            SCRIPTS / "activate_p07_telegram_profile_read_v1.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "/healthz",
            "/readyz",
            "shutil.rmtree",
            "git push",
            "docker system prune",
            "profile_digest",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("raw_message_recorded", source)
        self.assertIn("raw_identity_recorded", source)
        self.assertIn("secret_recorded", source)
        self.assertIn("ACTIVE_WAITING_OWNER_TELEGRAM_E2E", source)

    def test_malformed_runtime_without_authenticated_context_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp)
            runtime = candidate / "runtime"
            runtime.mkdir()
            (runtime / "telegram_owner_runtime_gateway.py").write_text(
                "CHANNEL_KIND = 'astrbot_telegram'\n",
                encoding="utf-8",
            )
            with self.assertRaises(activator.ActivationRejected):
                activator._validate_authenticated_context(candidate)


if __name__ == "__main__":
    unittest.main()
