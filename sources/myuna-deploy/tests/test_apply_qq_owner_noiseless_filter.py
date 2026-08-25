from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "apply_qq_owner_noiseless_filter.py"


class QQOwnerNoiselessFilterUpdateTests(unittest.TestCase):
    def test_update_is_digest_bound_and_capability_neutral(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("--approved-plan-digest", text)
        self.assertIn("hmac.compare_digest", text)
        self.assertIn("preview-only-no-writes", text)
        self.assertIn('"capabilities_changed": False', text)
        self.assertIn('"database_changed": False', text)
        self.assertIn('"model_called_by_update": False', text)

    def test_update_switches_only_the_plugin_and_has_compensating_rollback(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"--no-deps"', text)
        self.assertIn('"--force-recreate"', text)
        self.assertIn('"astrbot"', text)
        self.assertIn('"merge", "--ff-only"', text)
        self.assertIn('"revert", "--no-edit"', text)
        self.assertIn("CURRENT_PLUGIN_ROOT", text)
        self.assertNotIn("DROP FUNCTION", text)
        self.assertNotIn("DELETE FROM", text)

    def test_update_backs_up_files_without_copying_channel_secrets(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("WINDOWS_BACKUP_ROOT", text)
        self.assertIn("_copy_verified", text)
        self.assertNotIn("NAPCAT_WEBUI_TOKEN", text)
        self.assertNotIn("DEEPSEEK_API_KEY", text)


if __name__ == "__main__":
    unittest.main()
