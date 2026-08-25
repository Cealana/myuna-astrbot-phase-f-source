from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "apply_qq_owner_boundary_metadata_fix.py"
METADATA = (
    ROOT
    / "channels"
    / "astrbot-qq"
    / "plugin"
    / "myuna_gateway"
    / "metadata.yaml"
)


class QQOwnerBoundaryMetadataFixTests(unittest.TestCase):
    def test_metadata_names_and_scopes_the_plugin(self) -> None:
        text = METADATA.read_text(encoding="utf-8")
        self.assertIn("name: astrbot_plugin_myuna_gateway", text)
        self.assertIn("version: 0.2.0", text)
        self.assertIn("support_platforms:\n  - aiocqhttp", text)

    def test_release_requires_and_hashes_metadata(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('TARGET_PLUGIN_FILES = ("main.py", "protocol.py", "metadata.yaml")', text)
        self.assertIn("plugin_bundle_sha256", text)
        self.assertIn("target plugin metadata is incomplete", text)
        self.assertIn("plugin_metadata_verified", text)

    def test_astrbot_default_llm_is_disabled_fail_closed(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('provider_settings["enable"] = False', text)
        self.assertIn('"astrbot_builtin_llm": "disabled-fail-closed"', text)
        self.assertIn('"astrbot_builtin_llm_enabled": False', text)
        self.assertIn("_astrbot_provider_state() != (False, 0)", text)

    def test_update_is_digest_bound_and_does_not_restart_napcat(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("--approved-plan-digest", text)
        self.assertIn("hmac.compare_digest", text)
        self.assertIn('"--no-deps"', text)
        self.assertIn('"--force-recreate"', text)
        self.assertIn('"astrbot"', text)
        self.assertNotIn('"napcat",', text)
        self.assertNotIn("DEEPSEEK_API_KEY", text)

    def test_sensitive_config_has_two_verified_backups_and_rollback(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("pre-cmd_config.json", text)
        self.assertIn("WINDOWS_BACKUP_ROOT", text)
        self.assertIn("_restore_config", text)
        self.assertIn('"revert", "--no-edit"', text)
        self.assertIn("recreate_astrbot_after_restore", text)


if __name__ == "__main__":
    unittest.main()
