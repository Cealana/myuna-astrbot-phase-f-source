from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import render_telegram_astrbot_config as renderer
import telegram_bot_token_intake as intake


SYNTHETIC_TOKEN = "12345678:" + "A" * 36


class TelegramTokenIntakeR2Tests(unittest.TestCase):
    def test_token_validation_is_bounded_and_content_free(self) -> None:
        self.assertEqual(
            intake.validate_token((SYNTHETIC_TOKEN + "\n").encode("ascii")),
            SYNTHETIC_TOKEN.encode("ascii"),
        )
        for invalid in (b"", b"secret", b"123:abc", b"A" * 200):
            with self.subTest(invalid_length=len(invalid)):
                with self.assertRaises(intake.TokenIntakeRejected) as caught:
                    intake.validate_token(invalid)
                rendered = invalid.decode("ascii", "ignore")
                if rendered:
                    self.assertNotIn(rendered, str(caught.exception))

    def test_atomic_secret_is_mode_0600_and_replace_is_explicit(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("mode and ownership contract requires root test runner")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "secrets" / "bot-token"
            intake.write_secret_atomic(
                target,
                SYNTHETIC_TOKEN.encode("ascii"),
                replace=False,
            )
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(target.read_text(encoding="ascii").strip(), SYNTHETIC_TOKEN)
            with self.assertRaises(intake.TokenIntakeRejected):
                intake.write_secret_atomic(
                    target,
                    SYNTHETIC_TOKEN.encode("ascii"),
                    replace=False,
                )

    def test_renderer_disables_astrbot_provider_and_commands(self) -> None:
        baseline = {
            "admins_id": ["synthetic"],
            "platform": [],
            "provider": [{"id": "must-be-removed"}],
            "provider_settings": {
                "enable": True,
                "proactive_capability": {"add_cron_tools": True},
                "web_search": True,
            },
            "provider_sources": [{"id": "must-be-removed"}],
        }
        rendered = renderer.render_config(baseline, SYNTHETIC_TOKEN)
        renderer.validate_rendered_config(rendered)
        self.assertEqual(rendered["admins_id"], [])
        self.assertEqual(rendered["provider"], [])
        self.assertEqual(rendered["provider_sources"], [])
        platform = rendered["platform"][0]
        self.assertFalse(platform["telegram_command_register"])
        self.assertFalse(platform["telegram_command_auto_refresh"])
        self.assertEqual(platform["telegram_token"], SYNTHETIC_TOKEN)
        self.assertEqual(
            platform["start_message"],
            "Myuna Telegram 安全入口已启动；请按 Owner 绑定流程继续",
        )

    def test_renderer_targets_the_single_telegram_runtime_identity(self) -> None:
        self.assertEqual(
            renderer.TELEGRAM_USER,
            "myuna-gateway-telegram",
        )

    def test_windows_helper_does_not_put_token_in_arguments_or_output(self) -> None:
        helper = (
            ROOT
            / "scripts"
            / "windows"
            / "Set-MyunaTelegramToken.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("Read-Host", helper)
        self.assertIn("-AsSecureString", helper)
        self.assertIn("RedirectStandardInput = $true", helper)
        self.assertIn("ZeroFreeBSTR", helper)
        self.assertNotIn("Write-Host $plainToken", helper)
        self.assertNotRegex(helper, r"ArgumentList\.Add\(\$plainToken\)")

    def test_candidate_contains_no_real_token(self) -> None:
        token_pattern = r"\b[0-9]{8,12}:[A-Za-z0-9_-]{30,}\b"
        for path in (
            ROOT / "scripts" / "telegram_bot_token_intake.py",
            ROOT / "scripts" / "render_telegram_astrbot_config.py",
            ROOT / "scripts" / "windows" / "Set-MyunaTelegramToken.ps1",
        ):
            self.assertNotRegex(path.read_text(encoding="utf-8"), token_pattern)


if __name__ == "__main__":
    unittest.main()
