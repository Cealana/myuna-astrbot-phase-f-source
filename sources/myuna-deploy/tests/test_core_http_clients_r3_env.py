from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import render_core_http_clients_r3_env as renderer


DROP_IN = ROOT / "systemd" / "myuna-core-telegram-credential-r3.conf"


class CoreHttpClientsR3EnvTests(unittest.TestCase):
    def test_exact_legacy_line_is_replaced_and_everything_else_is_preserved(self):
        source = (
            "MYUNA_ENV=dev\n"
            f"{renderer.LEGACY_LINE}\n"
            "MYUNA_MODEL=deepseek\n"
        )
        rendered = renderer.render_scoped_http_clients(source)
        self.assertEqual(
            rendered,
            (
                "MYUNA_ENV=dev\n"
                f"{renderer.SCOPED_LINE}\n"
                "MYUNA_MODEL=deepseek\n"
            ),
        )
        self.assertNotIn(renderer.LEGACY_LINE, rendered)

    def test_missing_duplicate_or_mixed_configuration_fails_closed(self) -> None:
        rejected = (
            "MYUNA_ENV=dev\n",
            f"{renderer.LEGACY_LINE}\n{renderer.LEGACY_LINE}\n",
            (
                f"{renderer.LEGACY_LINE}\n"
                f"{renderer.SCOPED_LINE}\n"
            ),
            "MYUNA_DEV_TOKEN_CREDENTIAL=unexpected\n",
        )
        for source in rejected:
            with self.subTest(source=source):
                with self.assertRaises(renderer.CoreHttpClientEnvRejected):
                    renderer.render_scoped_http_clients(source)

    def test_line_ending_and_missing_final_newline_are_preserved(self) -> None:
        source = f"A=1\r\n{renderer.LEGACY_LINE}"
        rendered = renderer.render_scoped_http_clients(source)
        self.assertEqual(rendered, f"A=1\r\n{renderer.SCOPED_LINE}")

    def test_core_drop_in_adds_only_telegram_credential(self) -> None:
        content = DROP_IN.read_text(encoding="utf-8")
        self.assertEqual(
            content,
            (
                "[Service]\n"
                "LoadCredential=telegram_owner_core_token:"
                "/etc/myuna-telegram-gateway/secrets/core-token-v1\n"
            ),
        )
        self.assertNotIn("Environment=", content)
        self.assertNotIn("ExecStart", content)
        self.assertNotIn("qq_owner_core_token", content)


if __name__ == "__main__":
    unittest.main()
