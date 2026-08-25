from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
ADR = ROOT / "docs" / "ADR-045-telegram-thin-media-transport-v1.md"
SCRIPTS = tuple(
    ROOT / "scripts" / name
    for name in (
        "media_transport_kernel.py",
        "telegram_media_transport_adapter.py",
        "fake_media_transport_adapter.py",
    )
)


class TelegramMediaTransportRepositoryContractTests(unittest.TestCase):
    def test_candidate_has_no_live_sdk_secret_path_or_activation(self) -> None:
        flattened = "\n".join(path.read_text(encoding="utf-8") for path in SCRIPTS)
        for forbidden in (
            "bot-token",
            "CREDENTIALS_DIRECTORY",
            "getFile",
            "api.telegram.org",
            "systemctl",
            "/etc/myuna",
            "/var/lib/myuna",
        ):
            self.assertNotIn(forbidden, flattened)

    def test_adr_states_fake_parity_and_non_effects(self) -> None:
        text = " ".join(ADR.read_text(encoding="utf-8").split())
        for required in (
            "produce identical authenticated media delivery",
            "production decoder is deliberately absent",
            "does not modify the active AstrBot plugin",
            "No Telegram SDK or API is imported or called",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
