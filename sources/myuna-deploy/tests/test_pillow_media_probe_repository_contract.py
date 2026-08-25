from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pillow_media_probe.py"
POLICY = ROOT / "config" / "vision-media-probe-pillow-v1.json"


class PillowMediaProbeRepositoryContractTests(unittest.TestCase):
    def test_probe_has_no_channel_network_or_runtime_dependency(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "telegram",
            "bot-token",
            "api.telegram.org",
            "requests",
            "urllib",
            "systemctl",
            "/etc/myuna",
            "/var/lib/myuna",
        ):
            self.assertNotIn(forbidden, text.lower())

    def test_policy_remains_inactive_and_bounded(self) -> None:
        text = POLICY.read_text(encoding="utf-8")
        for required in (
            '"status": "inactive_candidate"',
            '"maximum_bytes": 8388608',
            '"maximum_pixels": 16000000',
            '"allow_animation": false',
            '"allow_trailing_payload": false',
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
