from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "channels" / "astrbot-qq" / "compose.dev.yml"
ADR = ROOT / "docs" / "ADR-018-napcat-primary-channel.md"


class AstrBotNapCatStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = COMPOSE.read_text(encoding="utf-8")
        cls.adr = ADR.read_text(encoding="utf-8")

    def test_images_are_digest_pinned(self) -> None:
        images = re.findall(r"^\s*image:\s*(\S+)$", self.compose, re.MULTILINE)
        self.assertEqual(len(images), 2)
        for image in images:
            self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")
            self.assertNotIn(":latest", image)

    def test_host_ports_are_loopback_only(self) -> None:
        published = re.findall(r'^\s*-\s*"([^\"]+:\d+:\d+)"$', self.compose, re.MULTILINE)
        self.assertEqual(sorted(published), ["127.0.0.1:6099:6099", "127.0.0.1:6185:6185"])
        self.assertNotRegex(self.compose, r'"(?:0\.0\.0\.0|\[::\]):(?:6099|6185|6199)')

    def test_onebot_port_is_not_published(self) -> None:
        self.assertNotRegex(self.compose, r'127\.0\.0\.1:6199:6199')
        self.assertIn('- "6199"', self.compose)

    def test_security_and_resource_controls_exist(self) -> None:
        self.assertGreaterEqual(self.compose.count("no-new-privileges:true"), 2)
        self.assertGreaterEqual(self.compose.count("pids_limit:"), 2)
        self.assertGreaterEqual(self.compose.count("mem_limit:"), 2)
        self.assertGreaterEqual(self.compose.count("max-size: 10m"), 2)

    def test_astrbot_boundary_is_immutable_and_local(self) -> None:
        self.assertIn(
            ":/AstrBot/data/plugins/astrbot_plugin_myuna_gateway:ro",
            self.compose,
        )
        self.assertIn(":/run/secrets/myuna-channel-signing-v1:ro", self.compose)
        self.assertIn(":/run/myuna-gateway:ro", self.compose)
        self.assertIn('PYTHONDONTWRITEBYTECODE: "1"', self.compose)
        self.assertNotIn("/var/run/postgresql", self.compose)

    def test_identity_roles_are_separate(self) -> None:
        self.assertIn("Myuna 的独立 QQ 账号", self.adr)
        self.assertIn("principal-owner-cealana", self.adr)
        self.assertIn("官方 QQ 机器人 adapter", self.adr)


if __name__ == "__main__":
    unittest.main()
