from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "tmpfiles.d/myuna-telegram-media-shadow.conf"


class TelegramMediaShadowTmpfilesTests(unittest.TestCase):
    def test_exact_runtime_directory_contract(self) -> None:
        self.assertEqual(
            CONTRACT.read_text(encoding="ascii").splitlines(),
            [
                "d /run/myuna-telegram-media-auth 0750 myuna-gateway-telegram myuna-gateway-telegram -",
                "d /run/myuna-telegram-media-metadata-shadow 0755 myuna-telegram-media-shadow myuna-gateway-telegram -",
            ],
        )

    def test_contract_is_runtime_only_and_contains_no_secret_path(self) -> None:
        text = CONTRACT.read_text(encoding="ascii")
        for forbidden in (
            "/etc/", "/opt/", "/srv/", "/home/", "secret", "token",
            "0777", "0666", "root root",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
