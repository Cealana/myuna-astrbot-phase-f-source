from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.http_client_auth import (
    HttpClientAuthError,
    LoadedHttpClientCredential,
    authenticate_http_client,
    load_http_client_credentials,
    parse_http_client_credentials,
)


class HttpClientAuthTests(unittest.TestCase):
    def test_two_scoped_credentials_load_without_secret_disclosure(self) -> None:
        specs = parse_http_client_credentials(
            "qq-owner-private:astrbot_qq:qq_owner_core_token,"
            "telegram-owner-private:astrbot_telegram:telegram_owner_core_token"
        )
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "qq_owner_core_token").write_text(
                "qq-owner-test-token",
                encoding="utf-8",
            )
            (root / "telegram_owner_core_token").write_text(
                "telegram-owner-test-token",
                encoding="utf-8",
            )
            for path in root.iterdir():
                path.chmod(0o600)
            loaded = load_http_client_credentials(
                specs,
                legacy_credential_name=None,
                environ={"CREDENTIALS_DIRECTORY": temp},
            )
        self.assertEqual(
            tuple((item.client_id, item.channel_kind) for item in loaded),
            (
                ("qq-owner-private", "astrbot_qq"),
                ("telegram-owner-private", "astrbot_telegram"),
            ),
        )
        self.assertNotIn("test-token", repr(loaded))

    def test_duplicate_secret_values_fail_closed(self) -> None:
        specs = parse_http_client_credentials(
            "qq-owner-private:astrbot_qq:qq_owner_core_token,"
            "telegram-owner-private:astrbot_telegram:telegram_owner_core_token"
        )
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("qq_owner_core_token", "telegram_owner_core_token"):
                path = root / name
                path.write_text("same-test-token", encoding="utf-8")
                path.chmod(0o600)
            with self.assertRaises(HttpClientAuthError):
                load_http_client_credentials(
                    specs,
                    legacy_credential_name=None,
                    environ={"CREDENTIALS_DIRECTORY": temp},
                )

    def test_token_and_both_identity_headers_must_match_one_client(self) -> None:
        credentials = (
            LoadedHttpClientCredential(
                client_id="qq-owner-private",
                channel_kind="astrbot_qq",
                token="qq-owner-test-token",
            ),
            LoadedHttpClientCredential(
                client_id="telegram-owner-private",
                channel_kind="astrbot_telegram",
                token="telegram-owner-test-token",
            ),
        )
        matched = authenticate_http_client(
            "Bearer telegram-owner-test-token",
            "telegram-owner-private",
            "astrbot_telegram",
            credentials,
        )
        self.assertIsNotNone(matched)
        self.assertEqual(matched.client_id, "telegram-owner-private")
        self.assertIsNone(
            authenticate_http_client(
                "Bearer telegram-owner-test-token",
                "qq-owner-private",
                "astrbot_qq",
                credentials,
            )
        )
        self.assertIsNone(
            authenticate_http_client(
                "Bearer telegram-owner-test-token",
                "",
                "",
                credentials,
            )
        )
        self.assertIsNone(
            authenticate_http_client(
                "Bearer unknown-test-token",
                "telegram-owner-private",
                "astrbot_telegram",
                credentials,
            )
        )

    def test_legacy_single_client_remains_backward_compatible(self) -> None:
        credential = LoadedHttpClientCredential(
            client_id="legacy-dev",
            channel_kind="loopback_dev",
            token="legacy-test-token",
            identity_headers_required=False,
        )
        self.assertIs(
            authenticate_http_client(
                "Bearer legacy-test-token",
                "",
                "",
                (credential,),
            ),
            credential,
        )


if __name__ == "__main__":
    unittest.main()
