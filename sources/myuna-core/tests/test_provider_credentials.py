from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.providers.credentials import CredentialError, load_systemd_credential


class ProviderCredentialTests(unittest.TestCase):
    def test_systemd_credential_is_loaded_without_environment_fallback(self) -> None:
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            credential = directory / "deepseek_api_key"
            credential.write_text("mock-secret-key", encoding="utf-8")
            credential.chmod(0o600)
            value = load_systemd_credential(environ={"CREDENTIALS_DIRECTORY": temp})
            self.assertEqual(value, "mock-secret-key")

    def test_environment_variable_secret_is_explicitly_rejected(self) -> None:
        with self.assertRaises(CredentialError):
            load_systemd_credential(
                environ={
                    "CREDENTIALS_DIRECTORY": "/run/credentials/example",
                    "DEEPSEEK_API_KEY": "forbidden",
                }
            )

    def test_world_readable_credential_is_rejected(self) -> None:
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            credential = directory / "deepseek_api_key"
            credential.write_text("mock-secret-key", encoding="utf-8")
            credential.chmod(0o604)
            with self.assertRaises(CredentialError):
                load_systemd_credential(environ={"CREDENTIALS_DIRECTORY": temp})

    def test_missing_credential_directory_is_rejected(self) -> None:
        with self.assertRaises(CredentialError):
            load_systemd_credential(environ={})


if __name__ == "__main__":
    unittest.main()
