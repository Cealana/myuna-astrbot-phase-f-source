from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).parents[1]


def load_script(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class P07COwnerProfileWriteFoundationTests(unittest.TestCase):
    def test_channel_profile_is_telegram_owner_private_text_only(self) -> None:
        document = json.loads(
            (
                ROOT
                / "config/capabilities/owner-private-profile-write-v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(document["response_scope"], "owner_private_dev_profile_write_v1")
        self.assertEqual(document["memory_protocol"], "profile-write-v1")
        self.assertEqual(document["subject"]["channel_kinds"], ["astrbot_telegram"])
        self.assertEqual(document["subject"]["conversation_kinds"], ["private"])
        self.assertEqual(document["subject"]["authority_levels"], ["owner"])
        self.assertTrue(document["capabilities"]["long_term_memory_write"])
        for name in (
            "vision",
            "tools",
            "external_data",
            "external_actions",
            "system_administration",
        ):
            self.assertFalse(document["capabilities"][name])

    def test_runtime_manifest_is_local_and_exact_confirmation_scope(self) -> None:
        document = json.loads(
            (
                ROOT
                / "config/capabilities/telegram-owner-v6-p07c-local-profile-write-v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(document["models"]["default"]["provider"], "local")
        self.assertEqual(
            document["service"]["response_scope"],
            "owner_private_dev_profile_write_v1",
        )
        self.assertEqual(
            document["capabilities"]["long_term_memory_write"]["scope"],
            (
                "verified Telegram Owner-private text; local candidate analysis; "
                "Owner-confirmed immutable Profile revision"
            ),
        )
        self.assertFalse(document["capabilities"]["tools"]["enabled"])
        self.assertFalse(document["capabilities"]["external_actions"]["enabled"])

    def test_core_environment_enables_only_fixed_profile_write_socket(self) -> None:
        lines = (
            ROOT / "config/telegram-owner-p07c-local-profile-write-v1.env"
        ).read_text(encoding="utf-8").splitlines()
        values = dict(line.split("=", 1) for line in lines)
        self.assertEqual(values["MYUNA_PROVIDERS_ENABLED"], "local")
        self.assertEqual(values["MYUNA_OWNER_PROFILE_WRITE_ENABLED"], "true")
        self.assertEqual(
            values["MYUNA_OWNER_PROFILE_WRITE_WORKER_SOCKET"],
            "/run/myuna-owner-profile-write-v1/profile-write.sock",
        )
        self.assertEqual(
            values["MYUNA_OWNER_PROFILE_CAPABILITY_PROFILE"],
            "/etc/myuna/capabilities/owner-private-profile-read-v1.json",
        )
        self.assertNotIn("deepseek", "\n".join(lines).casefold())

    def test_read_worker_release_includes_dynamic_selector_code(self) -> None:
        installer = load_script(
            "install_owner_profile_read_code_v1_p07c",
            "scripts/install_owner_profile_read_code_v1.py",
        )
        self.assertIn(
            "src/myuna_core/owner_profile/active_selector.py",
            installer.SOURCE_FILES,
        )


if __name__ == "__main__":
    unittest.main()
