from __future__ import annotations

from pathlib import Path
import unittest

from myuna_core.capabilities import load_capability_manifest
from myuna_core.config import load_settings
from myuna_core.providers.runtime import load_deepseek_runtime_settings


class LoopbackRuntimeConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[1]
        self.environment = {}
        for line in (self.repo / "config/dev-loopback-v5.env").read_text(
            encoding="utf-8"
        ).splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                self.environment[key] = value

    def test_manifest_enables_only_loopback_conversation(self) -> None:
        manifest = load_capability_manifest(
            self.repo / "config/capabilities/dev-v3.json"
        )
        self.assertEqual(manifest.response_scope, "loopback_dev_only")
        self.assertTrue(manifest.definition_release_active)
        self.assertTrue(manifest.core_active)
        self.assertFalse(manifest.external_listener_enabled)
        self.assertTrue(manifest.capability_enabled("conversation"))
        for name in (
            "long_term_memory_read",
            "long_term_memory_write",
            "vision",
            "tools",
            "external_data",
            "external_actions",
            "system_administration",
            "qq_channel",
        ):
            self.assertFalse(manifest.capability_enabled(name))

    def test_environment_is_ready_loopback_and_budgeted(self) -> None:
        settings = load_settings(self.environment)
        provider = load_deepseek_runtime_settings(self.environment)
        self.assertTrue(settings.ready)
        self.assertEqual(settings.bind_host, "127.0.0.1")
        self.assertFalse(settings.memory_worker_enabled)
        self.assertTrue(settings.memory_synthetic_only)
        self.assertTrue(provider.live_calls_enabled)
        self.assertEqual(str(provider.daily_budget_usd), "2.00")

    def test_v4_environment_is_checksum_bound_synthetic_read_only(self) -> None:
        environment = {}
        for line in (
            self.repo / "config/dev-loopback-v5-synthetic-memory.env"
        ).read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                environment[key] = value
        manifest = load_capability_manifest(
            self.repo / "config/capabilities/dev-v4.json"
        )
        settings = load_settings(environment)
        self.assertEqual(manifest.response_scope, "loopback_dev_synthetic_memory")
        self.assertTrue(manifest.capability_enabled("long_term_memory_read"))
        self.assertFalse(manifest.authorizations["real_memory"])
        self.assertTrue(settings.memory_worker_enabled)
        self.assertTrue(settings.memory_synthetic_only)
        self.assertEqual(
            settings.memory_synthetic_fixture_sha256,
            "D71454FCB48061876874F41CC1DE3549029EA5C9876783A8A2E64BB57D1D0F8B",
        )


if __name__ == "__main__":
    unittest.main()
