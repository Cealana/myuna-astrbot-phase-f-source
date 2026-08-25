from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import activate_p06_telegram_recovery_v1 as activator  # noqa: E402
import build_p06_telegram_recovery_release_v1 as runtime_builder  # noqa: E402
import build_telegram_gateway_release_v1 as plugin_builder  # noqa: E402


class P06TelegramRecoveryReleaseTests(unittest.TestCase):
    def test_runtime_and_plugin_candidates_are_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            runtime_root = Path(temp) / "runtime"
            runtime_digest, runtime_candidate, runtime_manifest = (
                runtime_builder.build(ROOT, runtime_root)
            )
            self.assertTrue(
                runtime_builder.verify(runtime_candidate, runtime_manifest)
            )
            validated_digest, validated_manifest = (
                activator.validate_runtime_candidate(runtime_candidate)
            )
            self.assertEqual(validated_digest, runtime_digest)
            self.assertEqual(validated_manifest, runtime_manifest)
            self.assertEqual(
                (
                    runtime_candidate
                    / "runtime/gateway_recovery_episode.py"
                ).read_bytes(),
                (ROOT / "scripts/gateway_recovery_episode.py").read_bytes(),
            )
            self.assertEqual(
                (
                    runtime_candidate
                    / "runtime/telegram_owner_runtime_gateway.py"
                ).read_bytes(),
                (
                    ROOT / "scripts/telegram_owner_runtime_gateway.py"
                ).read_bytes(),
            )

            plugin_root = Path(temp) / "plugin"
            plugin_manifest = plugin_builder.build_release(ROOT, plugin_root)
            plugin_digest = str(plugin_manifest["release_digest"])
            plugin_candidate, validated_plugin = (
                activator.validate_plugin_candidate(
                    plugin_root,
                    plugin_digest,
                )
            )
            self.assertEqual(validated_plugin, plugin_manifest)
            self.assertEqual(
                (
                    plugin_candidate
                    / "channels/astrbot-telegram/plugin/"
                    "myuna_telegram_gateway/protocol.py"
                ).read_bytes(),
                (
                    ROOT
                    / "channels/astrbot-telegram/plugin/"
                    "myuna_telegram_gateway/protocol.py"
                ).read_bytes(),
            )

    def test_activation_rendering_is_exact_and_scope_bounded(self) -> None:
        runtime_digest = "a" * 64
        plugin_digest = "b" * 64
        dropin = activator.render_dropin(runtime_digest).decode("utf-8")
        self.assertIn(runtime_digest, dropin)
        self.assertIn("MYUNA_SESSION_CONTEXT_STORE=sqlite-v1", dropin)
        self.assertNotIn("myuna-core@qq", dropin)

        config = json.loads(
            activator.render_r5_config(plugin_digest).decode("utf-8")
        )
        self.assertEqual(config["gateway_release"], plugin_digest)
        self.assertEqual(
            set(config),
            {
                "channel_root",
                "compose_file",
                "gateway_release",
                "plugin_root",
                "schema",
            },
        )
        self.assertIn(
            "/opt/myuna/telegram-gateway/releases/" + plugin_digest,
            config["plugin_root"],
        )

    def test_activation_never_uses_audit_health_or_deletes_evidence(self) -> None:
        source = (
            ROOT / "scripts/activate_p06_telegram_recovery_v1.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "/healthz",
            "/readyz",
            "shutil.rmtree",
            "unlink(missing_ok",
            "git push",
            "docker system prune",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("RECOVERY_DATABASE", source)
        self.assertNotIn("RECOVERY_DATABASE.unlink", source)
        self.assertIn("BACKUP_ROOT", source)
        self.assertIn("previous_plugin_release", source)


if __name__ == "__main__":
    unittest.main()
