from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load_module(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


build = load_module(
    "build_persistent_session_context_v1_release.py",
    "build_persistent_session_context_v1_release",
)
activate = load_module(
    "activate_persistent_session_context_v1.py",
    "activate_persistent_session_context_v1",
)


class PersistentSessionContextReleaseTests(unittest.TestCase):
    def test_canonical_bytes_are_deterministic(self) -> None:
        self.assertEqual(
            build.canonical_bytes({"b": 2, "a": "中文"}),
            b'{"a":"\xe4\xb8\xad\xe6\x96\x87","b":2}',
        )

    def test_dropins_enable_only_candidate_runtime_and_sqlite(self) -> None:
        digest = "a" * 64
        for channel in ("qq", "telegram"):
            rendered = activate.render_dropin(channel, digest).decode("utf-8")
            self.assertIn(digest, rendered)
            self.assertIn("MYUNA_SESSION_CONTEXT_STORE=sqlite-v1", rendered)
            self.assertNotIn("EnvironmentFile", rendered)
            self.assertEqual(rendered.count("ExecStart="), 2)

    def test_channel_release_paths_are_distinct(self) -> None:
        self.assertNotEqual(
            activate.CHANNELS["qq"]["release_root"],
            activate.CHANNELS["telegram"]["release_root"],
        )

    def test_core_exec_wrapper_overrides_attempts_at_last_hop(self) -> None:
        rendered = activate.render_core_exec_dropin().decode("utf-8")
        self.assertEqual(rendered.count("ExecStart="), 2)
        self.assertIn("/usr/bin/env MYUNA_DEEPSEEK_MAX_ATTEMPTS=1", rendered)
        self.assertIn("/usr/bin/python3 -m myuna_core", rendered)
        self.assertNotIn("/bin/sh", rendered)

    def test_core_exec_wrapper_passes_systemd_syntax_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            unit = Path(directory) / "pctx-core-wrapper.service"
            unit.write_text(
                "[Unit]\nDescription=synthetic\n"
                "[Service]\nType=simple\n"
                "ExecStart=/usr/bin/python3 -m myuna_core\n"
                + activate.render_core_exec_dropin().decode("utf-8"),
                encoding="utf-8",
            )
            completed = subprocess.run(
                ["systemd-analyze", "verify", str(unit)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_mock_rollback_removes_only_exact_candidate_dropins(self) -> None:
        digest = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            channels = {}
            for channel in ("qq", "telegram"):
                dropin = root / channel / "candidate.conf"
                dropin.parent.mkdir()
                original = activate.CHANNELS[channel]
                channels[channel] = {**original, "dropin": dropin}
            baseline = b"MYUNA_DEEPSEEK_MAX_ATTEMPTS=2\nOTHER=same\n"
            core_environment = root / "qq.env"
            core_environment.write_bytes(baseline)
            core_exec_dropin = root / "core" / "candidate.conf"
            core_exec_dropin.parent.mkdir()
            core_exec_dropin.write_bytes(activate.render_core_exec_dropin())
            backup = root / "backup"
            backup.mkdir()
            (backup / "qq.env").write_bytes(baseline)
            (backup / "RECEIPT.json").write_text(
                '{"core":{"environment_sha256":"'
                + activate.digest_bytes(baseline)
                + '","exec_dropin_preexisting":false}}',
                encoding="utf-8",
            )
            with (
                mock.patch.object(activate, "CHANNELS", channels),
                mock.patch.object(activate, "CORE_ENV_PATH", core_environment),
                mock.patch.object(activate, "CORE_EXEC_DROPIN", core_exec_dropin),
                mock.patch.object(activate, "systemctl") as systemctl,
                mock.patch.object(activate, "is_active", return_value=True),
                mock.patch.object(
                    activate,
                    "_effective_core_attempts",
                    return_value=activate.CORE_BASE_MAX_ATTEMPTS,
                ),
            ):
                for channel, spec in channels.items():
                    spec["dropin"].write_bytes(
                        activate.render_dropin(channel, digest)
                    )
                activate._rollback_live(digest, backup)
            self.assertEqual(core_environment.read_bytes(), baseline)
            self.assertFalse(core_exec_dropin.exists())
            self.assertTrue(all(not spec["dropin"].exists() for spec in channels.values()))
            systemctl.assert_any_call("daemon-reload")
            systemctl.assert_any_call("restart", activate.CORE_SERVICE)


if __name__ == "__main__":
    unittest.main()
