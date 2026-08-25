from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import activate_p07_local_provider_1_7b_v1 as activation  # noqa: E402


class P07LocalProvider17BActivationTests(unittest.TestCase):
    def test_target_metadata_is_exact_and_content_free(self) -> None:
        self.assertEqual(activation.TARGET_MODEL_BYTES, 1_282_439_264)
        self.assertEqual(
            activation.TARGET_MODEL_SHA256,
            "d2387ca2dbfee2ffabce7120d3770dadca0b293052bc2f0e138fdc940d9bc7b5",
        )
        self.assertEqual(
            activation.TARGET_MODEL_REVISION,
            "daeb8e2d528a760970442092f6bf1e55c3b659eb",
        )
        plan = json.loads(activation.plan_bytes())
        self.assertEqual(plan["target"]["alias"], "myuna-local-owner-v1")
        self.assertTrue(plan["live_scope"]["model_or_provider_probe_forbidden"])
        self.assertTrue(plan["rollback"]["profile_and_session_data_unchanged"])

    def test_target_unit_changes_only_the_model_release_contract(self) -> None:
        target = activation.target_unit_bytes().decode("utf-8")
        current = (ROOT / "systemd/myuna-local-provider-v1.service").read_text(
            encoding="utf-8"
        )
        self.assertIn(activation.TARGET_MODEL_PATH.as_posix(), target)
        self.assertNotIn(activation.CURRENT_MODEL_PATH.as_posix(), target)
        self.assertIn(activation.CURRENT_MODEL_PATH.as_posix(), current)
        for invariant in (
            "--alias myuna-local-owner-v1",
            "--host 127.0.0.1 --port 879",
            "--ctx-size 8192",
            "--offline",
            "--no-cache-prompt",
            "--log-disable",
            "MemoryMax=8G",
        ):
            self.assertIn(invariant, target)

    def test_activator_contains_no_model_health_or_private_probe(self) -> None:
        source = (SCRIPTS / "activate_p07_local_provider_1_7b_v1.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "/health",
            "/v1/models",
            "/chat/completions",
            "profile.toml",
            "urllib",
            "git push",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("socket.create_connection", source)
        self.assertIn("PRE_UNIT.service", source)

    def test_active_uses_systemctl_exit_status(self) -> None:
        with mock.patch.object(activation.subprocess, "run") as run:
            run.return_value.returncode = 3
            self.assertFalse(activation.active("inactive.service"))
            run.return_value.returncode = 0
            self.assertTrue(activation.active("active.service"))


if __name__ == "__main__":
    unittest.main()
