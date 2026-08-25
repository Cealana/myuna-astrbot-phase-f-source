from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import activate_p08_active_temporal_context_v1 as activation


class P08CombinedRollbackTests(unittest.TestCase):
    @unittest.skipUnless(activation.os.geteuid() == 0, "root required")
    def test_successful_phase_can_be_rolled_back_to_absent_without_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            (state / "temporal-context.sqlite3").write_bytes(b"synthetic")
            (state / "trusted-time.sqlite3").write_bytes(b"synthetic")
            selector = root / "selector.json"
            environment = root / "selector.env"
            service = root / "service"
            socket = root / "socket"
            for path in (selector, environment, service, socket):
                path.write_bytes(b"target")
            payload = {
                "release_digest": "a" * 64,
                "release_source": "/synthetic/release",
                "release_target": "/synthetic/target",
                "core_commit": "1" * 40,
                "deploy_commit": "2" * 40,
                "gateway_runtime": "/synthetic/runtime",
                "gateway_manifest_digest": "b" * 64,
                "gateway_client_sha256": "c" * 64,
                "plugin": "/synthetic/plugin",
                "plugin_digest": "d" * 64,
                "state_prestate": "absent",
                "files_prestate": {
                    str(path): {"state": "absent"}
                    for path in (selector, environment, service, socket)
                },
            }
            plan_digest = activation.digest_bytes(activation.canonical(payload))
            plan = {
                "schema": activation.PLAN_SCHEMA,
                "plan_digest": plan_digest,
                **payload,
            }
            backup = root / "backup" / plan_digest
            backup.mkdir(parents=True)
            commands: list[list[str]] = []
            with patch.object(activation, "STATE_ROOT", state), patch.object(
                activation, "BACKUP_ROOT", root / "backup"
            ):
                receipt = activation.rollback_activated_plan(
                    plan,
                    runner=lambda command: commands.append(command),
                )
            self.assertEqual(receipt["status"], "rolled_back")
            self.assertFalse(state.exists())
            preserved = backup / "state-preserved-after-combined-rollback"
            self.assertEqual(
                {path.name for path in preserved.iterdir()},
                {"temporal-context.sqlite3", "trusted-time.sqlite3"},
            )
            self.assertTrue(all(not path.exists() for path in (selector, environment, service, socket)))
            self.assertEqual(commands[-1], ["/usr/bin/systemctl", "daemon-reload"])


if __name__ == "__main__":
    unittest.main()
