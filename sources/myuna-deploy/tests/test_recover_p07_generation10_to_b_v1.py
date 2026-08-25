from __future__ import annotations

import ast
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import recover_p07_generation10_to_b_v1 as recovery


class Generation10ToBRecoveryTests(unittest.TestCase):
    def _backup(self, root: Path) -> tuple[Path, dict[str, bytes]]:
        backup = root / "source-backup"
        backup.mkdir(mode=0o700)
        payloads = {
            "CORE_BINDING": b"core-binding\n",
            "CORE_GATE": b"core-gate\n",
            "CORE_SELECTOR": b"core-selector\n",
            "SELECTOR": b"selector\n",
            "TELEGRAM_DROPIN": b"telegram-dropin\n",
        }
        for name, payload in payloads.items():
            path = backup / name
            path.write_bytes(payload)
            path.chmod(0o600)
        bundle = backup / "STOPPED_BUNDLE_PRESTATE.json"
        bundle.write_text('{"bundle_digest":"' + "a" * 64 + '"}', "ascii")
        bundle.chmod(0o600)
        return backup, payloads

    def test_source_backup_requires_exact_content_addressed_control_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backup, payloads = self._backup(Path(directory))
            expected = {
                name: sha256(payload).hexdigest() for name, payload in payloads.items()
            }
            with patch.object(recovery, "REQUIRED_B_FILES", expected):
                observed, bundle = recovery._load_source_backup(backup)
                self.assertEqual(observed, payloads)
                self.assertEqual(bundle["bundle_digest"], "a" * 64)
                (backup / "SELECTOR").write_bytes(b"drifted\n")
                with self.assertRaisesRegex(
                    recovery.Generation10ToBRejected,
                    "recovery_source_digest_rejected",
                ):
                    recovery._load_source_backup(backup)

    def test_source_backup_rejects_symlink_and_permission_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backup, payloads = self._backup(Path(directory))
            expected = {
                name: sha256(payload).hexdigest() for name, payload in payloads.items()
            }
            with patch.object(recovery, "REQUIRED_B_FILES", expected):
                (backup / "CORE_GATE").chmod(0o644)
                with self.assertRaisesRegex(
                    recovery.Generation10ToBRejected,
                    "recovery_source_metadata_rejected",
                ):
                    recovery._load_source_backup(backup)

    def test_executor_has_no_delete_checkpoint_or_private_row_path(self) -> None:
        source = Path(recovery.__file__).read_text("utf-8")
        tree = ast.parse(source)
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        self.assertFalse({"unlink", "rmdir", "execute", "executemany"} & attributes)
        self.assertNotIn("wal_checkpoint", source)
        self.assertNotIn("SELECT *", source)
        self.assertNotIn("requests", source)
        self.assertNotIn("httpx", source)

    def test_plan_is_content_free_and_binds_executor_and_prestate(self) -> None:
        plan = recovery.build_plan(
            {
                "b_bundle_digest": "a" * 64,
                "current_release_set_id": "b" * 64,
                "current_services": {},
                "source_backup_name": "synthetic",
                "source_control_digest": "c" * 64,
            }
        )
        self.assertIn(b'"old_epoch_content_read_or_mutated":false', plan)
        self.assertIn(b'"target":"accepted-b-generation4-functional-prestate"', plan)
        self.assertNotIn(b"message", plan)
        self.assertNotIn(b"token", plan)

    def test_rollback_restores_each_exact_prestate_service_boolean(self) -> None:
        states = {
            recovery.CORE_SERVICE: False,
            recovery.TELEGRAM_SOCKET: True,
            recovery.TELEGRAM_SERVICE: False,
        }

        def systemctl(action: str, unit: str, *, check: bool = True) -> None:
            del check
            states[unit] = action == "start"

        prestate = {
            "current_services": {
                unit: {"active": expected}
                for unit, expected in {
                    recovery.CORE_SERVICE: True,
                    recovery.TELEGRAM_SOCKET: False,
                    recovery.TELEGRAM_SERVICE: False,
                }.items()
            }
        }
        with patch.object(recovery, "systemctl", side_effect=systemctl), patch.object(
            recovery, "active", side_effect=lambda unit: states[unit]
        ), patch.object(recovery, "wait_stable"):
            recovery._restore_service_states(prestate)
        self.assertEqual(
            states,
            {
                recovery.CORE_SERVICE: True,
                recovery.TELEGRAM_SOCKET: False,
                recovery.TELEGRAM_SERVICE: False,
            },
        )


if __name__ == "__main__":
    unittest.main()
