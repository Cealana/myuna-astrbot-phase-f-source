from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import p07_credential_binding as binding
from scripts import recover_p07_b_generation4_core_v1 as recovery


class Generation4IncidentRecoveryTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path]:
        dropins = root / "dropins"
        dropins.mkdir()
        source = root / "credential-source"
        source.write_bytes(b"synthetic-only")
        source.chmod(0o600)
        (dropins / "credentials.conf").write_text(
            f"[Service]\n{binding.DIRECTIVE_PREFIX}{source.as_posix()}\n",
            encoding="ascii",
        )
        local_profile = dropins / recovery.LOCAL_PROFILE_DROPIN.name
        local_profile.write_bytes(recovery.BROKEN_LOCAL_PROFILE_DROPIN)
        (dropins / "zzzzzzzzz-p07-hybrid-external-v1.conf").write_bytes(
            binding.canonical_hybrid_gate()
        )
        for path in dropins.glob("*.conf"):
            path.chmod(0o644)
        return dropins, source, local_profile

    def test_executor_has_no_private_state_or_active_probe_path(self) -> None:
        source = Path(recovery.__file__).read_text(encoding="utf-8")
        self.assertNotIn("journalctl", source)
        self.assertNotIn("sqlite3", source)
        self.assertNotIn("external-context-epochs", source)
        self.assertNotIn("urllib", source)
        self.assertNotIn("requests", source)
        self.assertNotIn("provider_payload", source)
        self.assertNotIn("model_response", source)
        self.assertNotIn("generation-5", source)
        self.assertNotIn("generation-6", source)

    def test_preflight_recognizes_exact_missing_effective_credential_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dropins, source, local_profile = self._fixture(Path(temporary))
            with mock.patch.object(recovery, "DROPIN_ROOT", dropins), mock.patch.object(
                recovery, "LOCAL_PROFILE_DROPIN", local_profile
            ), mock.patch.object(recovery, "EXPECTED_SOURCE", source), mock.patch.object(
                recovery, "_verify_exact_b_selection"
            ), mock.patch.object(
                recovery,
                "active",
                side_effect=lambda unit: unit == recovery.TELEGRAM_SOCKET,
            ), mock.patch.object(recovery, "_restart_count", return_value=54):
                prestate = recovery.inspect_prestate()
            self.assertFalse(prestate["core_active"])
            self.assertEqual(prestate["core_restarts"], 54)
            self.assertTrue(prestate["telegram_socket_active"])

    def test_preflight_rejects_unrecognized_dropin_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dropins, source, local_profile = self._fixture(Path(temporary))
            local_profile.write_bytes(recovery.BROKEN_LOCAL_PROFILE_DROPIN + b"# drift\n")
            with mock.patch.object(recovery, "DROPIN_ROOT", dropins), mock.patch.object(
                recovery, "LOCAL_PROFILE_DROPIN", local_profile
            ), mock.patch.object(recovery, "EXPECTED_SOURCE", source), mock.patch.object(
                recovery, "_verify_exact_b_selection"
            ):
                with self.assertRaises(recovery.RecoveryRejected) as captured:
                    recovery.inspect_prestate()
            self.assertEqual(
                captured.exception.code,
                "local_profile_dropin_prestate_drifted",
            )

    def test_apply_writes_rebind_and_content_free_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _dropins, _source, local_profile = self._fixture(root)
            prestate = {
                "core_active": False,
                "core_restarts": 54,
                "core_release": recovery.CORE_RELEASE,
                "local_profile_dropin_gid": local_profile.stat().st_gid,
                "local_profile_dropin_mode": 0o644,
                "local_profile_dropin_sha256": recovery.digest_file(local_profile),
                "selector_sha256": recovery.EXPECTED_SELECTOR_SHA256,
                "telegram_service_active": False,
                "telegram_socket_active": True,
            }
            patches = [
                mock.patch.object(recovery, "LOCAL_PROFILE_DROPIN", local_profile),
                mock.patch.object(recovery, "BACKUP_ROOT", root / "backups"),
                mock.patch.object(recovery, "STATE_ROOT", root / "state"),
                mock.patch.object(recovery, "inspect_prestate", return_value=prestate),
                mock.patch.object(recovery, "systemctl", return_value=""),
                mock.patch.object(recovery, "verify_strict_binding", return_value={}),
                mock.patch.object(recovery, "wait_stable", return_value=54),
                mock.patch.object(
                    recovery,
                    "verify_target",
                    return_value={
                        "core_restarts": 54,
                        "effective_credential_count": 1,
                        "generation": 4,
                        "telegram_restarts": 0,
                    },
                ),
            ]
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
                ready = recovery.recover(
                    expected_plan_sha256=None,
                    preflight_only=True,
                )
                result = recovery.recover(
                    expected_plan_sha256=str(ready["plan_sha256"]),
                    preflight_only=False,
                )
            self.assertEqual(local_profile.read_bytes(), recovery.CORE_DROPIN_BYTES)
            self.assertEqual(
                result["status"],
                "P07_B_GENERATION4_FUNCTIONAL_PRESTATE_RESTORED",
            )
            receipts = list((root / "state").glob("RECEIPT-*.json"))
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
            self.assertFalse(receipt["credential_source_or_value_changed"])
            self.assertFalse(receipt["channel_model_provider_health_called"])

    def test_failure_restores_exact_dropin_and_inactive_prestate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _dropins, _source, local_profile = self._fixture(root)
            original = local_profile.read_bytes()
            prestate = {
                "core_active": False,
                "core_restarts": 54,
                "core_release": recovery.CORE_RELEASE,
                "local_profile_dropin_gid": local_profile.stat().st_gid,
                "local_profile_dropin_mode": 0o644,
                "local_profile_dropin_sha256": recovery.digest_file(local_profile),
                "selector_sha256": recovery.EXPECTED_SELECTOR_SHA256,
                "telegram_service_active": False,
                "telegram_socket_active": True,
            }
            active_state = {recovery.CORE_SERVICE: False}

            def fake_systemctl(action: str, *units: str, **_kwargs: object) -> str:
                if action == "start" and recovery.CORE_SERVICE in units:
                    active_state[recovery.CORE_SERVICE] = True
                if action == "stop" and recovery.CORE_SERVICE in units:
                    active_state[recovery.CORE_SERVICE] = False
                return ""

            with mock.patch.object(recovery, "LOCAL_PROFILE_DROPIN", local_profile), mock.patch.object(
                recovery, "BACKUP_ROOT", root / "backups"
            ), mock.patch.object(recovery, "STATE_ROOT", root / "state"), mock.patch.object(
                recovery, "inspect_prestate", return_value=prestate
            ), mock.patch.object(recovery, "systemctl", side_effect=fake_systemctl), mock.patch.object(
                recovery, "active", side_effect=lambda unit: active_state.get(unit, True)
            ), mock.patch.object(recovery, "verify_strict_binding", return_value={}), mock.patch.object(
                recovery,
                "wait_stable",
                side_effect=recovery.RecoveryRejected("synthetic_start_failure"),
            ):
                ready = recovery.recover(
                    expected_plan_sha256=None,
                    preflight_only=True,
                )
                with self.assertRaises(recovery.RecoveryRejected):
                    recovery.recover(
                        expected_plan_sha256=str(ready["plan_sha256"]),
                        preflight_only=False,
                    )
            self.assertEqual(local_profile.read_bytes(), original)
            journals = list((root / "state").glob("JOURNAL-*.json"))
            self.assertEqual(len(journals), 1)
            self.assertEqual(
                json.loads(journals[0].read_text(encoding="utf-8"))["rollback"],
                "verified",
            )

    def test_rollback_failure_is_typed_and_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _dropins, _source, local_profile = self._fixture(root)
            prestate = {
                "core_active": False,
                "core_restarts": 54,
                "core_release": recovery.CORE_RELEASE,
                "local_profile_dropin_gid": local_profile.stat().st_gid,
                "local_profile_dropin_mode": 0o644,
                "local_profile_dropin_sha256": recovery.digest_file(local_profile),
                "selector_sha256": recovery.EXPECTED_SELECTOR_SHA256,
                "telegram_service_active": False,
                "telegram_socket_active": True,
            }
            with mock.patch.object(recovery, "LOCAL_PROFILE_DROPIN", local_profile), mock.patch.object(
                recovery, "BACKUP_ROOT", root / "backups"
            ), mock.patch.object(recovery, "STATE_ROOT", root / "state"), mock.patch.object(
                recovery, "inspect_prestate", return_value=prestate
            ), mock.patch.object(recovery, "systemctl", return_value=""), mock.patch.object(
                recovery, "verify_strict_binding", return_value={}
            ), mock.patch.object(
                recovery,
                "wait_stable",
                side_effect=recovery.RecoveryRejected("synthetic_start_failure"),
            ), mock.patch.object(
                recovery,
                "restore",
                side_effect=OSError("synthetic_rollback_failure"),
            ):
                ready = recovery.recover(
                    expected_plan_sha256=None,
                    preflight_only=True,
                )
                with self.assertRaises(recovery.RecoveryRejected) as captured:
                    recovery.recover(
                        expected_plan_sha256=str(ready["plan_sha256"]),
                        preflight_only=False,
                    )
            self.assertEqual(captured.exception.code, "recovery_rollback_rejected")
            journals = list((root / "state").glob("JOURNAL-*.json"))
            self.assertEqual(len(journals), 1)
            projection = json.loads(journals[0].read_text(encoding="utf-8"))
            self.assertEqual(projection["rollback"], "failed")
            self.assertEqual(projection["status"], "rollback_failed")
            self.assertNotIn("synthetic", journals[0].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
