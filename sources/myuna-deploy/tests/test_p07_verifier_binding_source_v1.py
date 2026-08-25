from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
CORE_SRC = ROOT.parent / "core" / "src"
for candidate in (SCRIPTS, CORE_SRC):
    if candidate.is_dir() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import activate_p07_external_epoch_rollover_v1 as activator
import external_context_epoch as epoch
import telegram_owner_runtime_gateway as runtime
import telegram_runtime_config as contract


def _payload(*, principal_id: str = "owner-synthetic") -> dict[str, object]:
    return {
        "binding_id": "binding-synthetic",
        "channel_kind": "astrbot_telegram",
        "channel_instance": "telegram-synthetic",
        "core_host": "127.0.0.1",
        "core_port": 48080,
        "evidence_sha256": "a" * 64,
        "finalization_digest": "b" * 64,
        "max_history_characters": 16000,
        "max_history_messages": 128,
        "max_requests_per_ten_minutes": 20,
        "namespace_id": "owner-synthetic-private",
        "principal_id": principal_id,
    }


def _write_config(
    path: Path,
    *,
    payload: dict[str, object] | None = None,
    raw: bytes | None = None,
    mode: int = 0o640,
) -> None:
    path.write_bytes(
        raw
        if raw is not None
        else json.dumps(payload or _payload(), sort_keys=True).encode("utf-8")
    )
    os.chmod(path, mode)


def _snapshot(path: Path) -> contract.ProtectedRuntimeConfigSnapshot:
    return contract.parse_protected_runtime_config_snapshot(
        path,
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
        expected_mode=0o640,
    )


class SharedContractTests(unittest.TestCase):
    def test_runtime_and_activator_use_one_contract_module(self) -> None:
        self.assertIs(runtime.RuntimeConfig, contract.RuntimeConfig)
        runtime_source = inspect.getsource(runtime.main)
        target_source = inspect.getsource(activator.verify_target)
        smoke_source = inspect.getsource(activator.verify_new_epoch_startup_smoke)
        self.assertIn(
            "runtime_config_contract.load_protected_runtime_config_snapshot()",
            runtime_source,
        )
        self.assertIn(
            "runtime_config_contract.external_epoch_binding_from_runtime_config",
            runtime_source,
        )
        self.assertIn("verify_empty_epoch_from_runtime_config", target_source)
        self.assertNotIn("config.get(\"principal_id\")", target_source)
        self.assertIn("verify_empty_epoch_from_runtime_config", smoke_source)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", smoke_source)
        self.assertIn("PYTHONPATH=", smoke_source)

    def test_resume_config_cannot_become_or_conflict_with_binding_source(self) -> None:
        activator.require_resume_config_not_binding_source(
            {"gateway_release": "a" * 64, "schema": "synthetic"}
        )
        for key in ("channel_kind", "principal_id", "namespace_id"):
            with self.subTest(key=key), self.assertRaisesRegex(
                activator.RolloverRejected,
                "runtime_config_conflicting_source_rejected",
            ):
                activator.require_resume_config_not_binding_source(
                    {"gateway_release": "a" * 64, key: "conflict"}
                )

    def test_missing_wrong_source_duplicate_permission_type_and_symlink_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / "missing.json"
            with self.assertRaises(contract.RuntimeConfigRejected):
                _snapshot(missing)

            wrong_source = root / "resume.json"
            _write_config(wrong_source, payload={"gateway_release": "a" * 64})
            with self.assertRaises(contract.RuntimeConfigRejected):
                _snapshot(wrong_source)

            duplicate = root / "duplicate.json"
            duplicate_raw = json.dumps(_payload(), sort_keys=True)[:-1]
            duplicate_raw += ',"principal_id":"duplicate"}'
            _write_config(duplicate, raw=duplicate_raw.encode("utf-8"))
            with self.assertRaises(contract.RuntimeConfigRejected):
                _snapshot(duplicate)

            wrong_mode = root / "wrong-mode.json"
            _write_config(wrong_mode, mode=0o600)
            with self.assertRaises(contract.RuntimeConfigRejected):
                _snapshot(wrong_mode)

            wrong_owner = root / "wrong-owner.json"
            _write_config(wrong_owner)
            os.chown(wrong_owner, os.geteuid() + 1, os.getegid())
            with self.assertRaises(contract.RuntimeConfigRejected):
                _snapshot(wrong_owner)

            directory = root / "directory.json"
            directory.mkdir()
            with self.assertRaises(contract.RuntimeConfigRejected):
                _snapshot(directory)

            target = root / "target.json"
            _write_config(target)
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(contract.RuntimeConfigRejected):
                _snapshot(link)

    def test_exact_failed_gate_red_then_shared_protected_source_green(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "owner-runtime-v1.json"
            _write_config(config_path)
            snapshot = _snapshot(config_path)
            binding = contract.external_epoch_binding_from_runtime_config(
                snapshot.config
            )
            database = root / "epoch.db"
            epoch.ExternalEpochStore(
                database,
                epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=binding,
            )
            resume_payload: dict[str, object] = {"gateway_release": "a" * 64}
            with self.assertRaisesRegex(
                epoch.ExternalEpochRejected,
                "epoch_binding_scope_rejected",
            ):
                epoch.ExternalEpochBinding(
                    channel_kind=str(resume_payload.get("channel_kind")),
                    client_id="telegram-owner-private",
                    principal_id=str(resume_payload.get("principal_id")),
                    namespace_id=str(resume_payload.get("namespace_id")),
                )
            accepted = activator.verify_empty_epoch_from_runtime_config(
                database,
                expected_config_projection=snapshot.projection(),
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                snapshot_loader=lambda: _snapshot(config_path),
            )
            self.assertTrue(accepted["initialized"])

    def test_identity_and_snapshot_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_path = root / "first.json"
            second_path = root / "second.json"
            _write_config(first_path)
            _write_config(second_path, payload=_payload(principal_id="owner-other"))
            first = _snapshot(first_path)
            second = _snapshot(second_path)
            database = root / "epoch.db"
            epoch.ExternalEpochStore(
                database,
                epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=contract.external_epoch_binding_from_runtime_config(
                    first.config
                ),
            )
            snapshots = iter((first, second))
            with self.assertRaisesRegex(
                activator.RolloverRejected,
                "runtime_config_changed_during_verification",
            ):
                activator.verify_empty_epoch_from_runtime_config(
                    database,
                    expected_config_projection=first.projection(),
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                    snapshot_loader=lambda: next(snapshots),
                )
            with self.assertRaisesRegex(
                activator.RolloverRejected,
                "runtime_config_snapshot_drifted",
            ):
                activator.verify_empty_epoch_from_runtime_config(
                    database,
                    expected_config_projection=second.projection(),
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                    snapshot_loader=lambda: first,
                )

    def test_target_loader_maps_protected_parser_failure_to_content_free_gate(self) -> None:
        with mock.patch.object(
            contract,
            "load_protected_runtime_config_snapshot",
            side_effect=contract.RuntimeConfigRejected("private detail suppressed"),
        ):
            with self.assertRaisesRegex(
                activator.RolloverRejected,
                "runtime_config_source_rejected",
            ):
                activator.load_target_runtime_config_snapshot()


if __name__ == "__main__":
    unittest.main()
