from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import stat
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
import external_epoch_bundle as bundle
import external_context_epoch as epoch
import telegram_owner_runtime_gateway as runtime


def _synthetic_epoch(path: Path) -> None:
    path.parent.mkdir(parents=True, mode=0o700)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE epoch_state (
                singleton INTEGER PRIMARY KEY,
                schema_name TEXT NOT NULL,
                schema_version INTEGER NOT NULL,
                epoch_id TEXT NOT NULL,
                selected_revision INTEGER NOT NULL,
                max_revision INTEGER NOT NULL
            );
            CREATE TABLE committed_turns (
                sequence INTEGER PRIMARY KEY,
                user_message TEXT NOT NULL,
                assistant_reply TEXT NOT NULL
            );
            CREATE TABLE committed_summaries (
                summary_version INTEGER PRIMARY KEY,
                content TEXT NOT NULL
            );
            CREATE TABLE pending_turns (
                event_id TEXT PRIMARY KEY,
                current_message TEXT NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO epoch_state VALUES (1, ?, 1, ?, 7, 7)",
            ("myuna.external-authorized-epoch.v1", activator.OLD_EPOCH_ID),
        )
        for sequence in range(1, 8):
            connection.execute(
                "INSERT INTO committed_turns VALUES (?, ?, ?)",
                (sequence, f"synthetic-user-{sequence}", f"synthetic-assistant-{sequence}"),
            )
        connection.commit()
    finally:
        connection.close()
    os.chmod(path.parent, 0o700)
    os.chmod(path, 0o600)


def _service_owned_bundle(database: Path, *, sidecars: bool) -> None:
    identity = pwd.getpwnam(activator.TELEGRAM_RUNTIME_USER)
    if sidecars:
        for suffix in ("-wal", "-shm"):
            path = Path(f"{database}{suffix}")
            path.write_bytes(f"synthetic{suffix}".encode())
            os.chmod(path, 0o600)
            os.chown(path, identity.pw_uid, identity.pw_gid)
    os.chown(database, identity.pw_uid, identity.pw_gid)
    os.chown(database.parent, identity.pw_uid, identity.pw_gid)


class SelectorContractTests(unittest.TestCase):
    def test_runtime_accepts_exact_selector(self) -> None:
        payload = activator.selector_payload("a" * 64)
        selection = runtime.ExternalEpochSelection.from_payload(payload)
        self.assertEqual(selection.epoch_id, activator.NEW_EPOCH_ID)
        self.assertEqual(selection.database_path, activator.NEW_EPOCH_DATABASE)
        self.assertEqual(selection.generation, 4)

    def test_runtime_rejects_unknown_field(self) -> None:
        payload = activator.selector_payload("a" * 64)
        payload["extra"] = "rejected"
        with self.assertRaises(runtime.RuntimeRejected):
            runtime.ExternalEpochSelection.from_payload(payload)

    def test_runtime_rejects_path_escape(self) -> None:
        payload = activator.selector_payload("a" * 64)
        payload["database_path"] = "/tmp/epoch.db"
        with self.assertRaises(runtime.RuntimeRejected):
            runtime.ExternalEpochSelection.from_payload(payload)

    def test_runtime_rejects_boolean_generation(self) -> None:
        payload = activator.selector_payload("a" * 64)
        payload["generation"] = True
        with self.assertRaises(runtime.RuntimeRejected):
            runtime.ExternalEpochSelection.from_payload(payload)

    def test_selector_is_deterministic_and_content_free(self) -> None:
        payload = activator.selector_payload("b" * 64)
        self.assertEqual(activator.validate_selector_payload(payload), payload)
        rendered = activator.canonical(payload)
        self.assertEqual(rendered, activator.canonical(payload))
        self.assertNotIn(b"message", rendered)
        self.assertNotIn(b"reply", rendered)
        self.assertNotIn(b"summary", rendered)


class EpochMetadataTests(unittest.TestCase):
    def test_metadata_projection_never_returns_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch" / "epoch.db"
            _synthetic_epoch(database)
            metadata = activator.inspect_epoch_metadata(database)
        self.assertEqual(metadata["turn_count"], 7)
        self.assertEqual(metadata["summary_count"], 0)
        self.assertEqual(metadata["pending_count"], 0)
        self.assertNotIn("user_message", metadata)
        self.assertNotIn("assistant_reply", metadata)
        self.assertNotIn("content", metadata)

    def test_expected_metadata_rejects_drift(self) -> None:
        metadata = {
            "epoch_id": activator.OLD_EPOCH_ID,
            "max_revision": 7,
            "pending_count": 0,
            "schema_name": "myuna.external-authorized-epoch.v1",
            "schema_version": 1,
            "selected_revision": 7,
            "summary_count": 0,
            "turn_count": 8,
        }
        with self.assertRaisesRegex(activator.RolloverRejected, "old_epoch_turn_count_rejected"):
            activator.require_expected_old_epoch(
                metadata,
                revision=7,
                turns=7,
                summaries=0,
                pending=0,
            )

    def test_empty_epoch_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch.db"
            binding = epoch.ExternalEpochBinding(
                channel_kind="astrbot_telegram",
                client_id="telegram-owner-private",
                principal_id="owner-synthetic",
                namespace_id="owner-synthetic-private",
            )
            epoch.ExternalEpochStore(
                database,
                epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=binding,
            )
            metadata = activator.inspect_empty_epoch(
                database,
                binding=binding,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
        self.assertEqual(
            metadata,
            {
                "initialized": True,
                "max_revision": 0,
                "pending_count": 0,
                "pending_summary_count": 0,
                "provenance_count": 0,
                "schema_name": epoch.SQLITE_SCHEMA,
                "schema_version": epoch.SQLITE_SCHEMA_VERSION,
                "selected_revision": 0,
                "summary_count": 0,
                "turn_count": 0,
            },
        )

    def test_offline_metadata_verifier_reads_retained_valid_wal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "epoch.db"
            archive = root / "archive" / "epoch.db"
            _synthetic_epoch(source)
            writer = sqlite3.connect(source)
            try:
                self.assertEqual(writer.execute("PRAGMA journal_mode = WAL").fetchone()[0], "wal")
                writer.execute("PRAGMA wal_autocheckpoint = 0")
                writer.execute(
                    "INSERT INTO committed_turns VALUES (8, ?, ?)",
                    ("synthetic-user-8", "synthetic-assistant-8"),
                )
                writer.commit()
                archive.parent.mkdir(mode=0o700)
                for suffix in ("", "-wal", "-shm"):
                    shutil.copy2(Path(f"{source}{suffix}"), Path(f"{archive}{suffix}"))
                    os.chmod(Path(f"{archive}{suffix}"), 0o600)
                metadata = activator.inspect_epoch_metadata(archive)
            finally:
                writer.close()
        self.assertEqual(metadata["turn_count"], 8)
        self.assertEqual(metadata["summary_count"], 0)
        self.assertEqual(metadata["pending_count"], 0)


class SealAndRollbackTests(unittest.TestCase):
    def test_main_only_and_complete_sidecar_bundles_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "old" / "epoch.db"
            _synthetic_epoch(database)
            digest = hashlib.sha256(database.read_bytes()).hexdigest()
            _service_owned_bundle(database, sidecars=False)
            with mock.patch.object(activator, "OLD_EPOCH_DATABASE", database):
                main_only = activator.validate_old_epoch_paths(digest)
            self.assertEqual(
                [entry["name"] for entry in main_only["bundle_projection"]["files"]],
                ["epoch.db"],
            )
            _service_owned_bundle(database, sidecars=True)
            with mock.patch.object(activator, "OLD_EPOCH_DATABASE", database):
                complete = activator.validate_old_epoch_paths(digest)
            self.assertEqual(
                [entry["name"] for entry in complete["bundle_projection"]["files"]],
                ["epoch.db", "epoch.db-shm", "epoch.db-wal"],
            )
            self.assertNotIn("user_message", json.dumps(complete))
            self.assertNotIn("assistant_reply", json.dumps(complete))

    def test_seal_is_byte_preserving_and_restore_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "old" / "epoch.db"
            _synthetic_epoch(database)
            _service_owned_bundle(database, sidecars=True)
            with mock.patch.object(activator, "OLD_EPOCH_DATABASE", database):
                prestate = activator.validate_old_epoch_paths(
                    hashlib.sha256(database.read_bytes()).hexdigest()
                )
                original = {
                    name: path.read_bytes()
                    for name, path in bundle.bundle_paths(database).items()
                }
                activator.seal_old_epoch(str(prestate["bundle_digest"]))
                for path in bundle.bundle_paths(database).values():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o440)
                self.assertEqual(stat.S_IMODE(database.parent.stat().st_mode), 0o550)
                activator.restore_old_epoch_permissions(
                    prestate,
                    expected_bundle_digest=str(prestate["bundle_digest"]),
                )
                for name, path in bundle.bundle_paths(database).items():
                    self.assertEqual(path.read_bytes(), original[name])
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(database.parent.stat().st_mode), 0o700)

    def test_partial_sidecar_fails_closed_before_seal(self) -> None:
        for suffix in ("-wal", "-shm"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                database = Path(temporary) / "old" / "epoch.db"
                _synthetic_epoch(database)
                _service_owned_bundle(database, sidecars=False)
                identity = pwd.getpwnam(activator.TELEGRAM_RUNTIME_USER)
                sidecar = Path(f"{database}{suffix}")
                sidecar.write_bytes(b"synthetic")
                os.chmod(sidecar, 0o600)
                os.chown(sidecar, identity.pw_uid, identity.pw_gid)
                with mock.patch.object(activator, "OLD_EPOCH_DATABASE", database):
                    with self.assertRaisesRegex(
                        bundle.ExternalEpochBundleRejected,
                        "bundle_partial_sidecar_rejected",
                    ):
                        activator.validate_old_epoch_paths(
                            hashlib.sha256(database.read_bytes()).hexdigest()
                        )
                self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)

    def test_permission_type_symlink_and_digest_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "old" / "epoch.db"
            _synthetic_epoch(database)
            _service_owned_bundle(database, sidecars=False)
            identity = pwd.getpwnam(activator.TELEGRAM_RUNTIME_USER)
            kwargs = {
                "expected_file_mode": 0o600,
                "expected_parent_mode": 0o700,
                "expected_uid": identity.pw_uid,
                "expected_gid": identity.pw_gid,
            }
            os.chmod(database, 0o640)
            with self.assertRaisesRegex(bundle.ExternalEpochBundleRejected, "bundle_file_permission_rejected"):
                bundle.inspect_epoch_bundle(database, **kwargs)
            os.chmod(database, 0o600)
            database.unlink()
            database.mkdir()
            with self.assertRaisesRegex(bundle.ExternalEpochBundleRejected, "bundle_file_type_rejected"):
                bundle.inspect_epoch_bundle(database, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "old" / "epoch.db"
            _synthetic_epoch(database)
            _service_owned_bundle(database, sidecars=False)
            original = database.parent / "original.db"
            database.rename(original)
            database.symlink_to(original)
            with self.assertRaisesRegex(bundle.ExternalEpochBundleRejected, "bundle_file_type_rejected"):
                bundle.inspect_epoch_bundle(database, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "old" / "epoch.db"
            _synthetic_epoch(database)
            _service_owned_bundle(database, sidecars=False)
            prestate = bundle.inspect_epoch_bundle(database, **kwargs)
            database.write_bytes(database.read_bytes() + b"drift")
            with self.assertRaisesRegex(bundle.ExternalEpochBundleRejected, "bundle_digest_drifted"):
                bundle.require_same_bundle(
                    prestate,
                    bundle.inspect_epoch_bundle(database, **kwargs),
                )
            with self.assertRaisesRegex(bundle.ExternalEpochBundleRejected, "bundle_digest_mismatch"):
                bundle.seal_epoch_bundle(
                    database,
                    expected_bundle_digest="0" * 64,
                    source_uid=identity.pw_uid,
                    source_gid=identity.pw_gid,
                    sealed_gid=identity.pw_gid,
                )

    def test_partial_seal_crash_is_exactly_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "old" / "epoch.db"
            _synthetic_epoch(database)
            _service_owned_bundle(database, sidecars=True)
            identity = pwd.getpwnam(activator.TELEGRAM_RUNTIME_USER)
            prestate = bundle.inspect_epoch_bundle(
                database,
                expected_file_mode=0o600,
                expected_parent_mode=0o700,
                expected_uid=identity.pw_uid,
                expected_gid=identity.pw_gid,
            )
            os.chown(database, 0, identity.pw_gid)
            os.chmod(database, 0o440)
            restored = bundle.restore_epoch_bundle_permissions(
                database,
                prestate=prestate,
                expected_bundle_digest=str(prestate["bundle_digest"]),
            )
            self.assertEqual(restored["bundle_digest"], prestate["bundle_digest"])
            for path in bundle.bundle_paths(database).values():
                self.assertEqual(path.stat().st_uid, identity.pw_uid)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_restore_reinstalls_selector_absence_and_dropin_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "old" / "epoch.db"
            _synthetic_epoch(database)
            _service_owned_bundle(database, sidecars=True)
            identity = pwd.getpwnam(activator.TELEGRAM_RUNTIME_USER)
            bundle_prestate = bundle.inspect_epoch_bundle(
                database,
                expected_file_mode=0o600,
                expected_parent_mode=0o700,
                expected_uid=identity.pw_uid,
                expected_gid=identity.pw_gid,
            )
            dropin = root / "runtime.conf"
            selector = root / "selector.json"
            old_dropin = b"old-runtime\n"
            dropin.write_bytes(b"new-runtime\n")
            selector.write_bytes(b"new-selector\n")
            for path in bundle.bundle_paths(database).values():
                os.chown(path, 0, identity.pw_gid)
                os.chmod(path, 0o440)
            os.chown(database.parent, 0, identity.pw_gid)
            os.chmod(database.parent, 0o550)
            prestate = {
                "old_epoch": bundle_prestate,
                "runtime_dropin_sha256": hashlib.sha256(old_dropin).hexdigest(),
                "runtime_release": "a" * 64,
            }
            with (
                mock.patch.object(activator, "OLD_EPOCH_DATABASE", database),
                mock.patch.object(activator, "TELEGRAM_DROPIN", dropin),
                mock.patch.object(activator, "SELECTOR_PATH", selector),
                mock.patch.object(activator, "stop_telegram"),
                mock.patch.object(activator, "start_telegram"),
                mock.patch.object(activator, "active", return_value=True),
                mock.patch.object(
                    activator,
                    "show",
                    return_value=f"/opt/myuna/context24-gateway/telegram/releases/{'a' * 64}/runtime/telegram_owner_runtime_gateway.py",
                ),
            ):
                activator.restore_prestate(
                    prestate,
                    old_dropin,
                    None,
                    bundle_prestate=bundle_prestate,
                    current_bundle_digest=str(bundle_prestate["bundle_digest"]),
                    restore_bundle_permissions_needed=True,
                )
            self.assertEqual(dropin.read_bytes(), old_dropin)
            self.assertFalse(selector.exists())
            for path in bundle.bundle_paths(database).values():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(database.parent.stat().st_mode), 0o700)


class PlanTests(unittest.TestCase):
    def test_live_prestate_requires_strict_credential_binding_first(self) -> None:
        with (
            mock.patch.object(activator, "active", return_value=True),
            mock.patch.object(
                activator,
                "verify_credential_binding",
                side_effect=activator.ActivationRejected(
                    "credential_category_rejected"
                ),
            ) as strict,
            mock.patch.object(activator, "verify_effective_credential") as effective,
        ):
            with self.assertRaises(activator.ActivationRejected) as captured:
                activator.verify_live_prestate(
                    expected_core_release="a" * 64,
                    expected_runtime_release="b" * 64,
                    expected_plugin_release="c" * 64,
                    expected_old_sha256="d" * 64,
                    revision=7,
                    turns=7,
                    summaries=0,
                    pending=0,
                )
        self.assertEqual(captured.exception.code, "credential_category_rejected")
        strict.assert_called_once_with()
        effective.assert_not_called()

    def test_plan_is_bounded_and_content_free(self) -> None:
        prestate = {
            "core_release": "c" * 64,
            "old_epoch": {
                "sha256": "d" * 64,
                "selected_revision": 7,
                "max_revision": 7,
                "turn_count": 7,
                "summary_count": 0,
                "pending_count": 0,
            },
            "plugin_release": "e" * 64,
            "runtime_dropin_sha256": "f" * 64,
            "runtime_release": "1" * 64,
            "telegram_service_restarts": 0,
            "telegram_socket_restarts": 0,
        }
        candidate = Path("/tmp") / ("2" * 64)
        plan = activator.build_plan(
            candidate,
            core_commit="3" * 40,
            deploy_commit="4" * 40,
            prestate=prestate,
        )
        payload = json.loads(plan)
        self.assertEqual(payload["schema"], activator.SCHEMA)
        self.assertFalse(payload["boundaries"]["legacy_session_migrated"])
        self.assertNotIn(b"synthetic-user", plan)
        self.assertNotIn(b"message_text", plan)
        self.assertNotIn(b"assistant_reply", plan)


if __name__ == "__main__":
    unittest.main()
