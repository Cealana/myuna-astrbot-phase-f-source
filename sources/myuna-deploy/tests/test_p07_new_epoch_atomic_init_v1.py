from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
CORE_SRC = ROOT.parent / "core" / "src"
for candidate in (SCRIPTS, CORE_SRC):
    if candidate.is_dir() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import activate_p07_external_epoch_rollover_v1 as activator
import external_context_epoch as epoch


def _binding(*, principal: str = "owner-synthetic") -> epoch.ExternalEpochBinding:
    return epoch.ExternalEpochBinding(
        channel_kind="astrbot_telegram",
        client_id="telegram-owner-private",
        principal_id=principal,
        namespace_id="owner-synthetic-private",
    )


def _strict_metadata(database: Path, binding: epoch.ExternalEpochBinding) -> dict[str, object]:
    return activator.inspect_empty_epoch(
        database,
        binding=binding,
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
    )


class AtomicInitializationTests(unittest.TestCase):
    def test_first_startup_initializes_schema_identity_and_zero_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch" / "epoch.db"
            binding = _binding()
            store = epoch.ExternalEpochStore(
                database,
                epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=binding,
            )
            self.assertEqual(
                store.public_metadata(),
                {
                    "initialized": True,
                    "max_revision": 0,
                    "pending_count": 0,
                    "pending_summary_count": 0,
                    "provenance_count": 0,
                    "schema": epoch.SQLITE_SCHEMA,
                    "selected_revision": 0,
                    "summary_count": 0,
                    "turn_count": 0,
                },
            )
            self.assertTrue(_strict_metadata(database, binding)["initialized"])

    def test_duplicate_startup_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch" / "epoch.db"
            binding = _binding()
            for _ in range(3):
                epoch.ExternalEpochStore(
                    database,
                    epoch_id=activator.NEW_EPOCH_ID,
                    startup_binding=binding,
                )
            self.assertEqual(_strict_metadata(database, binding)["max_revision"], 0)

    def test_concurrent_startup_serializes_to_one_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch" / "epoch.db"
            binding = _binding()
            barrier = threading.Barrier(4)

            def initialize() -> None:
                barrier.wait(timeout=5)
                epoch.ExternalEpochStore(
                    database,
                    epoch_id=activator.NEW_EPOCH_ID,
                    startup_binding=binding,
                )

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(initialize) for _ in range(4)]
                for future in futures:
                    future.result(timeout=15)
            self.assertEqual(_strict_metadata(database, binding)["turn_count"], 0)

    def test_uncommitted_partial_schema_is_rolled_back_then_initialized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch" / "epoch.db"
            database.parent.mkdir(mode=0o700)
            connection = sqlite3.connect(database)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE epoch_state (singleton INTEGER PRIMARY KEY)")
            connection.close()
            os.chmod(database, 0o600)
            binding = _binding()
            epoch.ExternalEpochStore(
                database,
                epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=binding,
            )
            self.assertTrue(_strict_metadata(database, binding)["initialized"])

    def test_committed_partial_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch" / "epoch.db"
            database.parent.mkdir(mode=0o700)
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE epoch_state (singleton INTEGER PRIMARY KEY)")
            connection.commit()
            connection.close()
            os.chmod(database, 0o600)
            with self.assertRaisesRegex(
                epoch.ExternalEpochRejected,
                "epoch_database_schema_rejected",
            ):
                epoch.ExternalEpochStore(
                    database,
                    epoch_id=activator.NEW_EPOCH_ID,
                    startup_binding=_binding(),
                )

    def test_wrong_version_and_identity_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch" / "epoch.db"
            binding = _binding()
            epoch.ExternalEpochStore(
                database,
                epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=binding,
            )
            connection = sqlite3.connect(database)
            connection.execute("PRAGMA user_version = 9")
            connection.close()
            with self.assertRaisesRegex(
                epoch.ExternalEpochRejected,
                "epoch_database_schema_version_rejected",
            ):
                epoch.ExternalEpochStore(
                    database,
                    epoch_id=activator.NEW_EPOCH_ID,
                    startup_binding=binding,
                )

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch" / "epoch.db"
            epoch.ExternalEpochStore(
                database,
                epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=_binding(),
            )
            with self.assertRaisesRegex(
                epoch.ExternalEpochRejected,
                "epoch_state_binding_mismatch",
            ):
                epoch.ExternalEpochStore(
                    database,
                    epoch_id=activator.NEW_EPOCH_ID,
                    startup_binding=_binding(principal="other-synthetic-owner"),
                )


class StrictMetadataTests(unittest.TestCase):
    def test_wal_aware_query_only_verifier_sees_committed_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch.db"
            binding = _binding()
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0], "wal")
                connection.execute("PRAGMA wal_autocheckpoint = 0")
                connection.execute("BEGIN IMMEDIATE")
                for definition in epoch._TABLE_DEFINITIONS:
                    connection.execute(definition)
                connection.execute(f"PRAGMA user_version = {epoch.SQLITE_SCHEMA_VERSION}")
                now = "2026-08-04T00:00:00.000000+00:00"
                connection.execute(
                    "INSERT INTO epoch_state VALUES (1,?,?,?,?,?,?,0,0,0,?,?)",
                    (
                        epoch.SQLITE_SCHEMA,
                        epoch.SQLITE_SCHEMA_VERSION,
                        activator.NEW_EPOCH_ID,
                        binding.channel_kind,
                        binding.principal_id,
                        binding.namespace_id,
                        epoch.ZERO_DIGEST,
                        now,
                    ),
                )
                connection.execute(
                    "INSERT INTO epoch_revisions VALUES (0,0,?,NULL,?)",
                    (epoch.ZERO_DIGEST, now),
                )
                connection.commit()
                for path in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
                    self.assertTrue(path.exists())
                    os.chmod(path, 0o600)
                immutable = sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)
                try:
                    with self.assertRaises(sqlite3.OperationalError):
                        immutable.execute("SELECT COUNT(*) FROM epoch_state").fetchone()
                finally:
                    immutable.close()
                self.assertTrue(_strict_metadata(database, binding)["initialized"])
            finally:
                connection.close()

    def test_partial_sidecar_permission_owner_and_symlink_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch.db"
            binding = _binding()
            epoch.ExternalEpochStore(
                database,
                epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=binding,
            )
            Path(f"{database}-wal").write_bytes(b"synthetic-partial")
            os.chmod(Path(f"{database}-wal"), 0o600)
            with self.assertRaisesRegex(activator.RolloverRejected, "partial_sidecar"):
                _strict_metadata(database, binding)

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch.db"
            binding = _binding()
            epoch.ExternalEpochStore(
                database,
                epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=binding,
            )
            os.chmod(database, 0o640)
            with self.assertRaisesRegex(activator.RolloverRejected, "metadata_rejected"):
                _strict_metadata(database, binding)

        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target.db"
            target.write_bytes(b"synthetic")
            database = Path(temporary) / "epoch.db"
            database.symlink_to(target)
            with self.assertRaisesRegex(activator.RolloverRejected, "epoch_type_rejected"):
                _strict_metadata(database, _binding())

    def test_unknown_partial_and_corrupt_database_are_never_empty(self) -> None:
        for kind in ("partial", "corrupt"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                database = Path(temporary) / "epoch.db"
                if kind == "partial":
                    connection = sqlite3.connect(database)
                    connection.execute("CREATE TABLE unknown_table (id INTEGER PRIMARY KEY)")
                    connection.commit()
                    connection.close()
                else:
                    database.write_bytes(b"not-a-sqlite-database")
                os.chmod(database, 0o600)
                with self.assertRaises(Exception):
                    _strict_metadata(database, _binding())

    def test_exact_owner_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "epoch.db"
            binding = _binding()
            epoch.ExternalEpochStore(
                database,
                epoch_id=activator.NEW_EPOCH_ID,
                startup_binding=binding,
            )
            with self.assertRaisesRegex(activator.RolloverRejected, "metadata_rejected"):
                activator.inspect_empty_epoch(
                    database,
                    binding=binding,
                    expected_uid=os.geteuid() + 1,
                    expected_gid=os.getegid(),
                )


if __name__ == "__main__":
    unittest.main()
