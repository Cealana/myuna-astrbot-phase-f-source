from __future__ import annotations

from pathlib import Path
import os
import pwd
import sqlite3
import subprocess
import tempfile
import unittest

import myuna_core

from external_context_epoch_v3 import (
    ExternalEpochV3Binding,
    ExternalEpochV3Store,
)

from p07_d_runtime_readiness import (
    RuntimeProcessObservation,
    RuntimeReadinessRejected,
    content_free_metadata_digest,
    inspect_runtime_readiness,
    publish_runtime_readiness,
    readiness_path,
    wait_for_runtime_readiness,
)


RID = "a" * 64
SELECTOR = "b" * 64
CONFIG = "c" * 64
INVOCATION = "d" * 32
EPOCH = "telegram-owner-private-external-d-reset-v3"


def metadata() -> dict[str, object]:
    return {
        "abandoned_delivery_count": 0,
        "blocked_summary_count": 0,
        "delivered_intent_count": 0,
        "epoch_id": EPOCH,
        "max_revision": 0,
        "pending_count": 0,
        "queued_summary_count": 0,
        "release_set_id": RID,
        "schema": "myuna.external-authorized-epoch.v3",
        "selected_revision": 0,
        "summary_count": 0,
        "turn_count": 0,
    }


class RuntimeReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "epoch" / "epoch.db"
        self.database.parent.mkdir(mode=0o700)
        self.database.parent.chmod(0o700)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def publish(self, *, invocation: str = INVOCATION, pid: int = 1234):
        return publish_runtime_readiness(
            self.database,
            generation=9,
            release_set_id=RID,
            epoch_id=EPOCH,
            selector_digest=SELECTOR,
            runtime_config_digest=CONFIG,
            epoch_metadata=metadata(),
            invocation_id=invocation,
            pid=pid,
        )

    def inspect(self):
        return inspect_runtime_readiness(
            readiness_path(self.database),
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
            expected_generation=9,
            expected_release_set_id=RID,
            expected_epoch_id=EPOCH,
            expected_database_path=self.database.as_posix(),
            expected_selector_digest=SELECTOR,
            expected_runtime_config_digest=CONFIG,
        )

    def test_atomic_canonical_receipt_is_content_free_and_idempotent(self) -> None:
        first = self.publish()
        second = self.publish()
        self.assertEqual(first, second)
        self.assertEqual(self.inspect(), first)
        raw = readiness_path(self.database).read_text("ascii")
        self.assertNotIn("message", raw)
        self.assertNotIn("assistant", raw)
        self.assertEqual(first.epoch_metadata_digest, content_free_metadata_digest(metadata()))

    def test_new_invocation_replaces_stale_receipt_but_wrong_binding_fails_closed(self) -> None:
        self.publish()
        replacement = self.publish(invocation="e" * 32, pid=2345)
        self.assertEqual(self.inspect(), replacement)
        with self.assertRaisesRegex(RuntimeReadinessRejected, "binding_rejected"):
            inspect_runtime_readiness(
                readiness_path(self.database),
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                expected_generation=9,
                expected_release_set_id="f" * 64,
                expected_epoch_id=EPOCH,
                expected_database_path=self.database.as_posix(),
                expected_selector_digest=SELECTOR,
                expected_runtime_config_digest=CONFIG,
            )

    def test_absent_partial_symlink_and_permission_drift_are_typed(self) -> None:
        with self.assertRaisesRegex(RuntimeReadinessRejected, "readiness_absent"):
            self.inspect()
        target = readiness_path(self.database)
        target.write_text("{", encoding="ascii")
        target.chmod(0o600)
        with self.assertRaisesRegex(RuntimeReadinessRejected, "document_rejected"):
            self.inspect()
        target.unlink()
        target.symlink_to(self.database)
        with self.assertRaisesRegex(RuntimeReadinessRejected, "type_rejected"):
            self.inspect()
        target.unlink()
        self.publish()
        target.chmod(0o640)
        with self.assertRaisesRegex(RuntimeReadinessRejected, "permission_rejected"):
            self.inspect()

    def test_wait_rejects_service_failure_and_process_drift(self) -> None:
        failed = RuntimeProcessObservation("failed", "failed", "exit-code", 0, 0, "")
        with self.assertRaisesRegex(RuntimeReadinessRejected, "startup_failed_before_readiness"):
            wait_for_runtime_readiness(
                path=readiness_path(self.database),
                expected_uid=os.getuid(), expected_gid=os.getgid(),
                expected_generation=9, expected_release_set_id=RID,
                expected_epoch_id=EPOCH, expected_database_path=self.database.as_posix(),
                expected_selector_digest=SELECTOR, expected_runtime_config_digest=CONFIG,
                observe_process=lambda: failed, timeout_seconds=1, stable_seconds=0,
            )

        self.publish(pid=1234)
        observations = iter((
            RuntimeProcessObservation("active", "running", "success", 0, 1234, INVOCATION),
            RuntimeProcessObservation("active", "running", "success", 0, 2222, INVOCATION),
        ))
        with self.assertRaisesRegex(RuntimeReadinessRejected, "not_stable"):
            wait_for_runtime_readiness(
                path=readiness_path(self.database),
                expected_uid=os.getuid(), expected_gid=os.getgid(),
                expected_generation=9, expected_release_set_id=RID,
                expected_epoch_id=EPOCH, expected_database_path=self.database.as_posix(),
                expected_selector_digest=SELECTOR, expected_runtime_config_digest=CONFIG,
                observe_process=lambda: next(observations), timeout_seconds=1,
                stable_seconds=0, sleep=lambda _seconds: None,
            )

    def test_wait_accepts_only_matching_stable_process_receipt(self) -> None:
        self.publish(pid=1234)
        process = RuntimeProcessObservation("active", "running", "success", 0, 1234, INVOCATION)
        receipt = wait_for_runtime_readiness(
            path=readiness_path(self.database),
            expected_uid=os.getuid(), expected_gid=os.getgid(),
            expected_generation=9, expected_release_set_id=RID,
            expected_epoch_id=EPOCH, expected_database_path=self.database.as_posix(),
            expected_selector_digest=SELECTOR, expected_runtime_config_digest=CONFIG,
            observe_process=lambda: process, timeout_seconds=1,
            stable_seconds=0, sleep=lambda _seconds: None,
        )
        self.assertEqual(receipt.pid, 1234)

    def test_receipt_follows_wal_visible_query_only_metadata(self) -> None:
        store = ExternalEpochV3Store(
            self.database,
            epoch_id=EPOCH,
            release_set_id=RID,
            binding=ExternalEpochV3Binding(
                channel_kind="astrbot_telegram",
                client_id="telegram-owner-private",
                principal_id="principal-synthetic-owner",
                namespace_id="namespace-synthetic-owner",
            ),
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE epoch_state SET updated_at=updated_at WHERE singleton=1")
            connection.execute("COMMIT")
            self.assertTrue(Path(f"{self.database}-wal").is_file())
            self.assertTrue(Path(f"{self.database}-shm").is_file())
            observed = store.public_metadata()
            receipt = publish_runtime_readiness(
                self.database,
                generation=9,
                release_set_id=RID,
                epoch_id=EPOCH,
                selector_digest=SELECTOR,
                runtime_config_digest=CONFIG,
                epoch_metadata=observed,
                invocation_id=INVOCATION,
                pid=1234,
            )
        self.assertEqual(receipt.epoch_metadata_digest, content_free_metadata_digest(observed))

    @unittest.skipUnless(os.geteuid() == 0, "exact service identity requires root test runner")
    def test_exact_service_uid_gid_initializes_schema_before_readiness_receipt(self) -> None:
        identity = pwd.getpwnam("myuna-gateway-telegram")
        os.chown(self.temp.name, identity.pw_uid, identity.pw_gid)
        os.chown(self.database.parent, identity.pw_uid, identity.pw_gid)
        scripts = Path(__file__).resolve().parents[1] / "scripts"
        core_src = Path(myuna_core.__file__).resolve().parents[1]
        program = f"""
import os
from external_context_epoch_v3 import ExternalEpochV3Binding, ExternalEpochV3Store
from p07_d_runtime_readiness import publish_runtime_readiness
database = {self.database.as_posix()!r}
binding = ExternalEpochV3Binding(channel_kind='astrbot_telegram', client_id='telegram-owner-private', principal_id='principal-synthetic-owner', namespace_id='namespace-synthetic-owner')
store = ExternalEpochV3Store(database, epoch_id={EPOCH!r}, release_set_id={RID!r}, binding=binding)
store.startup_recover()
publish_runtime_readiness(database, generation=9, release_set_id={RID!r}, epoch_id={EPOCH!r}, selector_digest={SELECTOR!r}, runtime_config_digest={CONFIG!r}, epoch_metadata=store.public_metadata(), invocation_id={INVOCATION!r}, pid=os.getpid())
"""
        completed = subprocess.run(
            [
                "/usr/sbin/runuser", "-u", identity.pw_name, "--",
                "/usr/bin/env", "-i", "PATH=/usr/bin",
                f"PYTHONPATH={scripts}:{core_src}", "PYTHONDONTWRITEBYTECODE=1",
                "/usr/bin/python3", "-B", "-c", program,
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace")[:200])
        receipt = inspect_runtime_readiness(
            readiness_path(self.database),
            expected_uid=identity.pw_uid,
            expected_gid=identity.pw_gid,
            expected_generation=9,
            expected_release_set_id=RID,
            expected_epoch_id=EPOCH,
            expected_database_path=self.database.as_posix(),
            expected_selector_digest=SELECTOR,
            expected_runtime_config_digest=CONFIG,
        )
        self.assertEqual(receipt.epoch_metadata_digest, content_free_metadata_digest(metadata()))


if __name__ == "__main__":
    unittest.main()
