from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.episodic_memory import (
    ArchivedContent,
    EpisodicMemoryError,
    LifecycleRecord,
    LosslessArchiveStore,
)

from tests.episodic_memory_fixtures import digest, make_turn


class LosslessArchiveTests(unittest.TestCase):
    def test_complete_turn_is_lossless_append_only_cross_epoch_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.sqlite3"
            store = LosslessArchiveStore(path)
            store.initialize()
            first = make_turn(
                1,
                "0" * 64,
                owner="Cealana建议去江边走走。",
                assistant="Myuna表示赞同并去换衣服。",
            )
            second = make_turn(
                2,
                first.turn_digest,
                owner="第二个 synthetic turn",
                assistant="跨 epoch 仍保留原文",
                epoch_id="synthetic-epoch-2",
                release="2" * 64,
            )
            self.assertEqual(store.append_complete_turn(first.draft), first)
            self.assertEqual(store.append_complete_turn(second.draft), second)
            self.assertEqual(store.append_complete_turn(second.draft), second)
            loaded = store.turns()
            self.assertEqual(loaded, (first, second))
            self.assertEqual(store.metadata()["turn_count"], 2)
            self.assertEqual(store.metadata()["head_digest"], second.turn_digest)
            connection = sqlite3.connect(path)
            try:
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("UPDATE complete_turns SET owner_text = 'rewrite'")
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("DELETE FROM complete_turns")
            finally:
                connection.close()

    def test_half_turn_failure_is_typed_but_never_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LosslessArchiveStore(Path(directory) / "archive.sqlite3")
            store.initialize()
            record = LifecycleRecord(
                lifecycle_id="failed-delivery-1",
                event_kind="delivery_failed",
                request_digest=digest("failed-request"),
                occurred_at_utc=datetime(2026, 8, 8, tzinfo=timezone.utc),
                reason_code="typed_delivery_failure",
                delivery_acknowledged=False,
                complete_turn_written=False,
            )
            store.append_lifecycle(record)
            store.append_lifecycle(record)
            self.assertEqual(store.metadata()["turn_count"], 0)
            self.assertEqual(store.metadata()["lifecycle_count"], 1)

    def test_crash_recovery_and_conflicting_replay_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LosslessArchiveStore(Path(directory) / "archive.sqlite3")
            store.initialize()
            turn = make_turn(1, "0" * 64)
            with self.assertRaisesRegex(EpisodicMemoryError, "archive_crash_before_commit"):
                store.append_complete_turn(turn.draft, crash_stage="before_commit")
            self.assertEqual(store.metadata()["turn_count"], 0)
            with self.assertRaisesRegex(EpisodicMemoryError, "archive_crash_after_commit"):
                store.append_complete_turn(turn.draft, crash_stage="after_commit")
            self.assertEqual(store.append_complete_turn(turn.draft), turn)
            conflict = replace(turn.draft, assistant=ArchivedContent("text", "different"))
            with self.assertRaisesRegex(EpisodicMemoryError, "archive_replay_conflict"):
                store.append_complete_turn(conflict)

    def test_image_archive_accepts_description_and_digest_not_bytes(self) -> None:
        description = ArchivedContent(
            "image_description",
            "Synthetic textual image description only.",
            digest("synthetic-image-identity"),
        )
        self.assertNotIn(b"image", description.text_digest.encode("ascii"))
        with self.assertRaisesRegex(EpisodicMemoryError, "image_identity_required"):
            ArchivedContent("image_description", "description")

    def test_sequence_gap_parent_drift_and_type_drift_reject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = LosslessArchiveStore(root / "archive.sqlite3")
            store.initialize()
            with self.assertRaisesRegex(EpisodicMemoryError, "archive_sequence_gap"):
                store.append_complete_turn(make_turn(2, "0" * 64).draft)
            wrong_parent = make_turn(1, "f" * 64)
            with self.assertRaisesRegex(EpisodicMemoryError, "archive_parent_digest_mismatch"):
                store.append_complete_turn(wrong_parent.draft)
            directory_path = root / "not-a-file"
            directory_path.mkdir()
            with self.assertRaisesRegex(EpisodicMemoryError, "archive_type_rejected"):
                LosslessArchiveStore(directory_path).initialize()

    def test_root_must_be_precreated_and_storage_contract_is_persist_full(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(EpisodicMemoryError, "archive_path_invalid"):
                LosslessArchiveStore(Path("relative.sqlite3"))
            absent = root / "absent" / "archive.sqlite3"
            with self.assertRaisesRegex(EpisodicMemoryError, "archive_root_absent"):
                LosslessArchiveStore(absent).initialize()
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "archive_root_identity_rejected",
            ):
                LosslessArchiveStore(
                    root / "wrong-owner.sqlite3",
                    expected_uid=os.geteuid() + 1,
                ).initialize()
            store = LosslessArchiveStore(root / "archive.sqlite3")
            store.initialize()
            projection = store.storage_projection()
            self.assertEqual(projection["journal_mode"], "persist")
            self.assertEqual(projection["synchronous"], 2)
            self.assertEqual(projection["uid"], os.geteuid())
            self.assertEqual(projection["gid"], os.getegid())
            self.assertEqual(projection["mode"], 0o600)

    def test_initialization_rollback_and_lost_return_converge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "archive.sqlite3"
            store = LosslessArchiveStore(path)
            with self.assertRaisesRegex(
                EpisodicMemoryError, "archive_initialization_before_commit"
            ):
                store.initialize(fault_stage="before_commit")
            self.assertFalse(path.exists())
            self.assertFalse(path.with_name(path.name + "-journal").exists())
            with self.assertRaisesRegex(
                EpisodicMemoryError, "archive_initialization_lost_return"
            ):
                store.initialize(fault_stage="after_commit_before_verification")
            self.assertTrue(path.exists())
            store.initialize()
            self.assertEqual(store.metadata()["turn_count"], 0)

    def test_partial_schema_and_symlink_substitution_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            partial = root / "partial.sqlite3"
            connection = sqlite3.connect(partial)
            connection.execute("CREATE TABLE partial(value TEXT)")
            connection.close()
            os.chmod(partial, 0o600)
            with self.assertRaisesRegex(EpisodicMemoryError, "archive_schema_rejected"):
                LosslessArchiveStore(partial).initialize()
            target = root / "target.sqlite3"
            target.write_bytes(b"synthetic")
            os.chmod(target, 0o600)
            link = root / "linked.sqlite3"
            link.symlink_to(target)
            with self.assertRaisesRegex(EpisodicMemoryError, "archive_type_rejected"):
                LosslessArchiveStore(link).initialize()
            real_ancestor = root / "real-ancestor"
            nested = real_ancestor / "nested"
            nested.mkdir(mode=0o700, parents=True)
            nested.chmod(0o700)
            linked_ancestor = root / "linked-ancestor"
            linked_ancestor.symlink_to(real_ancestor, target_is_directory=True)
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "archive_root_ancestry_rejected",
            ):
                LosslessArchiveStore(
                    linked_ancestor / "nested" / "archive.sqlite3"
                ).initialize()
            protected = root / "protected"
            protected.mkdir(mode=0o700)
            protected.chmod(0o700)
            protected_store = LosslessArchiveStore(protected / "archive.sqlite3")
            protected_store.initialize()
            sidecar = protected / "archive.sqlite3-journal"
            sidecar.unlink()
            sidecar.symlink_to(target)
            with self.assertRaisesRegex(
                EpisodicMemoryError,
                "archive_journal_type_rejected",
            ):
                protected_store.metadata()

    def test_connection_descriptor_is_specific_and_closed(self) -> None:
        from myuna_core.episodic_memory import store as store_module

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected_path = root / "expected.sqlite3"
            other_path = root / "other.sqlite3"
            expected = LosslessArchiveStore(expected_path)
            other = LosslessArchiveStore(other_path)
            expected.initialize()
            other.initialize()
            captured: list[int] = []
            original_descriptor = store_module._new_connection_descriptor

            def capture_descriptor(before, after, identity):
                descriptor = original_descriptor(before, after, identity)
                captured.append(descriptor)
                return descriptor

            with patch.object(
                store_module,
                "_new_connection_descriptor",
                side_effect=capture_descriptor,
            ):
                self.assertEqual(expected.metadata()["turn_count"], 0)
            self.assertEqual(len(captured), 1)
            with self.assertRaises(FileNotFoundError):
                os.stat(f"/proc/self/fd/{captured[0]}")

            held_expected = os.open(expected_path, os.O_RDONLY)
            original_connect = store_module.sqlite3.connect

            def connect_other(*args, **kwargs):
                return original_connect(other_path, *args[1:], **kwargs)

            try:
                with patch.object(
                    store_module.sqlite3,
                    "connect",
                    side_effect=connect_other,
                ), self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "archive_connection_identity_ambiguous",
                ):
                    expected.metadata()
            finally:
                os.close(held_expected)

            extra_descriptors: list[int] = []

            def connect_with_unrelated_descriptor(*args, **kwargs):
                connection = original_connect(*args, **kwargs)
                extra_descriptors.append(os.open(expected_path, os.O_RDONLY))
                return connection

            try:
                with patch.object(
                    store_module.sqlite3,
                    "connect",
                    side_effect=connect_with_unrelated_descriptor,
                ), self.assertRaisesRegex(
                    EpisodicMemoryError,
                    "archive_connection_identity_ambiguous",
                ):
                    expected.metadata()
            finally:
                for extra_descriptor in extra_descriptors:
                    os.close(extra_descriptor)

            replacement_path = root / "replacement.sqlite3"
            replacement = LosslessArchiveStore(replacement_path)
            replacement.initialize()
            displaced_path = root / "displaced.sqlite3"
            original_terminal = expected._verify_terminal

            def replace_before_terminal(connection, identity, descriptor):
                expected_path.rename(displaced_path)
                replacement_path.rename(expected_path)
                original_terminal(connection, identity, descriptor)

            with patch.object(
                expected,
                "_verify_terminal",
                side_effect=replace_before_terminal,
            ), self.assertRaisesRegex(
                EpisodicMemoryError,
                "archive_connection_identity_drifted",
            ):
                expected.metadata()


if __name__ == "__main__":
    unittest.main()
