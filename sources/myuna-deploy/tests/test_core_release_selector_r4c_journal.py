from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from core_release_selector_r4c_journal import (  # noqa: E402
    ACTIVATION_RECEIPT_SCHEMA,
    FileJournal,
    JournalError,
    canonical_json_bytes,
)


PLAN = "a" * 64
TREE = "b" * 64


class FileJournalTests(unittest.TestCase):
    def make_journal(self, root: Path) -> FileJournal:
        counter = iter(range(1, 100))
        return FileJournal(
            root,
            PLAN,
            TREE,
            clock_ns=lambda: next(counter),
        )

    def test_append_is_canonical_hash_chained_and_durable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = self.make_journal(Path(temporary).resolve())
            with journal.acquire():
                first = journal.append(
                    phase="prepared",
                    event="prestate_verified",
                    data={"safe": True},
                )
                second = journal.append(
                    phase="mutation_intent",
                    event="before_mutation",
                )
                records = journal.read_records()
            self.assertEqual(records, [first, second])
            self.assertEqual(
                second["previous_record_sha256"],
                first["record_sha256"],
            )
            raw_lines = journal.journal_path.read_bytes().splitlines()
            self.assertEqual(
                raw_lines,
                [canonical_json_bytes(item) for item in records],
            )

    def test_tampered_record_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = self.make_journal(Path(temporary).resolve())
            with journal.acquire():
                journal.append(phase="prepared", event="verified")
            document = json.loads(journal.journal_path.read_text())
            document["event"] = "tampered"
            journal.journal_path.write_bytes(canonical_json_bytes(document) + b"\n")
            with journal.acquire():
                with self.assertRaisesRegex(
                    JournalError,
                    "journal_record_integrity_rejected",
                ):
                    journal.read_records()

    def test_truncated_tail_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = self.make_journal(Path(temporary).resolve())
            with journal.acquire():
                journal.append(phase="prepared", event="verified")
            journal.journal_path.write_bytes(
                journal.journal_path.read_bytes().rstrip(b"\n")
            )
            with journal.acquire():
                with self.assertRaisesRegex(JournalError, "journal_truncated"):
                    journal.read_records()

    def test_second_writer_is_rejected_while_lock_is_held(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = self.make_journal(root)
            second = self.make_journal(root)
            with first.acquire():
                with self.assertRaisesRegex(JournalError, "journal_lock_busy"):
                    with second.acquire():
                        pass

    def test_receipt_is_idempotent_but_conflicts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = self.make_journal(Path(temporary).resolve())
            receipt = {
                "schema": ACTIVATION_RECEIPT_SCHEMA,
                "status": "core_release_selector_active",
                "plan_digest": PLAN,
                "transaction_tree_sha256": TREE,
            }
            with journal.acquire():
                first = journal.write_receipt(receipt)
                second = journal.write_receipt(receipt)
                self.assertEqual(first, second)
                self.assertEqual(journal.read_receipt(), receipt)
                changed = dict(receipt)
                changed["status"] = "changed"
                with self.assertRaisesRegex(
                    JournalError,
                    "activation_receipt_conflict",
                ):
                    journal.write_receipt(changed)

    def test_journal_methods_require_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = self.make_journal(Path(temporary).resolve())
            with self.assertRaisesRegex(JournalError, "journal_lock_required"):
                journal.read_records()
            with self.assertRaisesRegex(JournalError, "journal_lock_required"):
                journal.append(phase="prepared", event="no-lock")


if __name__ == "__main__":
    unittest.main()
