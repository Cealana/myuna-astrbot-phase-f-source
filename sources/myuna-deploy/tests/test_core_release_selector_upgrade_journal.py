from __future__ import annotations

import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest


CANDIDATE_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
FORMAL_SCRIPTS = Path("/srv/myuna/repos/deploy/scripts")
FORMAL_TESTS = Path("/srv/myuna/repos/deploy/tests")
sys.path[:0] = [str(CANDIDATE_SCRIPTS), str(FORMAL_SCRIPTS), str(FORMAL_TESTS)]

from core_release_selector_upgrade_executor import (  # noqa: E402
    FakeUpgradeBackend,
    JournaledUpgradeExecutor,
    UpgradeBundle,
)
from core_release_selector_upgrade_journal import (  # noqa: E402
    DurableJournalError,
    HashChainJournal,
    ZERO_HASH,
)
from test_core_release_selector_upgrade_executor import bundle_payloads  # noqa: E402


TX = "a" * 64


class DurableJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "journal-root"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_create_append_reopen_and_verify_chain(self) -> None:
        journal = HashChainJournal(self.root, TX, create=True)
        self.assertEqual(journal.head_hash, ZERO_HASH)
        journal.append("prepared", "exact_prestate_verified", {"safe": True})
        journal.append("files_applied", "target_files_applied")
        reopened = HashChainJournal(self.root, TX, create=False)
        self.assertEqual(len(reopened.records), 2)
        self.assertEqual(reopened.records[0]["phase"], "prepared")
        self.assertNotEqual(reopened.head_hash, ZERO_HASH)

    def test_modes_are_private(self) -> None:
        journal = HashChainJournal(self.root, TX, create=True)
        self.assertEqual(stat.S_IMODE(journal.transaction_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(journal.journal_path.stat().st_mode), 0o600)
        journal.write_receipt({"status": "synthetic"})
        self.assertEqual(stat.S_IMODE(journal.receipt_path.stat().st_mode), 0o400)

    def test_receipt_is_exclusive_and_bound_to_journal_head(self) -> None:
        journal = HashChainJournal(self.root, TX, create=True)
        journal.append("prepared", "exact_prestate_verified")
        journal.write_receipt({"status": "synthetic"})
        receipt = journal.verify_receipt()
        self.assertEqual(receipt["journal_head_before_receipt"], journal.head_hash)
        with self.assertRaises(DurableJournalError):
            journal.write_receipt({"status": "second"})

    def test_integrates_with_r2a_executor_and_reopens_cleanly(self) -> None:
        payloads, plan_digest = bundle_payloads()
        bundle = UpgradeBundle.load(payloads, approved_plan_digest=plan_digest)
        journal = HashChainJournal(self.root, TX, create=True)
        result = JournaledUpgradeExecutor(
            bundle=bundle,
            backend=FakeUpgradeBackend(),
            journal=journal,
        ).execute()
        self.assertEqual(result["status"], "activated")
        reopened = HashChainJournal(self.root, TX, create=False)
        self.assertEqual(reopened.records[-1]["phase"], "committed")
        receipt = reopened.verify_receipt()
        self.assertEqual(receipt["status"], "selected_release_upgraded")

    def test_payload_tamper_is_detected(self) -> None:
        journal = HashChainJournal(self.root, TX, create=True)
        journal.append("prepared", "exact_prestate_verified")
        record = json.loads(journal.journal_path.read_text(encoding="utf-8"))
        record["payload"]["event"] = "tampered"
        journal.journal_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        journal.journal_path.chmod(0o600)
        with self.assertRaises(DurableJournalError):
            HashChainJournal(self.root, TX, create=False)

    def test_truncated_or_invalid_record_is_detected(self) -> None:
        journal = HashChainJournal(self.root, TX, create=True)
        journal.journal_path.write_bytes(b'{"sequence":1')
        with self.assertRaises(DurableJournalError):
            HashChainJournal(self.root, TX, create=False)

    def test_symlink_journal_is_rejected(self) -> None:
        transaction = self.root / TX
        self.root.mkdir(mode=0o700)
        transaction.mkdir(mode=0o700)
        target = Path(self.temporary.name) / "target"
        target.write_bytes(b"")
        (transaction / "journal.jsonl").symlink_to(target)
        with self.assertRaises(DurableJournalError):
            HashChainJournal(self.root, TX, create=False)

    def test_noncanonical_transaction_id_is_rejected(self) -> None:
        with self.assertRaises(DurableJournalError):
            HashChainJournal(self.root, "not-a-digest", create=True)


if __name__ == "__main__":
    unittest.main()
