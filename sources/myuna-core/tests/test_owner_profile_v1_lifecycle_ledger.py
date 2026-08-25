from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.owner_profile.lifecycle import (
    LifecycleEvent,
    LifecycleState,
    OwnerProfileLifecycleError,
)
from myuna_core.owner_profile.lifecycle_ledger import (
    append_lifecycle_event,
    initialize_lifecycle_ledger,
    load_lifecycle_ledger,
)


PROFILE_ID = "synthetic-ledger-profile"


def baseline_event(state: LifecycleState) -> LifecycleEvent:
    return LifecycleEvent(
        event_type="baseline_registered",
        event_id="event-baseline-synthetic",
        sequence=1,
        previous_event_sha256=state.last_event_sha256,
        profile_id=PROFILE_ID,
        base_revision=None,
        base_sha256=None,
        target_revision=2,
        target_sha256="2" * 64,
        confirmation_sha256="a" * 64,
        reason_category="initial_registration",
    )


def candidate_event(state: LifecycleState) -> LifecycleEvent:
    return LifecycleEvent(
        event_type="candidate_prepared",
        event_id="event-candidate-synthetic",
        sequence=state.last_sequence + 1,
        previous_event_sha256=state.last_event_sha256,
        profile_id=PROFILE_ID,
        base_revision=2,
        base_sha256="2" * 64,
        target_revision=3,
        target_sha256="3" * 64,
        confirmation_sha256=None,
        reason_category="owner_authored_revision",
    )


class OwnerProfileLifecycleLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "ledger"
        initialize_lifecycle_ledger(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def load(self) -> LifecycleState:
        return load_lifecycle_ledger(self.root, profile_id=PROFILE_ID)

    def test_atomic_append_replay_and_exact_retry_are_deterministic(self) -> None:
        empty = self.load()
        baseline = baseline_event(empty)
        registered = append_lifecycle_event(self.root, baseline)
        retried = append_lifecycle_event(self.root, baseline)
        self.assertEqual(retried, registered)

        candidate = candidate_event(registered)
        prepared = append_lifecycle_event(self.root, candidate)
        self.assertEqual(prepared.revisions[3].status, "prepared")
        self.assertEqual(self.load(), prepared)

        files = sorted(self.root.iterdir())
        self.assertEqual(len(files), 2)
        for path in files:
            metadata = path.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.root.lstat().st_mode), 0o700)

    def test_event_content_tamper_fails_closed(self) -> None:
        baseline = baseline_event(self.load())
        append_lifecycle_event(self.root, baseline)
        event_file = next(self.root.iterdir())
        event_file.write_bytes(b"{}\n")
        with self.assertRaisesRegex(OwnerProfileLifecycleError, "invalid_event"):
            self.load()

    def test_filename_digest_or_sequence_tamper_fails_closed(self) -> None:
        baseline = baseline_event(self.load())
        payload = baseline.canonical_bytes()
        wrong_name = self.root / f"000002-{'9' * 64}.json"
        wrong_name.write_bytes(payload)
        os.chmod(wrong_name, 0o600)
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError, "event_chain_rejected"
        ):
            self.load()

    def test_unexpected_file_symlink_and_permission_drift_fail_closed(self) -> None:
        cases: list[tuple[str, object]] = []

        unexpected = self.root / "unexpected.txt"
        unexpected.write_text("synthetic", encoding="utf-8")
        os.chmod(unexpected, 0o600)
        cases.append(("unexpected", unexpected))
        with self.subTest(case="unexpected"), self.assertRaisesRegex(
            OwnerProfileLifecycleError, "lifecycle_permission_drift"
        ):
            self.load()
        unexpected.unlink()

        link = self.root / f"000001-{'1' * 64}.json"
        link.symlink_to(self.root / "missing")
        cases.append(("symlink", link))
        with self.subTest(case="symlink"), self.assertRaisesRegex(
            OwnerProfileLifecycleError, "lifecycle_permission_drift"
        ):
            self.load()
        link.unlink()

        baseline = baseline_event(self.load())
        append_lifecycle_event(self.root, baseline)
        event_file = next(self.root.iterdir())
        os.chmod(event_file, 0o640)
        cases.append(("file_mode", event_file))
        with self.subTest(case="file_mode"), self.assertRaisesRegex(
            OwnerProfileLifecycleError, "lifecycle_permission_drift"
        ):
            self.load()
        os.chmod(event_file, 0o600)

        os.chmod(self.root, 0o750)
        cases.append(("directory_mode", self.root))
        with self.subTest(case="directory_mode"), self.assertRaisesRegex(
            OwnerProfileLifecycleError, "lifecycle_permission_drift"
        ):
            self.load()
        self.assertEqual(len(cases), 4)
        os.chmod(self.root, 0o700)

    def test_symlinked_ledger_root_is_rejected(self) -> None:
        real = Path(self.temporary.name) / "real-ledger"
        initialize_lifecycle_ledger(real)
        linked = Path(self.temporary.name) / "linked-ledger"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError, "lifecycle_permission_drift"
        ):
            load_lifecycle_ledger(linked, profile_id=PROFILE_ID)

    def test_chain_drift_rejects_append_without_creating_file(self) -> None:
        baseline = baseline_event(self.load())
        registered = append_lifecycle_event(self.root, baseline)
        candidate = candidate_event(registered)
        drifted = LifecycleEvent(
            event_type=candidate.event_type,
            event_id=candidate.event_id,
            sequence=candidate.sequence,
            previous_event_sha256="9" * 64,
            profile_id=candidate.profile_id,
            base_revision=candidate.base_revision,
            base_sha256=candidate.base_sha256,
            target_revision=candidate.target_revision,
            target_sha256=candidate.target_sha256,
            confirmation_sha256=candidate.confirmation_sha256,
            reason_category=candidate.reason_category,
        )
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError, "event_chain_rejected"
        ):
            append_lifecycle_event(self.root, drifted)
        self.assertEqual(len(tuple(self.root.iterdir())), 1)

    def test_concurrent_same_sequence_has_one_winner_and_valid_replay(self) -> None:
        empty = self.load()
        first = baseline_event(empty)
        second = LifecycleEvent(
            event_type="baseline_registered",
            event_id="event-baseline-competing",
            sequence=1,
            previous_event_sha256=empty.last_event_sha256,
            profile_id=PROFILE_ID,
            base_revision=None,
            base_sha256=None,
            target_revision=2,
            target_sha256="3" * 64,
            confirmation_sha256="b" * 64,
            reason_category="initial_registration",
        )

        def append(candidate: LifecycleEvent) -> str:
            try:
                append_lifecycle_event(self.root, candidate)
            except OwnerProfileLifecycleError as exc:
                return exc.code
            return "accepted"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(append, (first, second)))
        self.assertEqual(sorted(outcomes), ["accepted", "event_chain_rejected"])
        state = self.load()
        self.assertEqual(state.last_sequence, 1)
        self.assertEqual(state.active_revision, 2)
        self.assertIn(state.revisions[2].profile_sha256, {"2" * 64, "3" * 64})
        self.assertEqual(len(tuple(self.root.iterdir())), 1)

    def test_exact_pending_event_is_recovered_and_published(self) -> None:
        baseline = baseline_event(self.load())
        filename = f"000001-{baseline.sha256}.json"
        pending = self.root / f".pending-{filename}"
        pending.write_bytes(baseline.canonical_bytes())
        os.chmod(pending, 0o600)

        state = append_lifecycle_event(self.root, baseline)

        final = self.root / filename
        self.assertEqual(state.last_sequence, 1)
        self.assertTrue(final.is_file())
        self.assertFalse(pending.exists())
        self.assertEqual(self.load(), state)

    def test_linked_pending_event_is_recovered_after_publish_crash(self) -> None:
        baseline = baseline_event(self.load())
        filename = f"000001-{baseline.sha256}.json"
        pending = self.root / f".pending-{filename}"
        final = self.root / filename
        pending.write_bytes(baseline.canonical_bytes())
        os.chmod(pending, 0o600)
        os.link(pending, final)
        self.assertEqual(final.stat().st_nlink, 2)

        state = append_lifecycle_event(self.root, baseline)

        self.assertEqual(state.last_sequence, 1)
        self.assertFalse(pending.exists())
        self.assertEqual(final.stat().st_nlink, 1)
        self.assertEqual(self.load(), state)

    def test_unrelated_pending_event_requires_explicit_recovery(self) -> None:
        baseline = baseline_event(self.load())
        unrelated = self.root / f".pending-000001-{'9' * 64}.json"
        unrelated.write_bytes(baseline.canonical_bytes())
        os.chmod(unrelated, 0o600)

        with self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "lifecycle_recovery_required",
        ):
            append_lifecycle_event(self.root, baseline)
        self.assertFalse(
            any(path.name.startswith("000001-") for path in self.root.iterdir())
        )

    def test_mismatched_exact_pending_event_fails_closed(self) -> None:
        baseline = baseline_event(self.load())
        filename = f"000001-{baseline.sha256}.json"
        pending = self.root / f".pending-{filename}"
        pending.write_bytes(b"{\"synthetic\":true}\n")
        os.chmod(pending, 0o600)

        with self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "event_chain_rejected",
        ):
            append_lifecycle_event(self.root, baseline)
        self.assertFalse((self.root / filename).exists())

    def test_published_event_with_external_hardlink_is_rejected(self) -> None:
        baseline = baseline_event(self.load())
        append_lifecycle_event(self.root, baseline)
        event_file = next(self.root.iterdir())
        external_link = Path(self.temporary.name) / "external-event-link"
        os.link(event_file, external_link)

        with self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "lifecycle_permission_drift",
        ):
            self.load()

    def test_recovery_marker_does_not_consume_final_event_bound(self) -> None:
        baseline = baseline_event(self.load())
        filename = f"000001-{baseline.sha256}.json"
        pending = self.root / f".pending-{filename}"
        final = self.root / filename
        pending.write_bytes(baseline.canonical_bytes())
        os.chmod(pending, 0o600)
        os.link(pending, final)

        with patch(
            "myuna_core.owner_profile.lifecycle_ledger.MAX_EVENTS",
            1,
        ):
            state = append_lifecycle_event(self.root, baseline)

        self.assertEqual(state.last_sequence, 1)
        self.assertFalse(pending.exists())
        self.assertEqual(final.stat().st_nlink, 1)

    def test_relative_ledger_path_is_rejected_without_creation(self) -> None:
        relative = Path("synthetic-relative-ledger")
        with self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "lifecycle_path_rejected",
        ):
            initialize_lifecycle_ledger(relative)
        self.assertFalse(relative.exists())

    def test_low_level_io_failures_are_typed_and_directory_fd_is_closed(self) -> None:
        with patch(
            "myuna_core.owner_profile.lifecycle_ledger.fcntl.flock",
            side_effect=OSError("synthetic flock failure"),
        ), self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "lifecycle_unavailable",
        ):
            self.load()

        before_fds = len(os.listdir("/proc/self/fd"))
        with patch(
            "myuna_core.owner_profile.lifecycle_ledger.os.fstat",
            side_effect=OSError("synthetic fstat failure"),
        ), self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "lifecycle_unavailable",
        ):
            self.load()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before_fds)

        baseline = baseline_event(self.load())
        append_lifecycle_event(self.root, baseline)
        with patch(
            "myuna_core.owner_profile.lifecycle_ledger.os.read",
            side_effect=OSError("synthetic read failure"),
        ), self.assertRaisesRegex(
            OwnerProfileLifecycleError,
            "lifecycle_unavailable",
        ):
            self.load()


if __name__ == "__main__":
    unittest.main()
