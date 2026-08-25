from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from gateway_recovery_episode import (  # noqa: E402
    RECOVERY_NOTICE_TEXT,
    RecoveryEpisodeRejected,
    RecoveryEpisodeStore,
)


NOW = datetime(2026, 7, 31, 5, 0, tzinfo=timezone.utc)


def projection(
    *,
    category: str = "core_or_gateway_failure",
    fingerprint: str = "core_or_gateway_failure:core:synthetic",
) -> dict[str, object]:
    return {
        "schema": "myuna.safe-degradation.v1",
        "status": "degraded",
        "category": category,
        "fingerprint": fingerprint,
        "recovery_state": "active",
        "retryable": True,
        "owner_action_required": False,
    }


class RecoveryEpisodeStoreTests(unittest.TestCase):
    def store(
        self,
        root: str,
        *,
        scope: str = "scope-synthetic-a",
    ) -> RecoveryEpisodeStore:
        return RecoveryEpisodeStore(Path(root) / "state" / "episode.db", scope)

    def test_empty_startup_does_not_create_recovered_noise(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = self.store(temp)
            self.assertIsNone(store.snapshot())
            self.assertFalse(store.claim_recovery_notice(now=NOW))
            self.assertIsNone(store.snapshot())

    def test_invalid_projection_is_rejected_before_episode_mutation(self) -> None:
        invalid = [
            None,
            {},
            {**projection(), "extra": "rejected"},
            {**projection(), "schema": "wrong"},
            {**projection(), "status": "ok"},
            {**projection(), "recovery_state": "recovered"},
            {**projection(), "retryable": 1},
            {**projection(), "owner_action_required": 0},
            {**projection(), "category": "bad category"},
            {**projection(), "fingerprint": "bad fingerprint"},
        ]
        with tempfile.TemporaryDirectory() as temp:
            store = self.store(temp)
            for candidate in invalid:
                with self.subTest(candidate=candidate):
                    with self.assertRaises(RecoveryEpisodeRejected):
                        store.mark_active(candidate, now=NOW)
                    self.assertIsNone(store.snapshot())

    def test_first_and_repeated_active_failure_share_one_episode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = self.store(temp)
            store.mark_active(projection(), now=NOW)
            first = store.snapshot()
            self.assertIsNotNone(first)
            assert first is not None
            self.assertEqual(first.state, "active")
            self.assertEqual(first.occurrence_count, 1)
            self.assertFalse(first.notice_claimed)
            self.assertIsNone(first.recovered_at)

            later = NOW + timedelta(seconds=3)
            store.mark_active(
                projection(
                    category="provider_transient_failure",
                    fingerprint="provider_transient_failure:provider:synthetic",
                ),
                now=later,
            )
            second = store.snapshot()
            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second.episode_id, first.episode_id)
            self.assertEqual(second.occurrence_count, 2)
            self.assertEqual(second.category, "provider_transient_failure")
            self.assertEqual(
                second.fingerprint,
                "provider_transient_failure:provider:synthetic",
            )
            self.assertEqual(second.last_seen_at, "2026-07-31T05:00:03.000000Z")

    def test_recovery_notice_is_durable_and_at_most_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "state" / "episode.db"
            first = RecoveryEpisodeStore(database, "scope-synthetic")
            first.mark_active(projection(), now=NOW)
            self.assertTrue(
                first.claim_recovery_notice(now=NOW + timedelta(seconds=4))
            )
            recovered = first.snapshot()
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered.state, "recovered")
            self.assertTrue(recovered.notice_claimed)
            self.assertEqual(
                recovered.recovered_at,
                "2026-07-31T05:00:04.000000Z",
            )

            reopened = RecoveryEpisodeStore(database, "scope-synthetic")
            self.assertFalse(
                reopened.claim_recovery_notice(now=NOW + timedelta(seconds=5))
            )
            self.assertEqual(reopened.snapshot(), recovered)

    def test_new_failure_after_recovery_creates_new_episode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = self.store(temp)
            store.mark_active(projection(), now=NOW)
            first = store.snapshot()
            assert first is not None
            self.assertTrue(
                store.claim_recovery_notice(now=NOW + timedelta(seconds=1))
            )
            store.mark_active(projection(), now=NOW + timedelta(seconds=2))
            second = store.snapshot()
            assert second is not None
            self.assertNotEqual(second.episode_id, first.episode_id)
            self.assertEqual(second.state, "active")
            self.assertEqual(second.occurrence_count, 1)
            self.assertFalse(second.notice_claimed)

    def test_scope_isolation_uses_no_identity_or_message_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "state" / "episode.db"
            first = RecoveryEpisodeStore(database, "scope-a")
            second = RecoveryEpisodeStore(database, "scope-b")
            first.mark_active(projection(), now=NOW)
            self.assertIsNone(second.snapshot())
            self.assertFalse(second.claim_recovery_notice(now=NOW))
            self.assertEqual(first.snapshot().state, "active")

    def test_symlink_database_and_naive_timestamps_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.db"
            target.write_bytes(b"synthetic")
            link = root / "linked.db"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(RecoveryEpisodeRejected):
                RecoveryEpisodeStore(link, "scope-synthetic")

        with tempfile.TemporaryDirectory() as temp:
            store = self.store(temp)
            with self.assertRaises(RecoveryEpisodeRejected):
                store.mark_active(projection(), now=datetime(2026, 7, 31))
            store.mark_active(projection(), now=NOW)
            with self.assertRaises(RecoveryEpisodeRejected):
                store.claim_recovery_notice(now=datetime(2026, 7, 31))
            self.assertEqual(store.snapshot().state, "active")

    def test_existing_database_and_parent_metadata_must_be_private(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "state"
            parent.mkdir(mode=0o700)
            database = parent / "episode.db"
            database.write_bytes(b"not-opened")
            database.chmod(0o644)
            with self.assertRaises(RecoveryEpisodeRejected):
                RecoveryEpisodeStore(database, "scope-synthetic")
            self.assertEqual(database.read_bytes(), b"not-opened")
            self.assertEqual(database.stat().st_mode & 0o777, 0o644)

        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "state"
            parent.mkdir(mode=0o755)
            database = parent / "episode.db"
            with self.assertRaises(RecoveryEpisodeRejected):
                RecoveryEpisodeStore(database, "scope-synthetic")
            self.assertFalse(database.exists())
            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)

    def test_two_store_instances_allow_exactly_one_recovery_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "state" / "episode.db"
            first = RecoveryEpisodeStore(database, "scope-synthetic")
            second = RecoveryEpisodeStore(database, "scope-synthetic")
            first.mark_active(projection(), now=NOW)
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(
                    executor.map(
                        lambda item: item.claim_recovery_notice(
                            now=NOW + timedelta(seconds=1)
                        ),
                        (first, second),
                    )
                )
            self.assertEqual(sorted(results), [False, True])
            third = RecoveryEpisodeStore(database, "scope-synthetic")
            self.assertEqual(third.snapshot().state, "recovered")
            self.assertFalse(
                third.claim_recovery_notice(now=NOW + timedelta(seconds=2))
            )

    def test_database_mode_and_notice_text_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = self.store(temp)
            mode = os.stat(store.database_path).st_mode & 0o777
            self.assertEqual(mode, 0o600)
        self.assertTrue(RECOVERY_NOTICE_TEXT)
        for forbidden in (
            "core_or_gateway_failure",
            "provider",
            "identity",
            "channel",
            "event",
        ):
            self.assertNotIn(forbidden, RECOVERY_NOTICE_TEXT)


if __name__ == "__main__":
    unittest.main()
