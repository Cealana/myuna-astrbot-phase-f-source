from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest

from myuna_core.owner_profile.loader import parse_profile_bytes
from myuna_core.owner_profile.write_candidate import (
    ANALYSIS_TYPE,
    parse_candidate_analysis,
    prepare_profile_candidate,
)
from myuna_core.owner_profile.write_store import (
    OwnerProfileCandidateStoreError,
    cancel_pending_candidate,
    candidate_scope_sha256,
    initialize_candidate_store,
    load_pending_candidate,
    mark_candidate_consumed,
    parse_candidate_pointer,
    parse_candidate_record,
    stage_profile_candidate,
)


BASE_PROFILE = """\
schema_version = 1
document_type = "owner_profile_baseline"
profile_id = "synthetic-owner"
profile_revision = 2

[[sections]]
section_id = "preference-communication"
topic_key = "preference.communication"
category = "long_term_preference"
title = "Communication"
body = "Prefers direct and low-pressure communication."
keywords = ["direct", "low pressure"]
""".encode("utf-8")


def prepared_candidate(*, body: str = "Wants to keep learning synthetic electronics."):
    analysis = parse_candidate_analysis(
        json.dumps(
            {
                "schema_version": 1,
                "analysis_type": ANALYSIS_TYPE,
                "outcome": "candidate",
                "changes": [
                    {
                        "action": "add",
                        "category": "long_term_goal",
                        "topic_key": "goal.synthetic_electronics",
                        "title": "Synthetic electronics",
                        "body": body,
                        "keywords": ["electronics", "learning"],
                        "basis": "explicit_owner_statement",
                    }
                ],
                "excluded_categories": [],
            },
            ensure_ascii=False,
        )
    )
    return prepare_profile_candidate(parse_profile_bytes(BASE_PROFILE), analysis)


class CandidateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "candidate-store"
        self.uid = os.geteuid()
        initialize_candidate_store(self.root, expected_uid=self.uid)
        self.now = datetime(2035, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        self.scope = candidate_scope_sha256(
            channel_kind="astrbot_telegram",
            conversation_kind="private",
            authority_level="owner",
            binding_id="binding-synthetic",
            principal_id="principal-synthetic",
            namespace_id="namespace-synthetic",
            conversation_id="conversation-synthetic",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_initializes_exact_permissions(self) -> None:
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / "candidates").stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / "scopes").stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / "store.lock").stat().st_mode & 0o777, 0o600)

    def test_scope_rejects_non_telegram_or_non_owner(self) -> None:
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "candidate_scope_rejected"
        ):
            candidate_scope_sha256(
                channel_kind="astrbot_qq",
                conversation_kind="private",
                authority_level="owner",
                binding_id="binding-synthetic",
                principal_id="principal-synthetic",
                namespace_id="namespace-synthetic",
                conversation_id="conversation-synthetic",
            )

    def test_stage_and_load_preserve_exact_unicode_bytes(self) -> None:
        candidate = prepared_candidate(body="希望长期学习合成电子技术。")
        stored = stage_profile_candidate(
            self.root,
            candidate,
            scope_sha256=self.scope,
            now=self.now,
            expected_uid=self.uid,
        )
        loaded = load_pending_candidate(
            self.root,
            scope_sha256=self.scope,
            confirmation_code=candidate.confirmation_code,
            now=self.now + timedelta(hours=1),
            expected_uid=self.uid,
        )
        self.assertEqual(loaded.record_sha256, stored.record_sha256)
        self.assertEqual(loaded.target_profile_bytes, candidate.target_bytes)

    def test_exact_stage_replay_is_idempotent(self) -> None:
        candidate = prepared_candidate()
        first = stage_profile_candidate(
            self.root,
            candidate,
            scope_sha256=self.scope,
            now=self.now,
            expected_uid=self.uid,
        )
        second = stage_profile_candidate(
            self.root,
            candidate,
            scope_sha256=self.scope,
            now=self.now,
            expected_uid=self.uid,
        )
        self.assertEqual(first, second)

    def test_different_candidate_cannot_replace_pending(self) -> None:
        first = prepared_candidate()
        stage_profile_candidate(
            self.root,
            first,
            scope_sha256=self.scope,
            now=self.now,
            expected_uid=self.uid,
        )
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "candidate_pending_exists"
        ):
            stage_profile_candidate(
                self.root,
                prepared_candidate(body="Wants to keep learning synthetic circuits."),
                scope_sha256=self.scope,
                now=self.now + timedelta(hours=1),
                expected_uid=self.uid,
            )

    def test_wrong_confirmation_code_is_rejected(self) -> None:
        candidate = prepared_candidate()
        stage_profile_candidate(
            self.root,
            candidate,
            scope_sha256=self.scope,
            now=self.now,
            expected_uid=self.uid,
        )
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "candidate_confirmation_rejected"
        ):
            load_pending_candidate(
                self.root,
                scope_sha256=self.scope,
                confirmation_code="000000000000",
                now=self.now + timedelta(hours=1),
                expected_uid=self.uid,
            )

    def test_expired_candidate_cannot_commit(self) -> None:
        candidate = prepared_candidate()
        stage_profile_candidate(
            self.root,
            candidate,
            scope_sha256=self.scope,
            now=self.now,
            ttl=timedelta(minutes=5),
            expected_uid=self.uid,
        )
        with self.assertRaisesRegex(OwnerProfileCandidateStoreError, "candidate_expired"):
            load_pending_candidate(
                self.root,
                scope_sha256=self.scope,
                confirmation_code=candidate.confirmation_code,
                now=self.now + timedelta(minutes=5),
                expected_uid=self.uid,
            )

    def test_consumed_candidate_is_one_shot(self) -> None:
        candidate = prepared_candidate()
        stored = stage_profile_candidate(
            self.root,
            candidate,
            scope_sha256=self.scope,
            now=self.now,
            expected_uid=self.uid,
        )
        pointer = mark_candidate_consumed(
            self.root,
            scope_sha256=self.scope,
            candidate_record_sha256=stored.record_sha256,
            confirmation_code=candidate.confirmation_code,
            now=self.now + timedelta(hours=1),
            expected_uid=self.uid,
        )
        self.assertEqual(pointer.state, "consumed")
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "candidate_already_consumed"
        ):
            load_pending_candidate(
                self.root,
                scope_sha256=self.scope,
                confirmation_code=candidate.confirmation_code,
                now=self.now + timedelta(hours=2),
                expected_uid=self.uid,
            )

    def test_cancelled_candidate_is_not_committable(self) -> None:
        candidate = prepared_candidate()
        stage_profile_candidate(
            self.root,
            candidate,
            scope_sha256=self.scope,
            now=self.now,
            expected_uid=self.uid,
        )
        pointer = cancel_pending_candidate(
            self.root,
            scope_sha256=self.scope,
            confirmation_code=candidate.confirmation_code,
            now=self.now + timedelta(hours=1),
            expected_uid=self.uid,
        )
        self.assertEqual(pointer.state, "cancelled")
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "candidate_already_consumed"
        ):
            load_pending_candidate(
                self.root,
                scope_sha256=self.scope,
                confirmation_code=candidate.confirmation_code,
                now=self.now + timedelta(hours=2),
                expected_uid=self.uid,
            )

    def test_record_digest_drift_fails_closed(self) -> None:
        candidate = prepared_candidate()
        stored = stage_profile_candidate(
            self.root,
            candidate,
            scope_sha256=self.scope,
            now=self.now,
            expected_uid=self.uid,
        )
        record_path = self.root / "candidates" / f"{stored.record_sha256}.json"
        record_path.write_bytes(b"{}\n")
        os.chmod(record_path, 0o600)
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "candidate_digest_mismatch"
        ):
            load_pending_candidate(
                self.root,
                scope_sha256=self.scope,
                confirmation_code=candidate.confirmation_code,
                now=self.now + timedelta(hours=1),
                expected_uid=self.uid,
            )

    def test_pointer_permission_drift_fails_closed(self) -> None:
        candidate = prepared_candidate()
        stage_profile_candidate(
            self.root,
            candidate,
            scope_sha256=self.scope,
            now=self.now,
            expected_uid=self.uid,
        )
        pointer_path = self.root / "scopes" / f"{self.scope}.json"
        os.chmod(pointer_path, 0o644)
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "candidate_store_permission_drift"
        ):
            load_pending_candidate(
                self.root,
                scope_sha256=self.scope,
                confirmation_code=candidate.confirmation_code,
                now=self.now + timedelta(hours=1),
                expected_uid=self.uid,
            )

    def test_pointer_symlink_fails_closed(self) -> None:
        candidate = prepared_candidate()
        stored = stage_profile_candidate(
            self.root,
            candidate,
            scope_sha256=self.scope,
            now=self.now,
            expected_uid=self.uid,
        )
        pointer_path = self.root / "scopes" / f"{self.scope}.json"
        pointer_path.unlink()
        pointer_path.symlink_to(self.root / "candidates" / f"{stored.record_sha256}.json")
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "candidate_store_permission_drift"
        ):
            load_pending_candidate(
                self.root,
                scope_sha256=self.scope,
                confirmation_code=candidate.confirmation_code,
                now=self.now + timedelta(hours=1),
                expected_uid=self.uid,
            )

    def test_pending_crash_residue_requires_recovery(self) -> None:
        residue = self.root / "scopes" / (".pending-" + self.scope + "-" + "0" * 64 + ".json")
        residue.write_bytes(b"{}\n")
        os.chmod(residue, 0o600)
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "candidate_store_recovery_required"
        ):
            stage_profile_candidate(
                self.root,
                prepared_candidate(),
                scope_sha256=self.scope,
                now=self.now,
                expected_uid=self.uid,
            )

    def test_unknown_record_and_pointer_schema_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "malformed_candidate_record"
        ):
            parse_candidate_record(b'{"schema_version":2}\n')
        with self.assertRaisesRegex(
            OwnerProfileCandidateStoreError, "malformed_candidate_pointer"
        ):
            parse_candidate_pointer(b'{"schema_version":2}\n')


if __name__ == "__main__":
    unittest.main()
