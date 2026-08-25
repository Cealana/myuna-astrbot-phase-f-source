from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest

from myuna_core.owner_profile.active_selector import (
    ActiveProfileTarget,
    initialize_active_profile_store,
    install_active_profile_target,
    load_active_profile,
)
from myuna_core.owner_profile.lifecycle import GENESIS_DIGEST, LifecycleEvent
from myuna_core.owner_profile.lifecycle_ledger import (
    append_lifecycle_event,
    initialize_lifecycle_ledger,
    load_lifecycle_ledger,
)
from myuna_core.owner_profile.loader import parse_profile_bytes
from myuna_core.owner_profile.write_candidate import (
    ANALYSIS_TYPE,
    parse_candidate_analysis,
    prepare_profile_candidate,
)
from myuna_core.owner_profile.write_publish import (
    OwnerProfilePublishError,
    build_channel_approval_bytes,
    initialize_profile_release_store,
    install_immutable_profile_release,
    publish_audit_projection,
    publish_stored_profile_candidate,
)
from myuna_core.owner_profile.write_store import (
    initialize_candidate_store,
    load_pending_candidate,
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


def candidate_for(base_bytes: bytes = BASE_PROFILE):
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
                        "body": "希望长期继续学习合成电子技术。",
                        "keywords": ["电子", "学习"],
                        "basis": "explicit_owner_statement",
                    }
                ],
                "excluded_categories": [],
            },
            ensure_ascii=False,
        )
    )
    return prepare_profile_candidate(parse_profile_bytes(base_bytes), analysis)


class CandidatePublishTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.profile_root = base / "profile"
        self.release_root = self.profile_root / "releases"
        self.ledger = base / "ledger"
        self.candidate_store = base / "candidate-store"
        self.uid = os.geteuid()
        initialize_active_profile_store(self.profile_root, expected_uid=self.uid)
        initialize_profile_release_store(self.release_root, expected_uid=self.uid)
        initialize_lifecycle_ledger(self.ledger, expected_uid=self.uid)
        initialize_candidate_store(self.candidate_store, expected_uid=self.uid)
        self.base = parse_profile_bytes(BASE_PROFILE)
        install_immutable_profile_release(
            self.release_root,
            BASE_PROFILE,
            expected_uid=self.uid,
        )
        install_active_profile_target(
            self.profile_root,
            ActiveProfileTarget.from_profile(self.base),
            expected_current=None,
            expected_uid=self.uid,
        )
        append_lifecycle_event(
            self.ledger,
            LifecycleEvent(
                event_type="baseline_registered",
                event_id="baseline-synthetic",
                sequence=1,
                previous_event_sha256=GENESIS_DIGEST,
                profile_id=self.base.profile_id,
                base_revision=None,
                base_sha256=None,
                target_revision=self.base.profile_revision,
                target_sha256=self.base.sha256,
                confirmation_sha256="a" * 64,
                reason_category="initial_registration",
            ),
            expected_uid=self.uid,
        )
        self.candidate = candidate_for()
        stage_profile_candidate(
            self.candidate_store,
            self.candidate,
            scope_sha256="f" * 64,
            now=datetime(2035, 1, 2, 3, tzinfo=timezone.utc),
            expected_uid=self.uid,
        )
        self.record = load_pending_candidate(
            self.candidate_store,
            scope_sha256="f" * 64,
            confirmation_code=self.candidate.confirmation_code,
            now=datetime(2035, 1, 2, 4, tzinfo=timezone.utc),
            expected_uid=self.uid,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_approval_is_exact_and_content_free_shape(self) -> None:
        approval = build_channel_approval_bytes(self.candidate.target)
        document = json.loads(approval)
        self.assertEqual(document["profile_sha256"], self.candidate.target.sha256)
        self.assertNotIn("sections", document)
        self.assertNotIn("body", approval.decode("ascii"))

    def test_publish_installs_release_and_advances_lifecycle(self) -> None:
        result = publish_stored_profile_candidate(
            profile_root=self.profile_root,
            lifecycle_ledger=self.ledger,
            active_profile=self.base,
            record=self.record,
            expected_uid=self.uid,
        )
        self.assertEqual(result.target_revision, 3)
        release = self.release_root / f"r3-{self.candidate.target.sha256}"
        self.assertEqual((release / "profile.toml").read_bytes(), self.candidate.target_bytes)
        self.assertEqual(release.stat().st_mode & 0o777, 0o700)
        self.assertEqual((release / "profile.toml").stat().st_mode & 0o777, 0o600)
        state = load_lifecycle_ledger(
            self.ledger,
            profile_id=self.base.profile_id,
            expected_uid=self.uid,
        )
        self.assertEqual(state.active_revision, 3)
        self.assertEqual(state.revisions[3].status, "published")
        self.assertEqual(state.last_sequence, 4)

    def test_exact_replay_after_selector_update_is_idempotent(self) -> None:
        first = publish_stored_profile_candidate(
            profile_root=self.profile_root,
            lifecycle_ledger=self.ledger,
            active_profile=self.base,
            record=self.record,
            expected_uid=self.uid,
        )
        second = publish_stored_profile_candidate(
            profile_root=self.profile_root,
            lifecycle_ledger=self.ledger,
            active_profile=self.candidate.target,
            record=self.record,
            expected_uid=self.uid,
        )
        self.assertFalse(first.already_published)
        self.assertTrue(second.already_published)
        state = load_lifecycle_ledger(
            self.ledger,
            profile_id=self.base.profile_id,
            expected_uid=self.uid,
        )
        self.assertEqual(state.last_sequence, 4)

    def test_release_crash_residue_is_recovered_exactly(self) -> None:
        def failpoint(stage: str) -> None:
            self.assertEqual(stage, "release_files_fsynced")
            raise RuntimeError("synthetic crash")

        with self.assertRaisesRegex(RuntimeError, "synthetic crash"):
            publish_stored_profile_candidate(
                profile_root=self.profile_root,
                lifecycle_ledger=self.ledger,
                active_profile=self.base,
                record=self.record,
                expected_uid=self.uid,
                failpoint=failpoint,
            )
        state_before = load_lifecycle_ledger(
            self.ledger,
            profile_id=self.base.profile_id,
            expected_uid=self.uid,
        )
        self.assertEqual(state_before.last_sequence, 1)
        result = publish_stored_profile_candidate(
            profile_root=self.profile_root,
            lifecycle_ledger=self.ledger,
            active_profile=self.base,
            record=self.record,
            expected_uid=self.uid,
        )
        self.assertEqual(result.target_revision, 3)
        self.assertEqual(
            [name for name in os.listdir(self.release_root) if name.startswith(".pending-")],
            [],
        )

    def test_stale_base_fails_before_release_install(self) -> None:
        drifted_bytes = BASE_PROFILE.replace(
            b"direct and low-pressure", b"concise and low-pressure"
        )
        drifted = parse_profile_bytes(drifted_bytes)
        with self.assertRaisesRegex(
            OwnerProfilePublishError, "profile_publish_selector_drift"
        ):
            publish_stored_profile_candidate(
                profile_root=self.profile_root,
                lifecycle_ledger=self.ledger,
                active_profile=drifted,
                record=self.record,
                expected_uid=self.uid,
            )
        self.assertEqual(
            [name for name in os.listdir(self.release_root) if name.startswith("r3-")],
            [],
        )

    def test_lifecycle_publish_crash_recovers_selector_exactly(self) -> None:
        def failpoint(stage: str) -> None:
            if stage == "lifecycle_published":
                raise RuntimeError("synthetic selector crash")

        with self.assertRaisesRegex(RuntimeError, "synthetic selector crash"):
            publish_stored_profile_candidate(
                profile_root=self.profile_root,
                lifecycle_ledger=self.ledger,
                active_profile=self.base,
                record=self.record,
                expected_uid=self.uid,
                failpoint=failpoint,
            )
        self.assertEqual(
            load_active_profile(
                self.profile_root, expected_uid=self.uid
            ).profile_revision,
            self.base.profile_revision,
        )
        result = publish_stored_profile_candidate(
            profile_root=self.profile_root,
            lifecycle_ledger=self.ledger,
            active_profile=self.base,
            record=self.record,
            expected_uid=self.uid,
        )
        self.assertTrue(result.already_published)
        self.assertEqual(
            load_active_profile(
                self.profile_root, expected_uid=self.uid
            ).profile_revision,
            self.candidate.target.profile_revision,
        )

    def test_existing_release_content_drift_fails_closed(self) -> None:
        release, _ = install_immutable_profile_release(
            self.release_root,
            self.candidate.target_bytes,
            expected_uid=self.uid,
        )
        profile_path = release / "profile.toml"
        profile_path.write_bytes(b"corrupt\n")
        os.chmod(profile_path, 0o600)
        with self.assertRaisesRegex(
            OwnerProfilePublishError, "profile_publish_release_drift"
        ):
            install_immutable_profile_release(
                self.release_root,
                self.candidate.target_bytes,
                expected_uid=self.uid,
            )

    def test_release_permission_drift_fails_closed(self) -> None:
        os.chmod(self.release_root, 0o755)
        with self.assertRaisesRegex(
            OwnerProfilePublishError, "profile_publish_permission_drift"
        ):
            install_immutable_profile_release(
                self.release_root,
                self.candidate.target_bytes,
                expected_uid=self.uid,
            )

    def test_publish_audit_projection_contains_no_digest_or_content(self) -> None:
        projection = publish_audit_projection(outcome="accepted", target_revision=3)
        serialized = json.dumps(projection, sort_keys=True)
        self.assertNotIn(self.candidate.target.sha256, serialized)
        self.assertFalse(projection["raw_input_recorded"])
        self.assertFalse(projection["candidate_content_recorded"])
        self.assertFalse(projection["profile_digest_recorded"])


if __name__ == "__main__":
    unittest.main()
