from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myuna_core.owner_profile.active_selector import load_active_profile
from myuna_core.owner_profile.contracts import OwnerProfileError
from myuna_core.owner_profile.lifecycle import GENESIS_DIGEST, LifecycleEvent
from myuna_core.owner_profile.lifecycle_ledger import (
    append_lifecycle_event,
    initialize_lifecycle_ledger,
)
from myuna_core.owner_profile.loader import parse_profile_bytes
from myuna_core.owner_profile.write_bootstrap import (
    OwnerProfileWriteBootstrapError,
    bootstrap_profile_write_store,
    validate_profile_write_store,
)
from myuna_core.owner_profile.write_publish import (
    initialize_profile_release_store,
    install_immutable_profile_release,
)


PROFILE_BYTES = b'''schema_version = 1
document_type = "owner_profile_baseline"
profile_id = "synthetic-owner"
profile_revision = 2

[[sections]]
section_id = "preference-communication"
topic_key = "preference.communication"
category = "long_term_preference"
title = "Communication"
body = "Prefers direct communication."
keywords = ["direct"]
'''


class OwnerProfileWriteBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.uid = os.geteuid()
        self.source_root = root / "legacy-releases"
        self.write_root = root / "write-state"
        self.write_root.mkdir(mode=0o700)
        self.ledger = self.write_root / "ledger"
        initialize_profile_release_store(self.source_root, expected_uid=self.uid)
        self.source_release, _ = install_immutable_profile_release(
            self.source_root,
            PROFILE_BYTES,
            expected_uid=self.uid,
        )
        self.profile = parse_profile_bytes(PROFILE_BYTES)
        initialize_lifecycle_ledger(self.ledger, expected_uid=self.uid)
        append_lifecycle_event(
            self.ledger,
            LifecycleEvent(
                event_type="baseline_registered",
                event_id="baseline-synthetic",
                sequence=1,
                previous_event_sha256=GENESIS_DIGEST,
                profile_id=self.profile.profile_id,
                base_revision=None,
                base_sha256=None,
                target_revision=self.profile.profile_revision,
                target_sha256=self.profile.sha256,
                confirmation_sha256="a" * 64,
                reason_category="initial_registration",
            ),
            expected_uid=self.uid,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_bootstrap_copies_exact_release_and_selects_it(self) -> None:
        created = bootstrap_profile_write_store(
            source_release=self.source_release,
            source_sha256=self.profile.sha256,
            write_root=self.write_root,
            lifecycle_ledger=self.ledger,
            expected_uid=self.uid,
        )
        self.assertTrue(created)
        loaded = load_active_profile(self.write_root, expected_uid=self.uid)
        self.assertEqual(loaded, self.profile)
        self.assertEqual(
            (
                self.write_root
                / "releases"
                / f"r2-{self.profile.sha256}"
                / "profile.toml"
            ).read_bytes(),
            PROFILE_BYTES,
        )
        self.assertEqual((self.write_root / "candidates").stat().st_mode & 0o777, 0o700)

    def test_exact_bootstrap_replay_is_idempotent(self) -> None:
        arguments = {
            "source_release": self.source_release,
            "source_sha256": self.profile.sha256,
            "write_root": self.write_root,
            "lifecycle_ledger": self.ledger,
            "expected_uid": self.uid,
        }
        self.assertTrue(bootstrap_profile_write_store(**arguments))
        self.assertFalse(bootstrap_profile_write_store(**arguments))
        validate_profile_write_store(
            write_root=self.write_root,
            lifecycle_ledger=self.ledger,
            expected_uid=self.uid,
        )

    def test_validation_rejects_candidate_store_drift(self) -> None:
        bootstrap_profile_write_store(
            source_release=self.source_release,
            source_sha256=self.profile.sha256,
            write_root=self.write_root,
            lifecycle_ledger=self.ledger,
            expected_uid=self.uid,
        )
        lock = self.write_root / "candidates" / "store.lock"
        lock.chmod(0o644)
        with self.assertRaisesRegex(
            OwnerProfileError,
            "candidate_store_permission_drift",
        ):
            validate_profile_write_store(
                write_root=self.write_root,
                lifecycle_ledger=self.ledger,
                expected_uid=self.uid,
            )

    def test_noncanonical_lifecycle_path_fails_closed(self) -> None:
        wrong_ledger = Path(self.temporary.name) / "wrong" / "ledger"
        wrong_ledger.parent.mkdir(mode=0o700)
        initialize_lifecycle_ledger(wrong_ledger, expected_uid=self.uid)
        with self.assertRaisesRegex(
            OwnerProfileWriteBootstrapError, "profile_write_bootstrap_path_rejected"
        ):
            bootstrap_profile_write_store(
                source_release=self.source_release,
                source_sha256=self.profile.sha256,
                write_root=self.write_root,
                lifecycle_ledger=wrong_ledger,
                expected_uid=self.uid,
            )


if __name__ == "__main__":
    unittest.main()
