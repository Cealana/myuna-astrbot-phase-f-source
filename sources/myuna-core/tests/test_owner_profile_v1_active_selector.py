from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myuna_core.owner_profile.active_selector import (
    ActiveProfileSelectorError,
    ActiveProfileTarget,
    initialize_active_profile_store,
    install_active_profile_target,
    load_active_profile,
    load_active_profile_target,
    parse_active_profile_target,
    render_active_profile_target,
)
from myuna_core.owner_profile.loader import parse_profile_bytes
from myuna_core.owner_profile.write_publish import (
    initialize_profile_release_store,
    install_immutable_profile_release,
)


def profile_bytes(revision: int, body: str) -> bytes:
    return f'''schema_version = 1
document_type = "owner_profile_baseline"
profile_id = "synthetic-owner"
profile_revision = {revision}

[[sections]]
section_id = "preference-communication"
topic_key = "preference.communication"
category = "long_term_preference"
title = "Communication"
body = "{body}"
keywords = ["direct"]
'''.encode("utf-8")


class ActiveProfileSelectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "profile"
        self.uid = os.geteuid()
        initialize_active_profile_store(self.root, expected_uid=self.uid)
        initialize_profile_release_store(
            self.root / "releases", expected_uid=self.uid
        )
        self.base_bytes = profile_bytes(2, "Prefers direct communication.")
        self.target_bytes = profile_bytes(3, "Prefers direct, calm communication.")
        install_immutable_profile_release(
            self.root / "releases", self.base_bytes, expected_uid=self.uid
        )
        install_immutable_profile_release(
            self.root / "releases", self.target_bytes, expected_uid=self.uid
        )
        self.base = ActiveProfileTarget.from_profile(
            parse_profile_bytes(self.base_bytes)
        )
        self.target = ActiveProfileTarget.from_profile(
            parse_profile_bytes(self.target_bytes)
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_selector_encoding_is_canonical_and_strict(self) -> None:
        payload = render_active_profile_target(self.base)
        self.assertEqual(parse_active_profile_target(payload), self.base)
        self.assertTrue(payload.endswith(b"\n"))
        with self.assertRaisesRegex(
            ActiveProfileSelectorError, "unknown_profile_selector_schema"
        ):
            parse_active_profile_target(payload.replace(b'"schema_version":1', b'"schema_version":2'))

    def test_atomic_switch_loads_exact_immutable_release(self) -> None:
        self.assertTrue(
            install_active_profile_target(
                self.root,
                self.base,
                expected_current=None,
                expected_uid=self.uid,
            )
        )
        self.assertEqual(load_active_profile(self.root, expected_uid=self.uid).sha256, self.base.profile_sha256)
        self.assertTrue(
            install_active_profile_target(
                self.root,
                self.target,
                expected_current=self.base,
                expected_uid=self.uid,
            )
        )
        loaded = load_active_profile(self.root, expected_uid=self.uid)
        self.assertEqual(loaded.profile_revision, 3)
        self.assertEqual(loaded.sha256, self.target.profile_sha256)
        self.assertEqual(load_active_profile_target(self.root, expected_uid=self.uid), self.target)

    def test_exact_replay_is_idempotent(self) -> None:
        install_active_profile_target(
            self.root,
            self.base,
            expected_current=None,
            expected_uid=self.uid,
        )
        self.assertFalse(
            install_active_profile_target(
                self.root,
                self.base,
                expected_current=None,
                expected_uid=self.uid,
            )
        )

    def test_prestate_drift_fails_closed(self) -> None:
        install_active_profile_target(
            self.root,
            self.base,
            expected_current=None,
            expected_uid=self.uid,
        )
        unrelated = ActiveProfileTarget(
            profile_id=self.base.profile_id,
            profile_revision=9,
            profile_sha256="a" * 64,
        )
        with self.assertRaisesRegex(
            ActiveProfileSelectorError, "profile_selector_prestate_drift"
        ):
            install_active_profile_target(
                self.root,
                self.target,
                expected_current=unrelated,
                expected_uid=self.uid,
            )

    def test_permission_and_symlink_drift_fail_closed(self) -> None:
        install_active_profile_target(
            self.root,
            self.base,
            expected_current=None,
            expected_uid=self.uid,
        )
        selector = self.root / "active.json"
        os.chmod(selector, 0o644)
        with self.assertRaisesRegex(
            ActiveProfileSelectorError, "profile_selector_permission_drift"
        ):
            load_active_profile_target(self.root, expected_uid=self.uid)


if __name__ == "__main__":
    unittest.main()
