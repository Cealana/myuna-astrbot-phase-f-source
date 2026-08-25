from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.external_context.release_binding import (
    ReleaseSetFileSnapshot,
    ReleaseSetBindingRejected,
    load_release_set_file,
    load_release_set_file_snapshot,
    load_release_set_from_environ,
    release_set_enabled,
)

from tests.test_external_context_release_set import sample_fields
from myuna_core.external_context.release_set import P07DReleaseSet


class ReleaseSetBindingTests(unittest.TestCase):
    def test_protected_file_round_trip_and_duplicate_key_rejected(self) -> None:
        selected = P07DReleaseSet.create(**sample_fields())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release-set.json"
            path.write_text(json.dumps(selected.as_payload(), sort_keys=True), encoding="utf-8")
            path.chmod(0o640)
            self.assertEqual(
                load_release_set_file(
                    path,
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                ),
                selected,
            )
            snapshot = load_release_set_file_snapshot(
                path,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )
            self.assertEqual(snapshot.release_set, selected)
            self.assertRegex(snapshot.file_digest, r"^[0-9a-f]{64}$")
            path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
            path.chmod(0o640)
            with self.assertRaisesRegex(ReleaseSetBindingRejected, "duplicate_field"):
                load_release_set_file(
                    path,
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                )

    def test_mode_symlink_and_enablement_fail_closed(self) -> None:
        selected = P07DReleaseSet.create(**sample_fields())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "release-set.json"
            path.write_text(json.dumps(selected.as_payload()), encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaisesRegex(ReleaseSetBindingRejected, "mode_rejected"):
                load_release_set_file(path, expected_uid=os.getuid(), expected_gid=os.getgid())
            path.chmod(0o640)
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaisesRegex(ReleaseSetBindingRejected, "document_rejected"):
                load_release_set_file(link, expected_uid=os.getuid(), expected_gid=os.getgid())
        self.assertFalse(release_set_enabled({}))
        with self.assertRaisesRegex(ReleaseSetBindingRejected, "enablement_rejected"):
            release_set_enabled({"MYUNA_P07_D_RELEASE_SET_ENABLED": "sometimes"})

    def test_environment_binding_uses_root_group_for_shared_manifest(self) -> None:
        selected = P07DReleaseSet.create(**sample_fields())
        snapshot = ReleaseSetFileSnapshot(selected, "a" * 64)
        with patch(
            "myuna_core.external_context.release_binding.load_release_set_file_snapshot",
            return_value=snapshot,
        ) as loader:
            self.assertEqual(
                load_release_set_from_environ(
                    {"MYUNA_P07_D_RELEASE_SET_ENABLED": "true"},
                ),
                selected,
            )
        loader.assert_called_once_with(
            Path("/etc/myuna-telegram-gateway/p07-d-release-set-v1.json"),
            expected_uid=0,
            expected_gid=0,
        )


if __name__ == "__main__":
    unittest.main()
