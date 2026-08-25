from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from prepare_owner_profile_release_intake_v1 import (
    OwnerProfileIntakePrepareError,
    prepare_intake,
)
from myuna_core.owner_profile.loader import build_receipt


PROFILE_BYTES = """schema_version = 1
document_type = "owner_profile_baseline"
profile_id = "synthetic-private-intake"
profile_revision = 2

[[sections]]
section_id = "synthetic-section"
topic_key = "synthetic-topic"
category = "long_term_preference"
title = "Synthetic 中文"
body = "Synthetic stable private intake preference."
keywords = ["synthetic", "中文"]
""".encode("utf-8")


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


class PrepareOwnerProfileReleaseIntakeV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.intake_root = self.root / "drafts"
        self.intake_root.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.profile = self.intake_root / "source-profile.toml"
        self.receipt = self.intake_root / "source-receipt.json"
        self.profile.write_bytes(PROFILE_BYTES)
        self.receipt.write_bytes(canonical(build_receipt(PROFILE_BYTES)))
        self.profile.chmod(0o600)
        self.receipt.chmod(0o600)
        self.digest = sha256(PROFILE_BYTES).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self):
        return prepare_intake(
            self.profile,
            self.receipt,
            expected_sha256=self.digest,
            expected_revision=2,
            intake_root=self.intake_root,
            owner_uid=self.uid,
            owner_gid=os.getegid(),
        )

    def test_exact_intake_is_private_bound_and_idempotent(self) -> None:
        destination, created = self.prepare()
        self.assertTrue(created)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual(
            {path.name for path in destination.iterdir()},
            {"profile.toml", "receipt.json", "approval.json"},
        )
        for path in destination.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        approval = json.loads((destination / "approval.json").read_bytes())
        self.assertEqual(approval["decision"], "approved")
        self.assertEqual(approval["profile_sha256"], self.digest)

        repeated, repeated_created = self.prepare()
        self.assertEqual(repeated, destination)
        self.assertFalse(repeated_created)

    def test_digest_revision_and_receipt_drift_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            OwnerProfileIntakePrepareError,
            "intake_binding_rejected",
        ):
            prepare_intake(
                self.profile,
                self.receipt,
                expected_sha256="b" * 64,
                expected_revision=2,
                intake_root=self.intake_root,
                owner_uid=self.uid,
                owner_gid=os.getegid(),
            )
        with self.assertRaisesRegex(
            OwnerProfileIntakePrepareError,
            "intake_binding_rejected",
        ):
            prepare_intake(
                self.profile,
                self.receipt,
                expected_sha256=self.digest,
                expected_revision=3,
                intake_root=self.intake_root,
                owner_uid=self.uid,
                owner_gid=os.getegid(),
            )
        self.receipt.write_bytes(b"{}\n")
        with self.assertRaisesRegex(
            OwnerProfileIntakePrepareError,
            "malformed_receipt",
        ):
            self.prepare()

    def test_source_or_root_permission_and_type_drift_rejects(self) -> None:
        self.profile.chmod(0o640)
        with self.assertRaisesRegex(
            OwnerProfileIntakePrepareError,
            "intake_source_rejected",
        ):
            self.prepare()
        self.profile.chmod(0o600)

        outside = self.root / "outside"
        os.link(self.profile, outside)
        with self.assertRaisesRegex(
            OwnerProfileIntakePrepareError,
            "intake_source_rejected",
        ):
            self.prepare()
        outside.unlink()

        self.intake_root.chmod(0o750)
        with self.assertRaisesRegex(
            OwnerProfileIntakePrepareError,
            "intake_root_rejected",
        ):
            self.prepare()

    def test_existing_conflict_is_preserved(self) -> None:
        destination, _ = self.prepare()
        approval = destination / "approval.json"
        approval.write_bytes(b"synthetic-conflict\n")
        with self.assertRaisesRegex(
            OwnerProfileIntakePrepareError,
            "malformed_approval",
        ):
            self.prepare()
        self.assertEqual(approval.read_bytes(), b"synthetic-conflict\n")


if __name__ == "__main__":
    unittest.main()
