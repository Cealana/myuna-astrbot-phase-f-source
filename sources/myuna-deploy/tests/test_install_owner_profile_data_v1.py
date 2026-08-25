from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from install_owner_profile_data_v1 import (
    APPROVAL_FILENAME,
    FILE_MODE,
    PROFILE_FILENAME,
    RECEIPT_FILENAME,
    RELEASE_MODE,
    ROOT_MODE,
    OwnerProfileInstallError,
    install_profile_release,
    load_intake_bundle,
)
from myuna_core.owner_profile.approval import (
    APPROVAL_DECISION,
    APPROVAL_SCOPE,
    APPROVAL_TYPE,
)
from myuna_core.owner_profile.loader import build_receipt


PROFILE_TEMPLATE = """schema_version = 1
document_type = "owner_profile_baseline"
profile_id = "synthetic-install-profile"
profile_revision = 2

[[sections]]
section_id = "synthetic-section"
topic_key = "synthetic-topic"
category = "long_term_preference"
title = "Synthetic Unicode 中文"
body = "Synthetic stable preference for deterministic testing."
keywords = ["synthetic", "中文"]
""".encode("utf-8")


def canonical(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


class InstallOwnerProfileDataV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.intake_root = self.root / "intake"
        self.intake_root.mkdir(mode=0o700)
        self.destination_parent = self.root / "destination"
        self.destination_parent.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.digest = sha256(PROFILE_TEMPLATE).hexdigest()
        self.release_name = f"r2-{self.digest}"
        self.intake = self.intake_root / self.release_name
        self._write_intake()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _approval_bytes(self, **changes: object) -> bytes:
        payload: dict[str, object] = {
            "schema_version": 1,
            "approval_type": APPROVAL_TYPE,
            "approval_scope": APPROVAL_SCOPE,
            "decision": APPROVAL_DECISION,
            "profile_schema_version": 1,
            "profile_id": "synthetic-install-profile",
            "profile_revision": 2,
            "profile_sha256": self.digest,
        }
        payload.update(changes)
        return canonical(payload)

    def _write_intake(self, *, approval_changes: dict[str, object] | None = None) -> None:
        self.intake.mkdir(mode=0o700)
        receipt = canonical(build_receipt(PROFILE_TEMPLATE))
        payloads = {
            PROFILE_FILENAME: PROFILE_TEMPLATE,
            RECEIPT_FILENAME: receipt,
            APPROVAL_FILENAME: self._approval_bytes(**(approval_changes or {})),
        }
        for name, payload in payloads.items():
            path = self.intake / name
            path.write_bytes(payload)
            path.chmod(0o600)

    def load(self):
        return load_intake_bundle(
            self.intake,
            intake_uid=self.uid,
            allowed_roots=(self.intake_root,),
        )

    def install(self):
        return install_profile_release(
            self.load(),
            destination_root=self.destination_parent / "profile-root",
            root_uid=self.uid,
            service_uid=self.uid,
            service_gid=self.gid,
        )

    def test_exact_intake_installs_inactive_release_and_is_idempotent(self) -> None:
        destination, created = self.install()
        self.assertTrue(created)
        self.assertEqual(destination.name, self.release_name)
        self.assertEqual(
            {path.name for path in destination.iterdir()},
            {PROFILE_FILENAME, RECEIPT_FILENAME},
        )
        self.assertNotIn(APPROVAL_FILENAME, {path.name for path in destination.iterdir()})
        self.assertEqual((destination / PROFILE_FILENAME).read_bytes(), PROFILE_TEMPLATE)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), RELEASE_MODE)
        for path in destination.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), FILE_MODE)
            self.assertEqual(path.stat().st_nlink, 1)

        repeated, repeated_created = self.install()
        self.assertEqual(repeated, destination)
        self.assertFalse(repeated_created)
        profile_root = self.destination_parent / "profile-root"
        self.assertEqual(stat.S_IMODE(profile_root.stat().st_mode), ROOT_MODE)
        self.assertEqual(
            stat.S_IMODE((profile_root / "releases").stat().st_mode),
            ROOT_MODE,
        )

    def test_approval_digest_revision_or_identity_mismatch_rejects(self) -> None:
        variants = (
            {"profile_sha256": "b" * 64},
            {"profile_revision": 3},
            {"profile_id": "different-profile"},
        )
        for changes in variants:
            with self.subTest(changes=changes):
                (self.intake / APPROVAL_FILENAME).write_bytes(
                    self._approval_bytes(**changes)
                )
                with self.assertRaisesRegex(
                    OwnerProfileInstallError,
                    "approval_mismatch",
                ):
                    self.load()
        (self.intake / APPROVAL_FILENAME).write_bytes(self._approval_bytes())

    def test_intake_metadata_type_and_file_set_drift_fail_closed(self) -> None:
        extra = self.intake / "extra.txt"
        extra.write_text("synthetic", encoding="utf-8")
        extra.chmod(0o600)
        with self.assertRaisesRegex(
            OwnerProfileInstallError,
            "profile_intake_metadata_rejected",
        ):
            self.load()
        extra.unlink()

        profile = self.intake / PROFILE_FILENAME
        profile.chmod(0o640)
        with self.assertRaisesRegex(
            OwnerProfileInstallError,
            "profile_intake_metadata_rejected",
        ):
            self.load()
        profile.chmod(0o600)

        outside = self.root / "outside-profile"
        os.link(profile, outside)
        with self.assertRaisesRegex(
            OwnerProfileInstallError,
            "profile_intake_metadata_rejected",
        ):
            self.load()
        outside.unlink()

        self.intake_root.chmod(0o750)
        with self.assertRaisesRegex(
            OwnerProfileInstallError,
            "profile_intake_root_rejected",
        ):
            self.load()
        self.assertEqual(stat.S_IMODE(self.intake_root.stat().st_mode), 0o750)
        self.intake_root.chmod(0o700)

    def test_relative_symlinked_or_out_of_boundary_intake_rejects(self) -> None:
        with self.assertRaisesRegex(
            OwnerProfileInstallError,
            "profile_intake_path_rejected",
        ):
            load_intake_bundle(
                Path("relative"),
                intake_uid=self.uid,
                allowed_roots=(self.intake_root,),
            )

        linked = self.root / "linked-intake"
        linked.symlink_to(self.intake, target_is_directory=True)
        with self.assertRaisesRegex(
            OwnerProfileInstallError,
            "profile_intake_path_rejected",
        ):
            load_intake_bundle(
                linked,
                intake_uid=self.uid,
                allowed_roots=(self.root,),
            )

        with self.assertRaisesRegex(
            OwnerProfileInstallError,
            "profile_intake_path_rejected",
        ):
            load_intake_bundle(
                self.intake,
                intake_uid=self.uid,
                allowed_roots=(self.destination_parent,),
            )

    def test_conflicting_existing_release_is_preserved_and_rejected(self) -> None:
        destination, _ = self.install()
        receipt = destination / RECEIPT_FILENAME
        receipt.chmod(0o700)
        with self.assertRaisesRegex(
            OwnerProfileInstallError,
            "profile_installed_release_rejected",
        ):
            self.install()
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o700)

    def test_existing_install_root_drift_is_preserved_and_rejected(self) -> None:
        profile_root = self.destination_parent / "profile-root"
        profile_root.mkdir(mode=0o750)

        with self.assertRaisesRegex(
            OwnerProfileInstallError,
            "profile_install_root_rejected",
        ):
            self.install()

        self.assertEqual(stat.S_IMODE(profile_root.stat().st_mode), 0o750)
        self.assertFalse((profile_root / "releases").exists())

    def test_exact_pending_release_recovers_without_overwrite(self) -> None:
        bundle = self.load()
        profile_root = self.destination_parent / "profile-root"
        profile_root.mkdir(mode=ROOT_MODE)
        releases = profile_root / "releases"
        releases.mkdir(mode=ROOT_MODE)
        pending = releases / f".pending-{self.release_name}"
        pending.mkdir(mode=RELEASE_MODE)
        payloads = {
            PROFILE_FILENAME: bundle.profile_bytes,
            RECEIPT_FILENAME: bundle.receipt_bytes,
        }
        for name, payload in payloads.items():
            path = pending / name
            path.write_bytes(payload)
            path.chmod(FILE_MODE)

        destination, created = install_profile_release(
            bundle,
            destination_root=profile_root,
            root_uid=self.uid,
            service_uid=self.uid,
            service_gid=self.gid,
        )
        self.assertTrue(created)
        self.assertTrue(destination.is_dir())
        self.assertFalse(pending.exists())

    def test_mismatched_pending_release_is_preserved_and_rejected(self) -> None:
        bundle = self.load()
        profile_root = self.destination_parent / "profile-root"
        profile_root.mkdir(mode=ROOT_MODE)
        releases = profile_root / "releases"
        releases.mkdir(mode=ROOT_MODE)
        pending = releases / f".pending-{self.release_name}"
        pending.mkdir(mode=RELEASE_MODE)
        payloads = {
            PROFILE_FILENAME: b"synthetic-conflict",
            RECEIPT_FILENAME: bundle.receipt_bytes,
        }
        for name, payload in payloads.items():
            path = pending / name
            path.write_bytes(payload)
            path.chmod(FILE_MODE)

        with self.assertRaisesRegex(
            OwnerProfileInstallError,
            "profile_installed_release_conflict",
        ):
            install_profile_release(
                bundle,
                destination_root=profile_root,
                root_uid=self.uid,
                service_uid=self.uid,
                service_gid=self.gid,
            )
        self.assertEqual(
            (pending / PROFILE_FILENAME).read_bytes(), b"synthetic-conflict"
        )

    def test_installer_status_shape_cannot_expose_private_fields(self) -> None:
        from install_owner_profile_data_v1 import _status

        serialized = _status(status="INSTALLED_INACTIVE", revision=2, created=True)
        self.assertNotIn(self.digest, serialized)
        self.assertNotIn("synthetic-install-profile", serialized)
        self.assertNotIn(str(self.intake), serialized)
        self.assertIn('"raw_content_recorded":false', serialized)
        self.assertIn('"profile_digest_recorded":false', serialized)


if __name__ == "__main__":
    unittest.main()
