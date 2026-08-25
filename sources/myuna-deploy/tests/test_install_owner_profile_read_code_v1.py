from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from install_owner_profile_read_code_v1 import (
    FILE_MODE,
    MANIFEST_FILENAME,
    RELEASE_MODE,
    ROOT_MODE,
    SOURCE_FILES,
    OwnerProfileCodeInstallError,
    build_code_bundle,
    install_code_release,
    verify_git_source,
)


SOURCE_COMMIT = "a" * 40


class InstallOwnerProfileReadCodeV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        for index, relative in enumerate(SOURCE_FILES, start=1):
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f'"""Synthetic code fixture {index}."""\n',
                encoding="utf-8",
            )
        self.destination_parent = self.root / "destination"
        self.destination_parent.mkdir()
        self.destination_root = self.destination_parent / "code-root"
        self.uid = os.geteuid()
        self.gid = os.getegid()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def bundle(self):
        return build_code_bundle(self.source, source_commit=SOURCE_COMMIT)

    def install(self):
        return install_code_release(
            self.bundle(),
            destination_root=self.destination_root,
            uid=self.uid,
            gid=self.gid,
        )

    def test_minimal_code_release_is_deterministic_immutable_and_idempotent(self) -> None:
        first = self.bundle()
        second = self.bundle()
        self.assertEqual(first, second)
        self.assertEqual(len(first.payloads), len(SOURCE_FILES))

        destination, created = self.install()
        self.assertTrue(created)
        self.assertEqual(destination.name, first.release_sha256)
        manifest = json.loads((destination / MANIFEST_FILENAME).read_bytes())
        self.assertEqual(manifest["source_commit"], SOURCE_COMMIT)
        self.assertEqual(
            {entry["path"] for entry in manifest["files"]},
            set(SOURCE_FILES),
        )
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), RELEASE_MODE)
        for item in destination.rglob("*"):
            expected = RELEASE_MODE if item.is_dir() else FILE_MODE
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), expected)
            if item.is_file():
                self.assertEqual(item.stat().st_nlink, 1)

        repeated, repeated_created = self.install()
        self.assertEqual(repeated, destination)
        self.assertFalse(repeated_created)
        self.assertEqual(stat.S_IMODE(self.destination_root.stat().st_mode), ROOT_MODE)
        self.assertEqual(
            stat.S_IMODE((self.destination_root / "releases").stat().st_mode),
            ROOT_MODE,
        )

    def test_source_symlink_hardlink_missing_and_oversize_reject(self) -> None:
        target = self.source / SOURCE_FILES[0]
        outside = self.root / "outside"
        os.link(target, outside)
        with self.assertRaisesRegex(
            OwnerProfileCodeInstallError,
            "code_source_rejected",
        ):
            self.bundle()
        outside.unlink()

        target.unlink()
        target.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(
            OwnerProfileCodeInstallError,
            "code_source_rejected|code_source_unavailable",
        ):
            self.bundle()

    def test_existing_release_permission_or_content_drift_is_preserved(self) -> None:
        destination, _ = self.install()
        manifest = destination / MANIFEST_FILENAME
        manifest.chmod(0o400)
        with self.assertRaisesRegex(
            OwnerProfileCodeInstallError,
            "code_release_metadata_rejected",
        ):
            self.install()
        self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o400)

    def test_existing_root_drift_is_not_silently_repaired(self) -> None:
        self.destination_root.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            OwnerProfileCodeInstallError,
            "code_install_root_rejected",
        ):
            self.install()
        self.assertEqual(stat.S_IMODE(self.destination_root.stat().st_mode), 0o700)

    def test_exact_pending_release_recovers_and_conflict_fails_closed(self) -> None:
        bundle = self.bundle()
        destination, _ = self.install()
        payload = (destination / MANIFEST_FILENAME).read_bytes()
        self.assertTrue(payload)

        second_root = self.destination_parent / "second-code-root"
        _, created = install_code_release(
            bundle,
            destination_root=second_root,
            uid=self.uid,
            gid=self.gid,
        )
        self.assertTrue(created)
        second_releases = second_root / "releases"
        second_destination = second_releases / bundle.release_sha256
        second_destination.rename(
            second_releases / f".pending-{bundle.release_sha256}"
        )
        recovered, recovered_created = install_code_release(
            bundle,
            destination_root=second_root,
            uid=self.uid,
            gid=self.gid,
        )
        self.assertTrue(recovered_created)
        self.assertTrue(recovered.is_dir())

        (recovered / MANIFEST_FILENAME).chmod(0o600)
        (recovered / MANIFEST_FILENAME).write_bytes(b"synthetic-conflict")
        (recovered / MANIFEST_FILENAME).chmod(FILE_MODE)
        with self.assertRaisesRegex(
            OwnerProfileCodeInstallError,
            "code_release_content_rejected|code_release_identity_rejected",
        ):
            install_code_release(
                bundle,
                destination_root=second_root,
                uid=self.uid,
                gid=self.gid,
            )
        self.assertEqual(
            (recovered / MANIFEST_FILENAME).read_bytes(),
            b"synthetic-conflict",
        )

    def test_git_binding_rejects_tracked_drift_and_untracked_source(self) -> None:
        subprocess.run(
            ["git", "init", "--quiet", str(self.source)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.source), "config", "user.name", "Synthetic"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.source),
                "config",
                "user.email",
                "synthetic@example.invalid",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.source), "add", "--", *SOURCE_FILES],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.source), "commit", "--quiet", "-m", "fixture"],
            check=True,
        )
        commit = subprocess.run(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        verify_git_source(self.source, expected_commit=commit)

        source_file = self.source / SOURCE_FILES[0]
        original = source_file.read_bytes()
        source_file.write_bytes(original + b"# tracked drift\n")
        with self.assertRaisesRegex(
            OwnerProfileCodeInstallError,
            "code_source_git_rejected",
        ):
            verify_git_source(self.source, expected_commit=commit)
        source_file.write_bytes(original)

        subprocess.run(
            ["git", "-C", str(self.source), "rm", "--cached", SOURCE_FILES[0]],
            check=True,
            capture_output=True,
        )
        with self.assertRaisesRegex(
            OwnerProfileCodeInstallError,
            "code_source_git_rejected",
        ):
            verify_git_source(self.source, expected_commit=commit)


if __name__ == "__main__":
    unittest.main()
