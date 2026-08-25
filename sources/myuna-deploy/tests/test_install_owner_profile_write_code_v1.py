from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import install_owner_profile_write_code_v1 as installer  # noqa: E402


class InstallOwnerProfileWriteCodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        for relative in installer.SOURCE_FILES:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"# synthetic {relative}\n", encoding="utf-8")
        self.destination = self.root / "installed"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_bundle_is_deterministic_minimal_and_content_free(self) -> None:
        one = installer.build_code_bundle(
            self.source,
            source_commit="a" * 40,
        )
        two = installer.build_code_bundle(
            self.source,
            source_commit="a" * 40,
        )
        self.assertEqual(one, two)
        manifest = json.loads(one.manifest_bytes)
        self.assertEqual(manifest["component"], "owner_profile_write_v1")
        self.assertEqual(
            {record["path"] for record in manifest["files"]},
            set(installer.SOURCE_FILES),
        )
        self.assertNotIn("tests/", repr(manifest))
        self.assertNotIn("profile.toml", repr(manifest))
        self.assertIn(
            "src/myuna_core/owner_profile/write_socket_worker.py",
            installer.SOURCE_FILES,
        )

    def test_install_is_inactive_exact_and_idempotent(self) -> None:
        bundle = installer.build_code_bundle(
            self.source,
            source_commit="b" * 40,
        )
        release, created = installer.base.install_code_release(
            bundle,
            destination_root=self.destination,
            uid=os.geteuid(),
            gid=os.getegid(),
        )
        self.assertTrue(created)
        manifest = installer.validate_installed_code_release(
            bundle.release_sha256,
            destination_root=self.destination,
            uid=os.geteuid(),
            gid=os.getegid(),
        )
        self.assertEqual(manifest["source_commit"], "b" * 40)
        repeated, repeated_created = installer.base.install_code_release(
            bundle,
            destination_root=self.destination,
            uid=os.geteuid(),
            gid=os.getegid(),
        )
        self.assertEqual(repeated, release)
        self.assertFalse(repeated_created)

    def test_tamper_and_extra_file_fail_closed(self) -> None:
        bundle = installer.build_code_bundle(
            self.source,
            source_commit="c" * 40,
        )
        release, _ = installer.base.install_code_release(
            bundle,
            destination_root=self.destination,
            uid=os.geteuid(),
            gid=os.getegid(),
        )
        target = release / installer.SOURCE_FILES[0]
        target.chmod(0o640)
        with self.assertRaises(installer.OwnerProfileCodeInstallError):
            installer.validate_installed_code_release(
                bundle.release_sha256,
                destination_root=self.destination,
                uid=os.geteuid(),
                gid=os.getegid(),
            )


if __name__ == "__main__":
    unittest.main()
