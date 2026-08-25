from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.definition import DefinitionReleaseError, load_definition_release


RELEASE_ID = "v5-build-1234567890abcdef"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o750)
    for path in root.rglob("*"):
        path.chmod(0o750 if path.is_dir() else 0o640)


class DefinitionReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name) / "release"
        (self.root / "runtime-build/definition").mkdir(parents=True)
        (self.root / "runtime-build/definition/SKILL.md").write_text(
            "definition", encoding="utf-8"
        )
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "release-summary.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "approved-release",
                    "approved": True,
                    "activation_allowed": True,
                    "release_id": RELEASE_ID,
                    "version": "v5",
                    "build_id": "build-1234567890abcdef",
                    "source_sha256": "A" * 64,
                    "allowed_environments": ["dev"],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        files = [
            "runtime-build/definition/SKILL.md",
            "evidence/release-summary.json",
        ]
        (evidence / "release-files.sha256").write_text(
            "".join(f"{sha256(self.root / item)}  {item}\n" for item in files),
            encoding="utf-8",
        )
        for path in sorted(self.root.rglob("*"), reverse=True):
            path.chmod(0o550 if path.is_dir() else 0o440)
        self.root.chmod(0o550)

    def tearDown(self) -> None:
        make_writable(self.root)
        self.temporary.cleanup()

    def test_approved_immutable_release_loads(self) -> None:
        release = load_definition_release(
            self.root,
            expected_release_id=RELEASE_ID,
            environment="dev",
        )
        self.assertEqual(release.version, "v5")
        self.assertEqual(release.verified_files, 2)

    def test_release_id_mismatch_fails_closed(self) -> None:
        with self.assertRaises(DefinitionReleaseError):
            load_definition_release(
                self.root,
                expected_release_id="v5-wrong-release",
                environment="dev",
            )

    def test_writable_release_fails_closed(self) -> None:
        (self.root / "runtime-build/definition/SKILL.md").chmod(0o640)
        with self.assertRaises(DefinitionReleaseError):
            load_definition_release(
                self.root,
                expected_release_id=RELEASE_ID,
                environment="dev",
            )


if __name__ == "__main__":
    unittest.main()
