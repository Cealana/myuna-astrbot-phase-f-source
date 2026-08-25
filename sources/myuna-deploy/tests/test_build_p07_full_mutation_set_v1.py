from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import unittest

from scripts import build_p07_full_mutation_set_v1 as builder


DEPLOY = Path(__file__).resolve().parents[1]


def bundle_inventory(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        path.relative_to(root).as_posix(): (
            path.read_bytes(),
            stat.S_IMODE(path.stat().st_mode),
        )
        for path in root.rglob("*")
        if path.is_file()
    }


class FullMutationSetBuildTests(unittest.TestCase):
    def test_a_b_bundles_are_byte_mode_identical_and_inactive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "a"
            second = Path(directory) / "b"
            first_manifest = builder.build_bundle(
                deploy_source=DEPLOY,
                output_root=first,
                core_commit="1" * 40,
                deploy_commit="2" * 40,
            )
            second_manifest = builder.build_bundle(
                deploy_source=DEPLOY,
                output_root=second,
                core_commit="1" * 40,
                deploy_commit="2" * 40,
            )
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual(bundle_inventory(first), bundle_inventory(second))
            self.assertTrue(
                all(value is False for value in first_manifest["capabilities"].values())
            )
            self.assertEqual(
                first_manifest["rollback_lineages"],
                {
                    "dual_state_v2": "immutable-exhausted-1-of-1",
                    "predecessor": "immutable-exhausted-2-of-2",
                },
            )
            self.assertFalse(
                any(
                    "__pycache__" in path or path.endswith((".pyc", ".pyo"))
                    for path in bundle_inventory(first)
                )
            )

    def test_tamper_extra_and_mode_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "bundle"
            builder.build_bundle(
                deploy_source=DEPLOY,
                output_root=target,
                core_commit="1" * 40,
                deploy_commit="2" * 40,
            )
            manifest = json.loads((target / "manifest.json").read_text("ascii"))
            source = target / manifest["files"][0]["path"]
            source.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                builder.FullMutationBuildRejected,
                "full_mutation_bundle_inventory_rejected",
            ):
                builder.verify_bundle(target)

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "bundle"
            builder.build_bundle(
                deploy_source=DEPLOY,
                output_root=target,
                core_commit="1" * 40,
                deploy_commit="2" * 40,
            )
            (target / "unexpected.txt").write_text("extra", encoding="ascii")
            with self.assertRaisesRegex(
                builder.FullMutationBuildRejected,
                "full_mutation_bundle_inventory_rejected",
            ):
                builder.verify_bundle(target)

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "bundle"
            builder.build_bundle(
                deploy_source=DEPLOY,
                output_root=target,
                core_commit="1" * 40,
                deploy_commit="2" * 40,
            )
            manifest = json.loads((target / "manifest.json").read_text("ascii"))
            source = target / manifest["files"][0]["path"]
            source.chmod(0o600)
            with self.assertRaisesRegex(
                builder.FullMutationBuildRejected,
                "full_mutation_bundle_inventory_rejected",
            ):
                builder.verify_bundle(target)


if __name__ == "__main__":
    unittest.main()
