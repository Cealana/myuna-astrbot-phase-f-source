from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest

from tests.test_p07_d_release_set_transaction_v1 import release_set

from build_p07_policy_overlay_v1 import (
    PolicyOverlayBuildRejected,
    build_bundle,
    verify_bundle,
)


class PolicyOverlayBuildTests(unittest.TestCase):
    def test_deterministic_a_b_bundle_is_byte_identical_and_bytecode_free(self) -> None:
        parent = release_set()
        parent_bytes = json.dumps(
            parent.as_payload(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii") + b"\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = build_bundle(
                output_root=root / "a",
                parent_release_set=parent,
                parent_manifest_file_digest=__import__("hashlib").sha256(
                    parent_bytes
                ).hexdigest(),
                core_release_digest="1" * 64,
                runtime_release_digest="2" * 64,
                plugin_release_digest="3" * 64,
                plugin_config_digest="4" * 64,
                core_commit="5" * 40,
                deploy_commit="6" * 40,
            )
            second = build_bundle(
                output_root=root / "b",
                parent_release_set=parent,
                parent_manifest_file_digest=__import__("hashlib").sha256(
                    parent_bytes
                ).hexdigest(),
                core_release_digest="1" * 64,
                runtime_release_digest="2" * 64,
                plugin_release_digest="3" * 64,
                plugin_config_digest="4" * 64,
                core_commit="5" * 40,
                deploy_commit="6" * 40,
            )
            self.assertEqual(first, second)
            first_root = root / "a" / first["bundle_id"]
            second_root = root / "b" / second["bundle_id"]
            first_files = {
                path.name: path.read_bytes() for path in first_root.iterdir()
            }
            second_files = {
                path.name: path.read_bytes() for path in second_root.iterdir()
            }
            self.assertEqual(first_files, second_files)
            self.assertFalse(
                any(
                    path.suffix in {".pyc", ".pyo"} or path.name == "__pycache__"
                    for path in first_root.rglob("*")
                )
            )
            self.assertEqual(
                verify_bundle(first_root, parent_release_set=parent), first
            )

    def test_corrupt_or_mixed_bundle_is_rejected(self) -> None:
        parent = release_set()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = build_bundle(
                output_root=root,
                parent_release_set=parent,
                parent_manifest_file_digest="a" * 64,
                core_release_digest="1" * 64,
                runtime_release_digest="2" * 64,
                plugin_release_digest="3" * 64,
                plugin_config_digest="4" * 64,
                core_commit="5" * 40,
                deploy_commit="6" * 40,
            )
            target = root / manifest["bundle_id"]
            (target / "overlay-selector.json").write_text("{}\n", "ascii")
            with self.assertRaises(PolicyOverlayBuildRejected):
                verify_bundle(target, parent_release_set=parent)


if __name__ == "__main__":
    unittest.main()
