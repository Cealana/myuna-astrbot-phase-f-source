from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import unittest

from scripts import build_p07_owner_private_memory_transactional_controller as builder


DEPLOY = Path(__file__).resolve().parents[1]


def inventory(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        path.relative_to(root).as_posix(): (
            path.read_bytes(),
            stat.S_IMODE(path.stat().st_mode),
        )
        for path in root.rglob("*")
        if path.is_file()
    }


class TransactionalControllerBuildTests(unittest.TestCase):
    def test_a_b_are_byte_mode_identical_and_truthfully_inactive(self) -> None:
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
            self.assertEqual(inventory(first), inventory(second))
            capabilities = first_manifest["capabilities"]
            self.assertTrue(capabilities["live_controller_source_present"])
            self.assertTrue(
                all(
                    value is False
                    for key, value in capabilities.items()
                    if key != "live_controller_source_present"
                )
            )
            self.assertEqual(first_manifest["maximum_future_activations"], 1)
            self.assertEqual(
                first_manifest["immutable_evidence"]["predecessor"],
                "immutable-exhausted-2-of-2",
            )
            self.assertEqual(
                first_manifest["immutable_evidence"]["v2"],
                "immutable-exhausted-1-of-1",
            )
            self.assertFalse(
                any(
                    "__pycache__" in path or path.endswith((".pyc", ".pyo"))
                    for path in inventory(first)
                )
            )

    def test_tamper_extra_mode_and_capability_drift_are_rejected(self) -> None:
        for drift in ("tamper", "extra", "mode", "capability"):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "bundle"
                builder.build_bundle(
                    deploy_source=DEPLOY,
                    output_root=target,
                    core_commit="1" * 40,
                    deploy_commit="2" * 40,
                )
                manifest_path = target / "manifest.json"
                manifest = json.loads(manifest_path.read_text("ascii"))
                source = target / manifest["files"][0]["path"]
                if drift == "tamper":
                    source.write_bytes(b"tampered")
                elif drift == "extra":
                    (target / "unexpected.txt").write_bytes(b"extra")
                elif drift == "mode":
                    source.chmod(0o600 if source.stat().st_mode & 0o777 != 0o600 else 0o644)
                else:
                    manifest["capabilities"]["selected"] = True
                    manifest_path.write_bytes(builder.canonical(manifest))
                with self.assertRaises(builder.TransactionalControllerBuildRejected):
                    builder.verify_bundle(target)


if __name__ == "__main__":
    unittest.main()
