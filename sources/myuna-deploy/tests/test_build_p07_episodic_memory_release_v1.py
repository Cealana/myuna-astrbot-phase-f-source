from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from build_p07_episodic_memory_release_v1 import (
    EpisodicBuildRejected,
    build_release,
    verify_release,
)


DEPLOY_ROOT = Path(__file__).resolve().parents[1]


def locate_core_root() -> Path:
    candidates = (
        DEPLOY_ROOT.parent / "core-p07-episodic-archive-v1",
        DEPLOY_ROOT.parent / "core",
    )
    for candidate in candidates:
        if (candidate / "src/myuna_core/episodic_memory").is_dir():
            return candidate
    raise RuntimeError("p07_episodic_core_source_unavailable")


CORE_ROOT = locate_core_root()


class EpisodicMemoryBuildTests(unittest.TestCase):
    def test_a_b_build_is_byte_identical_bytecode_free_and_inactive(self) -> None:
        self.assertTrue((CORE_ROOT / "src/myuna_core/episodic_memory").is_dir())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = build_release(
                core_root=CORE_ROOT,
                deploy_root=DEPLOY_ROOT,
                output_root=root / "a",
                core_commit="1" * 40,
                deploy_commit="2" * 40,
            )
            second = build_release(
                core_root=CORE_ROOT,
                deploy_root=DEPLOY_ROOT,
                output_root=root / "b",
                core_commit="1" * 40,
                deploy_commit="2" * 40,
            )
            self.assertEqual(first, second)
            files_a = {
                path.relative_to(root / "a").as_posix(): path.read_bytes()
                for path in (root / "a").rglob("*")
                if path.is_file()
            }
            files_b = {
                path.relative_to(root / "b").as_posix(): path.read_bytes()
                for path in (root / "b").rglob("*")
                if path.is_file()
            }
            self.assertEqual(files_a, files_b)
            self.assertFalse(
                any(
                    path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
                    for path in (root / "a").rglob("*")
                )
            )
            self.assertTrue(all(value is False for value in first["capabilities"].values()))
            self.assertEqual(verify_release(root / "a"), first)

    def test_mixed_or_corrupt_release_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            build_release(
                core_root=CORE_ROOT,
                deploy_root=DEPLOY_ROOT,
                output_root=root,
                core_commit="1" * 40,
                deploy_commit="2" * 40,
            )
            target = root / "scripts/p07_episodic_memory_contract_v1.py"
            target.write_text("# drift\n", encoding="utf-8")
            with self.assertRaisesRegex(EpisodicBuildRejected, "digest_mismatch"):
                verify_release(root)

    def test_release_inventory_contains_only_additive_source_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            manifest = build_release(
                core_root=CORE_ROOT,
                deploy_root=DEPLOY_ROOT,
                output_root=root,
                core_commit="1" * 40,
                deploy_commit="2" * 40,
            )
            paths = {item["path"] for item in manifest["files"]}
            self.assertTrue(
                all(
                    path.startswith("src/myuna_core/episodic_memory/")
                    or path
                    in {
                        "docs/ADR-066-p07-lossless-episodic-memory-v1.md",
                        "scripts/build_p07_episodic_memory_release_v1.py",
                        "scripts/p07_episodic_memory_contract_v1.py",
                    }
                    for path in paths
                )
            )
            self.assertFalse(any(path.startswith("systemd/") for path in paths))


if __name__ == "__main__":
    unittest.main()
