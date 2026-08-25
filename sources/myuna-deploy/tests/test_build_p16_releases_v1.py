from __future__ import annotations

import json
import stat
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_p16_releases_v1 as builder  # noqa: E402


class BuildP16ReleasesV1Tests(unittest.TestCase):
    def _source_tree(self, root: Path, mapping: dict[str, str]) -> None:
        for source in mapping.values():
            path = root / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"source:{source}\n", encoding="utf-8")

    def _base_tree(self, root: Path, mapping: dict[str, str]) -> None:
        root.mkdir(parents=True)
        (root / "sentinel.txt").write_text("base\n", encoding="ascii")
        for destination in mapping:
            path = root / destination
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"base:{destination}\n", encoding="utf-8")

    def test_builds_deterministic_overlay_releases_and_reuses_exact_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core_source = root / "core-source"
            deploy_source = root / "deploy-source"
            core_base = root / ("a" * 64)
            qq_base = root / ("b" * 64)
            telegram_base = root / ("c" * 64)
            qq_mapping = {
                **builder._GATEWAY_SHARED,
                "runtime/qq_owner_runtime_gateway.py": (
                    "scripts/qq_owner_runtime_gateway.py"
                ),
            }
            telegram_mapping = {
                **builder._GATEWAY_SHARED,
                "runtime/p07_d_runtime_readiness.py": (
                    "scripts/p07_d_runtime_readiness.py"
                ),
                "runtime/telegram_owner_runtime_gateway.py": (
                    "scripts/telegram_owner_runtime_gateway.py"
                ),
            }
            self._source_tree(core_source, builder._CORE_OVERLAYS)
            self._source_tree(
                deploy_source,
                {**qq_mapping, **telegram_mapping, **builder._DIAGNOSTICS},
            )
            self._base_tree(core_base, builder._CORE_OVERLAYS)
            self._base_tree(qq_base, qq_mapping)
            self._base_tree(telegram_base, telegram_mapping)
            arguments = {
                "core_base": core_base,
                "qq_base": qq_base,
                "telegram_base": telegram_base,
                "core_source_root": core_source,
                "deploy_source_root": deploy_source,
                "core_source_commit": "1" * 40,
                "deploy_source_commit": "2" * 40,
                "output_root": root / "output",
            }
            first = builder.build_releases(**arguments)
            second = builder.build_releases(**arguments)
            self.assertTrue(all(not item["reused"] for item in first["releases"]))
            self.assertTrue(all(item["reused"] for item in second["releases"]))
            for item in first["releases"]:
                release = Path(item["release"])
                manifest = json.loads((release / "P16_MANIFEST.json").read_text())
                self.assertEqual(manifest["schema"], builder.SCHEMA)
                if item["kind"] == "core":
                    self.assertEqual(release.name, builder._tree_digest(release)[0])
                    self.assertTrue(
                        (release / "P16_INSTALLATION_RECEIPT.json").is_file()
                    )
                    for path in [release, *release.rglob("*")]:
                        expected = 0o550 if path.is_dir() else 0o440
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected)
                else:
                    self.assertEqual(release.name, manifest["release_digest"])
                if item["kind"] != "diagnostics":
                    self.assertEqual((release / "sentinel.txt").read_text(), "base\n")
            diagnostics = next(
                Path(item["release"])
                for item in first["releases"]
                if item["kind"] == "diagnostics"
            )
            self.assertTrue((diagnostics / "myuna_diagnose.py").is_file())

    def test_rejects_non_content_addressed_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-a-digest"
            path.mkdir()
            with self.assertRaisesRegex(ValueError, "base release digest"):
                builder._validate_base(path)


if __name__ == "__main__":
    unittest.main()
