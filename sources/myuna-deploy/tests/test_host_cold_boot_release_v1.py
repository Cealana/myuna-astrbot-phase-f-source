from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "build_host_cold_boot_release_v1.py"
SPEC = importlib.util.spec_from_file_location("build_host_cold_boot_release_v1", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class HostColdBootReleaseTests(unittest.TestCase):
    def test_release_is_deterministic_exact_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            first = module.build(ROOT, output, "1" * 40)
            second = module.build(ROOT, output, "1" * 40)
            self.assertEqual(first, second)
            manifest = (first / "MANIFEST.json").read_bytes()
            self.assertEqual(first.name, module.sha256(manifest).hexdigest())
            payload = json.loads(manifest)
            self.assertEqual(payload["schema"], module.SCHEMA)
            self.assertEqual(
                {path.name for path in first.iterdir()},
                {*module.FILES, "MANIFEST.json"},
            )
            for entry in payload["files"]:
                path = first / entry["path"]
                self.assertEqual(module.sha256(path.read_bytes()).hexdigest(), entry["sha256"])
                self.assertEqual(path.stat().st_mode & 0o777, int(entry["mode"], 8))

    def test_invalid_commit_and_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "source_commit_rejected"):
                module.build(ROOT, Path(temporary), "not-a-commit")


if __name__ == "__main__":
    unittest.main()
