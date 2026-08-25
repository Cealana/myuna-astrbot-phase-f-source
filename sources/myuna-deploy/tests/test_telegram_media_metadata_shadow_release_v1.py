from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import build_telegram_media_metadata_shadow_releases_v1 as builder


ROOT = Path(__file__).resolve().parents[1]


class TelegramMediaMetadataShadowReleaseTests(unittest.TestCase):
    def test_pair_is_deterministic_and_separates_auth_from_trace_worker(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = builder.build_pair(ROOT, Path(first))
            two = builder.build_pair(ROOT, Path(second))
            self.assertEqual(one, two)
            self.assertEqual(set(one), {"auth", "worker"})
            auth_files = {entry["destination"] for entry in one["auth"]["files"]}
            worker_files = {entry["destination"] for entry in one["worker"]["files"]}
            self.assertIn("telegram_media_metadata_protocol.py", auth_files)
            self.assertIn("telegram_media_metadata_shadow_enqueue.py", auth_files)
            self.assertIn("telegram_media_metadata_shadow/worker.py", worker_files)
            self.assertNotIn("telegram_media_metadata_protocol.py", worker_files)
            self.assertNotIn("telegram_media_metadata_shadow/worker.py", auth_files)

    def test_materialized_releases_are_read_only_and_manifest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            documents = builder.build_pair(ROOT, Path(output))
            for component, document in documents.items():
                release = Path(output) / component / document["release_digest"]
                self.assertEqual(release.stat().st_mode & 0o777, 0o555)
                manifest = json.loads((release / builder.MANIFEST_NAME).read_text())
                self.assertEqual(manifest, document)
                for entry in document["files"]:
                    self.assertEqual(
                        (release / entry["destination"]).stat().st_mode & 0o777,
                        int(entry["mode"], 8),
                    )

    def test_symlink_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as source:
            root = Path(source)
            for relative, _, _ in builder.COMPONENTS["worker"]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"safe")
            selected = root / builder.COMPONENTS["worker"][0][0]
            selected.unlink()
            selected.symlink_to(root / builder.COMPONENTS["worker"][1][0])
            with self.assertRaises(builder.TelegramMediaShadowReleaseRejected):
                builder.build_release_document(root, component="worker")


if __name__ == "__main__":
    unittest.main()
