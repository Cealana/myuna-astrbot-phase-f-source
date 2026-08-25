from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import build_vision_decoder_releases_v1 as builder


ROOT = Path(__file__).resolve().parents[1]


class VisionDecoderReleaseTests(unittest.TestCase):
    def test_pair_is_deterministic_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = builder.build_pair(ROOT, Path(first))
            two = builder.build_pair(ROOT, Path(second))
            self.assertEqual(one, two)
            self.assertEqual(set(one), {"worker", "probe"})
            worker_files = {entry["destination"] for entry in one["worker"]["files"]}
            probe_files = {entry["destination"] for entry in one["probe"]["files"]}
            self.assertIn("myuna_media_decoder/worker.py", worker_files)
            self.assertIn("docs/ADR-047-vision-decoder-worker-v1.md", worker_files)
            self.assertEqual(
                probe_files,
                {
                    "vision_media_types.py",
                    "pillow_media_probe.py",
                    "config/vision-media-probe-pillow-v1.json",
                },
            )
            for forbidden in ("myuna_core", "authenticated_conversation"):
                for entry in one["probe"]["files"]:
                    content = (ROOT / entry["source"]).read_text(encoding="utf-8")
                    self.assertNotIn(forbidden, content)

    def test_manifest_and_files_are_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            documents = builder.build_pair(ROOT, Path(output))
            for component, document in documents.items():
                release = Path(output) / component / document["release_digest"]
                manifest = json.loads((release / builder.MANIFEST_NAME).read_text())
                self.assertEqual(manifest, document)
                self.assertEqual(release.stat().st_mode & 0o777, 0o555)
                for entry in document["files"]:
                    self.assertEqual(
                        (release / entry["destination"]).stat().st_mode & 0o777,
                        0o444,
                    )

    def test_symlink_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as source:
            root = Path(source)
            for relative, _ in builder.COMPONENTS["probe"]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"safe")
            target = root / builder.COMPONENTS["probe"][0][0]
            target.unlink()
            target.symlink_to(root / builder.COMPONENTS["probe"][1][0])
            with self.assertRaises(builder.VisionDecoderReleaseRejected):
                builder.build_release_document(root, component="probe")


if __name__ == "__main__":
    unittest.main()

