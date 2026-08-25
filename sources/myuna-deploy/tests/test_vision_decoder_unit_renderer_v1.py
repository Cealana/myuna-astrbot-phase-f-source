from __future__ import annotations

from pathlib import Path
import unittest

import render_vision_decoder_systemd_units_v1 as renderer


ROOT = Path(__file__).resolve().parents[1]
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


class VisionDecoderUnitRendererTests(unittest.TestCase):
    def test_rendered_service_has_only_content_addressed_component_paths(self) -> None:
        units = renderer.render_repository_units(
            ROOT,
            worker_digest=DIGEST_A,
            probe_digest=DIGEST_B,
        )
        service = units["myuna-vision-decoder-shadow-v1.service"].decode()
        self.assertIn(f"/vision-decoder-worker/releases/{DIGEST_A}/", service)
        self.assertIn(f"/vision-media-probe/releases/{DIGEST_B}/", service)
        self.assertNotIn("/srv/myuna/repos/", service)
        self.assertNotRegex(service, renderer._UNRESOLVED)

    def test_invalid_digest_is_rejected(self) -> None:
        with self.assertRaises(renderer.VisionDecoderUnitRenderRejected):
            renderer.render_repository_units(
                ROOT,
                worker_digest="not-a-digest",
                probe_digest=DIGEST_B,
            )

    def test_mutable_template_path_is_rejected(self) -> None:
        template = (
            ROOT / "systemd/myuna-vision-decoder-shadow-v1.service"
        ).read_bytes().replace(
            b"/opt/myuna/vision-decoder-worker/releases/@WORKER_RELEASE@",
            b"/opt/myuna/vision-decoder-worker/current",
        )
        with self.assertRaises(renderer.VisionDecoderUnitRenderRejected):
            renderer.render_service(
                template,
                worker_digest=DIGEST_A,
                probe_digest=DIGEST_B,
            )


if __name__ == "__main__":
    unittest.main()

