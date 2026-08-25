from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import struct
import unittest
import zlib

try:
    from PIL import Image, features

    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

from media_transport_kernel import MediaTransportRejected
from pillow_media_probe import PillowMediaProbe, PillowMediaProbePolicy


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "vision-media-probe-pillow-v1.json"


def policy(**changes) -> PillowMediaProbePolicy:
    document = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    document.update(changes)
    return PillowMediaProbePolicy.from_document(document)


def encoded(format_name: str) -> bytes:
    output = BytesIO()
    mode = "RGB" if format_name == "JPEG" else "RGBA"
    image = Image.new(mode, (32, 24), (20, 40, 80, 255) if mode == "RGBA" else (20, 40, 80))
    image.save(output, format=format_name)
    return output.getvalue()


def png_chunk(name: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + name
        + payload
        + struct.pack(">I", zlib.crc32(name + payload) & 0xFFFFFFFF)
    )


def oversized_png() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 5000, 5000, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr) + png_chunk(b"IEND", b"")


class PillowMediaProbePolicyTests(unittest.TestCase):
    def test_policy_is_bounded_and_inactive(self) -> None:
        selected = policy()
        self.assertEqual(selected.allowed_formats, ("JPEG", "PNG", "WEBP"))
        self.assertEqual(selected.maximum_pixels, 16_000_000)
        for change in (
            {"status": "active"},
            {"maximum_bytes": 8 * 1024 * 1024 + 1},
            {"allow_animation": True},
            {"allowed_formats": ["TIFF"]},
        ):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    policy(**change)


@unittest.skipUnless(PILLOW_AVAILABLE, "isolated Pillow runtime required")
class PillowMediaProbeDecoderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.probe = PillowMediaProbe(policy=policy())

    def test_static_jpeg_png_and_webp_are_fully_decoded(self) -> None:
        if not features.check("webp"):
            self.skipTest("Pillow WebP decoder unavailable")
        expected = {
            "JPEG": "image/jpeg",
            "PNG": "image/png",
            "WEBP": "image/webp",
        }
        for format_name, mime_type in expected.items():
            with self.subTest(format_name=format_name):
                inspection = self.probe.inspect(encoded(format_name))
                self.assertEqual(inspection.mime_type, mime_type)
                self.assertEqual((inspection.width, inspection.height), (32, 24))

    def test_truncated_and_trailing_payloads_fail_closed(self) -> None:
        for format_name in ("JPEG", "PNG", "WEBP"):
            original = encoded(format_name)
            for malformed in (original[:-8], original + b"untrusted-tail"):
                with self.subTest(format_name=format_name, length=len(malformed)):
                    with self.assertRaisesRegex(
                        MediaTransportRejected,
                        "^media probe rejected$",
                    ) as raised:
                        self.probe.inspect(malformed)
                    self.assertIsNone(raised.exception.__cause__)

    def test_pixel_bomb_and_unsupported_container_fail_before_load(self) -> None:
        for malformed in (oversized_png(), b"GIF89a" + b"x" * 64):
            with self.subTest(prefix=malformed[:8]):
                with self.assertRaises(MediaTransportRejected):
                    self.probe.inspect(malformed)

    def test_animated_webp_is_rejected(self) -> None:
        output = BytesIO()
        frames = (
            Image.new("RGB", (16, 16), "red"),
            Image.new("RGB", (16, 16), "blue"),
        )
        frames[0].save(
            output,
            format="WEBP",
            save_all=True,
            append_images=[frames[1]],
            duration=100,
            loop=0,
        )
        with self.assertRaises(MediaTransportRejected):
            self.probe.inspect(output.getvalue())


if __name__ == "__main__":
    unittest.main()
