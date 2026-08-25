from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import socket
import sys
import threading
import unittest

DEPLOY = Path(__file__).resolve().parents[1]
FORMAL_DEPLOY = Path("/srv/myuna/repos/deploy")
sys.path.insert(0, str(DEPLOY / "components" / "vision-decoder-worker"))

try:
    from PIL import Image

    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

from myuna_media_decoder.protocol import DecoderRequest, read_response, write_request
from myuna_media_decoder.worker import DecoderWorkerEngine, handle_connection
from pillow_media_probe import PillowMediaProbe, PillowMediaProbePolicy


POLICY_ID = "vision-media-probe-pillow-v1"


def png() -> bytes:
    output = BytesIO()
    Image.new("RGB", (40, 30), "navy").save(output, format="PNG")
    return output.getvalue()


def engine() -> DecoderWorkerEngine:
    document = json.loads(
        (FORMAL_DEPLOY / "config" / "vision-media-probe-pillow-v1.json").read_text(
            encoding="utf-8"
        )
    )
    policy = PillowMediaProbePolicy.from_document(document)
    return DecoderWorkerEngine(
        probe=PillowMediaProbe(policy=policy),
        policy_id=policy.policy_id,
    )


def exchange(content: bytes):
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    thread = threading.Thread(target=handle_connection, args=(server, engine()))
    thread.start()
    try:
        write_request(
            client,
            DecoderRequest(
                request_id="decoder-pillow-0001",
                content_sha256=sha256(content).hexdigest(),
                probe_policy_id=POLICY_ID,
                content=content,
            ),
        )
        return read_response(client)
    finally:
        client.close()
        server.close()
        thread.join(timeout=2)


@unittest.skipUnless(PILLOW_AVAILABLE, "isolated Pillow runtime required")
class VisionDecoderWorkerPillowTests(unittest.TestCase):
    def test_real_pillow_probe_round_trip(self) -> None:
        response = exchange(png())
        self.assertEqual(response.status, "verified")
        self.assertEqual(response.mime_type, "image/png")
        self.assertEqual((response.width, response.height), (40, 30))

    def test_trailing_payload_returns_only_generic_rejection(self) -> None:
        response = exchange(png() + b"untrusted-tail")
        self.assertEqual(response.status, "rejected")
        self.assertEqual(response.error_code, "media_rejected")
        self.assertIsNone(response.content_sha256)


if __name__ == "__main__":
    unittest.main()
