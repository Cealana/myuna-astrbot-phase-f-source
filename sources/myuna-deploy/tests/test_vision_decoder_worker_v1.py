from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import socket
import sys
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "components" / "vision-decoder-worker"))

from media_transport_kernel import MediaInspection, MediaTransportRejected
from myuna_media_decoder.protocol import (
    DecoderRequest,
    DecoderWorkerRejected,
    read_response,
    write_request,
)
from myuna_media_decoder.worker import DecoderWorkerEngine, handle_connection


POLICY_ID = "vision-media-probe-pillow-v1"
CONTENT = b"synthetic-image-bytes"


class FakeProbe:
    def inspect(self, content: bytes) -> MediaInspection:
        if content != CONTENT:
            raise MediaTransportRejected("media probe rejected")
        return MediaInspection("image/png", 32, 24)


def request(**changes) -> DecoderRequest:
    values = {
        "request_id": "decoder-request-0001",
        "content_sha256": sha256(CONTENT).hexdigest(),
        "probe_policy_id": POLICY_ID,
        "content": CONTENT,
    }
    values.update(changes)
    return DecoderRequest(**values)


def exchange(selected: DecoderRequest, *, engine: DecoderWorkerEngine):
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    thread = threading.Thread(target=handle_connection, args=(server, engine))
    thread.start()
    try:
        write_request(client, selected)
        return read_response(client)
    finally:
        client.close()
        server.close()
        thread.join(timeout=2)


class VisionDecoderWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DecoderWorkerEngine(probe=FakeProbe(), policy_id=POLICY_ID)

    def test_socketpair_round_trip_returns_only_verified_metadata(self) -> None:
        response = exchange(request(), engine=self.engine)
        self.assertEqual(response.status, "verified")
        self.assertEqual(response.mime_type, "image/png")
        self.assertEqual((response.width, response.height), (32, 24))
        flattened = repr(response.to_document())
        self.assertNotIn("synthetic-image-bytes", flattened)
        self.assertNotIn("telegram", flattened.lower())

    def test_wrong_policy_returns_generic_rejection(self) -> None:
        response = exchange(
            request(probe_policy_id="different-policy"),
            engine=self.engine,
        )
        self.assertEqual(response.status, "rejected")
        self.assertEqual(response.error_code, "media_rejected")
        self.assertIsNone(response.content_sha256)

    def test_content_hash_is_verified_before_probe(self) -> None:
        with self.assertRaises(DecoderWorkerRejected):
            request(content_sha256="0" * 64)

    def test_request_repr_omits_content(self) -> None:
        self.assertNotIn("synthetic-image-bytes", repr(request()))


if __name__ == "__main__":
    unittest.main()
