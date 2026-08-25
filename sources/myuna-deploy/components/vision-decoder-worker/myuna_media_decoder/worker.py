from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
from typing import Protocol

from .protocol import (
    DecoderRequest,
    DecoderResponse,
    DecoderWorkerRejected,
    read_request,
    write_response,
)


class MediaProbe(Protocol):
    def inspect(self, content: bytes): ...


class DecoderWorkerEngine:
    def __init__(self, *, probe: MediaProbe, policy_id: str) -> None:
        self.probe = probe
        self.policy_id = policy_id

    def execute(self, request: DecoderRequest) -> DecoderResponse:
        if request.probe_policy_id != self.policy_id:
            raise DecoderWorkerRejected("decoder worker request rejected")
        inspection = self.probe.inspect(request.content)
        return DecoderResponse(
            request_id=request.request_id,
            status="verified",
            content_sha256=request.content_sha256,
            mime_type=inspection.mime_type,
            width=inspection.width,
            height=inspection.height,
        )


def handle_connection(connection: socket.socket, engine: DecoderWorkerEngine) -> None:
    request_id = "rejected-request"
    try:
        request = read_request(connection)
        request_id = request.request_id
        response = engine.execute(request)
    except Exception:
        response = DecoderResponse(
            request_id=request_id,
            status="rejected",
            error_code="media_rejected",
        )
    write_response(connection, response)


def serve(listener: socket.socket, engine: DecoderWorkerEngine) -> None:
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(10.0)
            handle_connection(connection, engine)


def inherited_listener() -> socket.socket:
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("exactly one systemd socket is required")
    return socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    arguments = parser.parse_args()
    policy_path = Path(arguments.policy)
    document = json.loads(policy_path.read_text(encoding="utf-8"))
    from pillow_media_probe import PillowMediaProbe, PillowMediaProbePolicy

    policy = PillowMediaProbePolicy.from_document(document)
    engine = DecoderWorkerEngine(
        probe=PillowMediaProbe(policy=policy),
        policy_id=policy.policy_id,
    )
    with inherited_listener() as listener:
        serve(listener, engine)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
