from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
import socket
import struct
from typing import Mapping


SCHEMA_VERSION = 1
MAX_HEADER_BYTES = 4096
MAX_CONTENT_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 4096
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "request_id",
        "content_length",
        "content_sha256",
        "probe_policy_id",
    }
)
_RESPONSE_KEYS = frozenset(
    {
        "schema_version",
        "request_id",
        "status",
        "mime_type",
        "width",
        "height",
        "content_sha256",
        "error_code",
    }
)


class DecoderWorkerRejected(PermissionError):
    """Protocol rejection without image, channel, or decoder detail."""


def _reject() -> DecoderWorkerRejected:
    return DecoderWorkerRejected("decoder worker request rejected")


def _safe_id(value: object) -> bool:
    return isinstance(value, str) and _SAFE_ID.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class DecoderRequest:
    request_id: str
    content_sha256: str
    probe_policy_id: str
    content: bytes

    def __post_init__(self) -> None:
        if (
            not _safe_id(self.request_id)
            or not _safe_id(self.probe_policy_id)
            or not isinstance(self.content_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.content_sha256) is None
            or not isinstance(self.content, bytes)
            or not 1 <= len(self.content) <= MAX_CONTENT_BYTES
            or sha256(self.content).hexdigest() != self.content_sha256
        ):
            raise _reject()

    def __repr__(self) -> str:
        return (
            "DecoderRequest("
            f"request_id={self.request_id!r}, "
            f"content_length={len(self.content)}, "
            f"probe_policy_id={self.probe_policy_id!r})"
        )


@dataclass(frozen=True, slots=True)
class DecoderResponse:
    request_id: str
    status: str
    content_sha256: str | None = None
    mime_type: str | None = None
    width: int | None = None
    height: int | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not _safe_id(self.request_id) or self.status not in {"verified", "rejected"}:
            raise ValueError("decoder response is invalid")
        if self.status == "verified":
            if (
                re.fullmatch(r"[0-9a-f]{64}", self.content_sha256 or "") is None
                or self.mime_type not in {"image/jpeg", "image/png", "image/webp"}
                or not isinstance(self.width, int)
                or not isinstance(self.height, int)
                or self.width < 1
                or self.height < 1
                or self.error_code is not None
            ):
                raise ValueError("verified decoder response is invalid")
        elif (
            self.error_code != "media_rejected"
            or any(
                value is not None
                for value in (
                    self.content_sha256,
                    self.mime_type,
                    self.width,
                    self.height,
                )
            )
        ):
            raise ValueError("rejected decoder response is invalid")

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "request_id": self.request_id,
            "status": self.status,
            "mime_type": self.mime_type,
            "width": self.width,
            "height": self.height,
            "content_sha256": self.content_sha256,
            "error_code": self.error_code,
        }


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(min(remaining, 64 * 1024))
        if not chunk:
            raise _reject()
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_framed_json(connection: socket.socket, *, maximum: int) -> Mapping[str, object]:
    length = struct.unpack(">I", _recv_exact(connection, 4))[0]
    if not 2 <= length <= maximum:
        raise _reject()
    try:
        document = json.loads(_recv_exact(connection, length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _reject() from None
    if not isinstance(document, dict):
        raise _reject()
    return document


def read_request(connection: socket.socket) -> DecoderRequest:
    try:
        document = _read_framed_json(connection, maximum=MAX_HEADER_BYTES)
        if set(document) != _REQUEST_KEYS or document["schema_version"] != SCHEMA_VERSION:
            raise _reject()
        content_length = document["content_length"]
        if not isinstance(content_length, int) or not 1 <= content_length <= MAX_CONTENT_BYTES:
            raise _reject()
        return DecoderRequest(
            request_id=document["request_id"],
            content_sha256=document["content_sha256"],
            probe_policy_id=document["probe_policy_id"],
            content=_recv_exact(connection, content_length),
        )
    except Exception:
        raise _reject() from None


def write_request(connection: socket.socket, request: DecoderRequest) -> None:
    document = {
        "schema_version": SCHEMA_VERSION,
        "request_id": request.request_id,
        "content_length": len(request.content),
        "content_sha256": request.content_sha256,
        "probe_policy_id": request.probe_policy_id,
    }
    header = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(header) > MAX_HEADER_BYTES:
        raise _reject()
    connection.sendall(struct.pack(">I", len(header)) + header + request.content)


def write_response(connection: socket.socket, response: DecoderResponse) -> None:
    payload = json.dumps(
        response.to_document(),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(payload) > MAX_RESPONSE_BYTES:
        raise _reject()
    connection.sendall(struct.pack(">I", len(payload)) + payload)


def read_response(connection: socket.socket) -> DecoderResponse:
    try:
        document = _read_framed_json(connection, maximum=MAX_RESPONSE_BYTES)
        if set(document) != _RESPONSE_KEYS or document["schema_version"] != SCHEMA_VERSION:
            raise _reject()
        return DecoderResponse(
            request_id=document["request_id"],
            status=document["status"],
            content_sha256=document["content_sha256"],
            mime_type=document["mime_type"],
            width=document["width"],
            height=document["height"],
            error_code=document["error_code"],
        )
    except Exception:
        raise _reject() from None
