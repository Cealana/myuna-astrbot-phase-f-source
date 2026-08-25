from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from io import BytesIO
from typing import Mapping
import warnings

from vision_media_types import MediaInspection, MediaTransportRejected


_FORMAT_TO_MIME = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "WEBP": "image/webp",
}


def _reject() -> MediaTransportRejected:
    return MediaTransportRejected("media probe rejected")


@dataclass(frozen=True, slots=True)
class PillowMediaProbePolicy:
    policy_id: str
    allowed_formats: tuple[str, ...]
    maximum_bytes: int
    maximum_width: int
    maximum_height: int
    maximum_pixels: int
    allow_animation: bool
    allow_trailing_payload: bool

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> "PillowMediaProbePolicy":
        try:
            if document["schema_version"] != 1 or document["status"] != "inactive_candidate":
                raise ValueError
            policy_id = document["policy_id"]
            allowed = tuple(document["allowed_formats"])
            if (
                not isinstance(policy_id, str)
                or not policy_id
                or not allowed
                or len(allowed) != len(set(allowed))
                or any(item not in _FORMAT_TO_MIME for item in allowed)
            ):
                raise ValueError
            limits = tuple(
                document[name]
                for name in (
                    "maximum_bytes",
                    "maximum_width",
                    "maximum_height",
                    "maximum_pixels",
                )
            )
            if any(not isinstance(value, int) or value < 1 for value in limits):
                raise ValueError
            if limits[0] > 8 * 1024 * 1024 or limits[1] > 8192 or limits[2] > 8192:
                raise ValueError
            if limits[3] > limits[1] * limits[2]:
                raise ValueError
            allow_animation = document["allow_animation"]
            allow_trailing = document["allow_trailing_payload"]
            if allow_animation is not False or allow_trailing is not False:
                raise ValueError
            return cls(
                policy_id=policy_id,
                allowed_formats=allowed,
                maximum_bytes=limits[0],
                maximum_width=limits[1],
                maximum_height=limits[2],
                maximum_pixels=limits[3],
                allow_animation=allow_animation,
                allow_trailing_payload=allow_trailing,
            )
        except (KeyError, TypeError, ValueError):
            raise ValueError("Pillow media probe policy is invalid") from None


def _validate_exact_container(content: bytes) -> None:
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        offset = 8
        saw_iend = False
        while offset < len(content):
            if len(content) - offset < 12:
                raise _reject()
            length = int.from_bytes(content[offset : offset + 4], "big")
            chunk_type = content[offset + 4 : offset + 8]
            chunk_end = offset + 12 + length
            if chunk_end > len(content):
                raise _reject()
            offset = chunk_end
            if chunk_type == b"IEND":
                if length != 0:
                    raise _reject()
                saw_iend = True
                break
        if not saw_iend or offset != len(content):
            raise _reject()
        return
    if content.startswith(b"\xff\xd8"):
        if not content.endswith(b"\xff\xd9"):
            raise _reject()
        return
    if content.startswith(b"RIFF") and len(content) >= 12 and content[8:12] == b"WEBP":
        if int.from_bytes(content[4:8], "little") + 8 != len(content):
            raise _reject()
        return
    raise _reject()


class PillowMediaProbe:
    """Fully decode bounded image bytes and return verified channel-neutral metadata."""

    def __init__(self, *, policy: PillowMediaProbePolicy) -> None:
        self.policy = policy

    def inspect(self, content: bytes) -> MediaInspection:
        try:
            if not isinstance(content, bytes) or not 1 <= len(content) <= self.policy.maximum_bytes:
                raise _reject()
            _validate_exact_container(content)
            image_module = import_module("PIL.Image")
            formats = tuple(self.policy.allowed_formats)
            with warnings.catch_warnings():
                warnings.simplefilter("error", image_module.DecompressionBombWarning)
                with image_module.open(BytesIO(content), formats=formats) as image:
                    detected_format = image.format
                    width, height = image.size
                    if (
                        detected_format not in formats
                        or width < 1
                        or height < 1
                        or width > self.policy.maximum_width
                        or height > self.policy.maximum_height
                        or width * height > self.policy.maximum_pixels
                        or bool(getattr(image, "is_animated", False))
                        or int(getattr(image, "n_frames", 1)) != 1
                    ):
                        raise _reject()
                    image.verify()
                with image_module.open(BytesIO(content), formats=formats) as decoded:
                    if decoded.format != detected_format or decoded.size != (width, height):
                        raise _reject()
                    decoded.load()
                    if bool(getattr(decoded, "is_animated", False)):
                        raise _reject()
            return MediaInspection(
                mime_type=_FORMAT_TO_MIME[detected_format],
                width=width,
                height=height,
            )
        except Exception:
            raise _reject() from None
