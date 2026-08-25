from __future__ import annotations

from dataclasses import dataclass


_MIME_TYPES = frozenset({"image/jpeg", "image/png", "image/webp"})
_MAX_DIMENSION = 8192


class MediaTransportRejected(PermissionError):
    """Fail-closed media error without source reference or content detail."""


@dataclass(frozen=True, slots=True)
class MediaInspection:
    mime_type: str
    width: int
    height: int

    def __post_init__(self) -> None:
        if self.mime_type not in _MIME_TYPES:
            raise ValueError("media inspection MIME type is unsupported")
        for value in (self.width, self.height):
            if not isinstance(value, int) or not 1 <= value <= _MAX_DIMENSION:
                raise ValueError("media inspection dimensions are unsupported")
