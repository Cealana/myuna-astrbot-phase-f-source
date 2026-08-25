from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from io import BytesIO
import re
from typing import BinaryIO, Callable, Mapping, Sequence

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.authenticated_media_delivery import (
    DELIVERY_SCHEMA_VERSION,
    AuthenticatedMediaDelivery,
)
from myuna_core.vision_input import VisionMediaDescriptor
from vision_media_types import MediaInspection, MediaTransportRejected


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_MEDIA_BYTES = 8 * 1024 * 1024


def _reject() -> MediaTransportRejected:
    return MediaTransportRejected("media transport rejected")


@dataclass(frozen=True, slots=True)
class TransportMediaPayload:
    source_ref: str = field(repr=False)
    content: bytes = field(repr=False)
    inspection: MediaInspection

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_ref, str)
            or not self.source_ref
            or len(self.source_ref) > 512
            or self.source_ref != self.source_ref.strip()
            or "\x00" in self.source_ref
        ):
            raise ValueError("transport media source reference is invalid")
        if not isinstance(self.content, bytes) or not 1 <= len(self.content) <= _MAX_MEDIA_BYTES:
            raise ValueError("transport media content is outside the supported range")


class PreparedAuthenticatedMediaDelivery:
    """One-shot bridge from transport bytes to the staging port."""

    __slots__ = ("delivery", "_content", "_taken")

    def __init__(
        self,
        *,
        delivery: AuthenticatedMediaDelivery,
        content: Mapping[str, bytes],
    ) -> None:
        if set(content) != {item.media_id for item in delivery.media}:
            raise ValueError("prepared media content does not match delivery descriptors")
        self.delivery = delivery
        self._content = dict(content)
        self._taken = False

    def __repr__(self) -> str:
        return (
            "PreparedAuthenticatedMediaDelivery("
            f"delivery_id={self.delivery.delivery_id!r}, "
            f"media_count={len(self.delivery.media)})"
        )

    def take_streams_once(self) -> Mapping[str, BinaryIO]:
        if self._taken:
            raise _reject()
        self._taken = True
        streams = {media_id: BytesIO(value) for media_id, value in self._content.items()}
        self._content.clear()
        return streams

    def audit_metadata(self) -> dict[str, object]:
        return self.delivery.audit_metadata()


MediaIdFactory = Callable[[str, str, int], str]
DeliveryIdFactory = Callable[[str], str]


def build_prepared_media_delivery(
    *,
    context: AuthenticatedConversationContext,
    user_question: str,
    media: Sequence[TransportMediaPayload],
    analysis_modes: tuple[str, ...],
    received_at: datetime,
    media_id_factory: MediaIdFactory,
    delivery_id_factory: DeliveryIdFactory,
) -> PreparedAuthenticatedMediaDelivery:
    try:
        if not 1 <= len(media) <= 4:
            raise _reject()
        source_refs = [item.source_ref for item in media]
        if len(source_refs) != len(set(source_refs)):
            raise _reject()
        descriptors: list[VisionMediaDescriptor] = []
        content_by_id: dict[str, bytes] = {}
        for index, item in enumerate(media):
            digest = sha256(item.content).hexdigest()
            media_id = media_id_factory(item.source_ref, digest, index)
            if not isinstance(media_id, str) or _SAFE_ID.fullmatch(media_id) is None:
                raise _reject()
            if media_id in content_by_id:
                raise _reject()
            descriptors.append(
                VisionMediaDescriptor(
                    media_id=media_id,
                    content_sha256=digest,
                    mime_type=item.inspection.mime_type,
                    byte_length=len(item.content),
                    width=item.inspection.width,
                    height=item.inspection.height,
                )
            )
            content_by_id[media_id] = item.content
        delivery_id = delivery_id_factory(context.event_id)
        if not isinstance(delivery_id, str) or _SAFE_ID.fullmatch(delivery_id) is None:
            raise _reject()
        delivery = AuthenticatedMediaDelivery(
            schema_version=DELIVERY_SCHEMA_VERSION,
            delivery_id=delivery_id,
            context=context,
            media=tuple(descriptors),
            user_question=user_question,
            analysis_modes=analysis_modes,
            received_at=received_at,
        )
        return PreparedAuthenticatedMediaDelivery(
            delivery=delivery,
            content=content_by_id,
        )
    except Exception:
        raise _reject() from None
