from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Sequence

from myuna_core.authenticated_conversation import AuthenticatedConversationContext

from media_transport_kernel import (
    DeliveryIdFactory,
    MediaIdFactory,
    MediaInspection,
    PreparedAuthenticatedMediaDelivery,
    TransportMediaPayload,
    build_prepared_media_delivery,
)


@dataclass(frozen=True, slots=True)
class FakeMediaInput:
    source_ref: str = field(repr=False)
    content: bytes = field(repr=False)
    inspection: MediaInspection


class FakeAuthenticatedMediaTransportAdapter:
    """Offline transport with the same kernel projection as channel adapters."""

    def __init__(
        self,
        *,
        media_id_factory: MediaIdFactory,
        delivery_id_factory: DeliveryIdFactory,
        now: Callable[[], datetime],
    ) -> None:
        self.media_id_factory = media_id_factory
        self.delivery_id_factory = delivery_id_factory
        self.now = now

    def prepare(
        self,
        *,
        context: AuthenticatedConversationContext,
        user_question: str,
        media: Sequence[FakeMediaInput],
        analysis_modes: tuple[str, ...] = ("question_answer",),
    ) -> PreparedAuthenticatedMediaDelivery:
        return build_prepared_media_delivery(
            context=context,
            user_question=user_question,
            media=tuple(
                TransportMediaPayload(
                    source_ref=item.source_ref,
                    content=item.content,
                    inspection=item.inspection,
                )
                for item in media
            ),
            analysis_modes=analysis_modes,
            received_at=self.now(),
            media_id_factory=self.media_id_factory,
            delivery_id_factory=self.delivery_id_factory,
        )
