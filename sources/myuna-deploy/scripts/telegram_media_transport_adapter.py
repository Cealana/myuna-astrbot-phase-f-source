from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Protocol, Sequence

from myuna_core.authenticated_conversation import AuthenticatedConversationContext

from media_transport_kernel import (
    DeliveryIdFactory,
    MediaIdFactory,
    MediaInspection,
    MediaTransportRejected,
    PreparedAuthenticatedMediaDelivery,
    TransportMediaPayload,
    build_prepared_media_delivery,
)


CHANNEL_KIND = "astrbot_telegram"
_MAX_MEDIA_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class TelegramMediaReference:
    platform_file_ref: str = field(repr=False)
    declared_byte_length: int
    declared_width: int
    declared_height: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.platform_file_ref, str)
            or not self.platform_file_ref
            or len(self.platform_file_ref) > 512
            or self.platform_file_ref != self.platform_file_ref.strip()
            or "\x00" in self.platform_file_ref
        ):
            raise ValueError("Telegram media reference is invalid")
        if (
            not isinstance(self.declared_byte_length, int)
            or not 1 <= self.declared_byte_length <= _MAX_MEDIA_BYTES
        ):
            raise ValueError("Telegram media byte length is invalid")
        for value in (self.declared_width, self.declared_height):
            if not isinstance(value, int) or not 1 <= value <= 8192:
                raise ValueError("Telegram media dimension hint is invalid")


class TelegramMediaDownloadPort(Protocol):
    def download(self, platform_file_ref: str, *, maximum_bytes: int) -> bytes: ...


class MediaProbePort(Protocol):
    def inspect(self, content: bytes) -> MediaInspection: ...


class TelegramMediaTransportAdapter:
    """Thin adapter: download, probe, validate hints, then delegate to the kernel."""

    def __init__(
        self,
        *,
        downloader: TelegramMediaDownloadPort,
        probe: MediaProbePort,
        media_id_factory: MediaIdFactory,
        delivery_id_factory: DeliveryIdFactory,
        now: Callable[[], datetime],
    ) -> None:
        self.downloader = downloader
        self.probe = probe
        self.media_id_factory = media_id_factory
        self.delivery_id_factory = delivery_id_factory
        self.now = now

    def prepare(
        self,
        *,
        context: AuthenticatedConversationContext,
        user_question: str,
        references: Sequence[TelegramMediaReference],
        analysis_modes: tuple[str, ...] = ("question_answer",),
    ) -> PreparedAuthenticatedMediaDelivery:
        try:
            if (
                context.channel_kind != CHANNEL_KIND
                or context.conversation_kind != "private"
                or context.authority_level != "owner"
                or not context.consent_media_processing
                or not 1 <= len(references) <= 4
            ):
                raise MediaTransportRejected("media transport rejected")
            source_refs = [item.platform_file_ref for item in references]
            if len(source_refs) != len(set(source_refs)):
                raise MediaTransportRejected("media transport rejected")
            payloads: list[TransportMediaPayload] = []
            for reference in references:
                content = self.downloader.download(
                    reference.platform_file_ref,
                    maximum_bytes=_MAX_MEDIA_BYTES,
                )
                if not isinstance(content, bytes) or len(content) != reference.declared_byte_length:
                    raise MediaTransportRejected("media transport rejected")
                inspection = self.probe.inspect(content)
                if (
                    inspection.width != reference.declared_width
                    or inspection.height != reference.declared_height
                ):
                    raise MediaTransportRejected("media transport rejected")
                payloads.append(
                    TransportMediaPayload(
                        source_ref=reference.platform_file_ref,
                        content=content,
                        inspection=inspection,
                    )
                )
            return build_prepared_media_delivery(
                context=context,
                user_question=user_question,
                media=payloads,
                analysis_modes=analysis_modes,
                received_at=self.now(),
                media_id_factory=self.media_id_factory,
                delivery_id_factory=self.delivery_id_factory,
            )
        except Exception:
            raise MediaTransportRejected("media transport rejected") from None
