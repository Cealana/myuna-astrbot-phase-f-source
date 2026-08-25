from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION,
    AuthenticatedConversationContext,
)
from myuna_core.fake_vision_media_staging import InMemoryVisionMediaStagingFake
from myuna_core.vision_media_boundary import VisionMediaStagingPolicy

from fake_media_transport_adapter import (
    FakeAuthenticatedMediaTransportAdapter,
    FakeMediaInput,
)
from media_transport_kernel import MediaInspection, MediaTransportRejected
from telegram_media_transport_adapter import (
    TelegramMediaReference,
    TelegramMediaTransportAdapter,
)


NOW = datetime(2026, 7, 27, 3, 0, tzinfo=timezone.utc)
PNG = b"\x89PNG\r\n\x1a\n" + b"offline-fixture"
PLATFORM_REF = "telegram-platform-file-ref-never-exported"


def context(*, channel: str = "astrbot_telegram") -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=SCHEMA_VERSION,
        request_id="request-telegram-media-0001",
        correlation_id="correlation-telegram-media-0001",
        client_id=f"client-{channel}",
        channel_kind=channel,
        binding_id=f"binding-{channel}-owner",
        principal_id="principal-owner",
        namespace_id="namespace-owner-private",
        authority_level="owner",
        channel_instance=f"instance-{channel}",
        conversation_id=f"conversation-{channel}-private",
        conversation_kind="private",
        event_id="event-telegram-media-0001",
        trace_id="trace-telegram-media-0001",
        occurred_at=NOW,
        delivery_capabilities=("text",),
        consent_media_processing=True,
    )


def media_id(source_ref: str, digest: str, index: int) -> str:
    value = sha256(f"media\0{source_ref}\0{digest}\0{index}".encode()).hexdigest()
    return f"media-{value[:40]}"


def delivery_id(event_id: str) -> str:
    return f"delivery-{sha256(event_id.encode()).hexdigest()[:40]}"


class FakeDownloader:
    def __init__(self, values: dict[str, bytes]) -> None:
        self.values = values
        self.calls: list[tuple[str, int]] = []

    def download(self, platform_file_ref: str, *, maximum_bytes: int) -> bytes:
        self.calls.append((platform_file_ref, maximum_bytes))
        value = self.values[platform_file_ref]
        if len(value) > maximum_bytes:
            raise ValueError("fixture exceeds bound")
        return value


class FakeProbe:
    def inspect(self, content: bytes) -> MediaInspection:
        if not content.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("fixture is not PNG")
        return MediaInspection(mime_type="image/png", width=640, height=480)


class FailingDownloader:
    def download(self, platform_file_ref: str, *, maximum_bytes: int) -> bytes:
        raise RuntimeError(f"internal download detail: {platform_file_ref}")


class FailingProbe:
    def inspect(self, content: bytes) -> MediaInspection:
        raise OSError("internal decoder detail")


def staging_policy() -> VisionMediaStagingPolicy:
    return VisionMediaStagingPolicy.from_document(
        {
            "schema_version": 1,
            "policy_id": "vision-media-staging-candidate-v1",
            "status": "inactive_candidate",
            "storage_scope": "private-ephemeral-media-v1",
            "maximum_ttl_seconds": 300,
            "maximum_reads_per_media": 1,
            "filesystem_guards": {
                "require_private_owner": True,
                "require_regular_file": True,
                "reject_symlinks": True,
            },
            "side_effects": {
                "allow_persistent_copy": False,
                "allow_remote_fetch": False,
                "secure_disposal_required": True,
            },
        }
    )


class CounterIds:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, prefix: str) -> str:
        self.value += 1
        return f"{prefix}-{self.value:04d}"


class TelegramMediaTransportAdapterTests(unittest.TestCase):
    def telegram_adapter(self, *, downloader: FakeDownloader | None = None):
        selected = downloader or FakeDownloader({PLATFORM_REF: PNG})
        return (
            TelegramMediaTransportAdapter(
                downloader=selected,
                probe=FakeProbe(),
                media_id_factory=media_id,
                delivery_id_factory=delivery_id,
                now=lambda: NOW + timedelta(seconds=1),
            ),
            selected,
        )

    def reference(self, **changes) -> TelegramMediaReference:
        values = {
            "platform_file_ref": PLATFORM_REF,
            "declared_byte_length": len(PNG),
            "declared_width": 640,
            "declared_height": 480,
        }
        values.update(changes)
        return TelegramMediaReference(**values)

    def test_telegram_and_fake_transport_produce_identical_delivery(self) -> None:
        telegram, downloader = self.telegram_adapter()
        prepared_telegram = telegram.prepare(
            context=context(),
            user_question="这张图里有什么？",
            references=(self.reference(),),
        )
        fake = FakeAuthenticatedMediaTransportAdapter(
            media_id_factory=media_id,
            delivery_id_factory=delivery_id,
            now=lambda: NOW + timedelta(seconds=1),
        )
        prepared_fake = fake.prepare(
            context=context(),
            user_question="这张图里有什么？",
            media=(
                FakeMediaInput(
                    source_ref=PLATFORM_REF,
                    content=PNG,
                    inspection=MediaInspection("image/png", 640, 480),
                ),
            ),
        )
        self.assertEqual(prepared_telegram.delivery, prepared_fake.delivery)
        self.assertEqual(prepared_telegram.audit_metadata(), prepared_fake.audit_metadata())
        self.assertEqual(downloader.calls, [(PLATFORM_REF, 8 * 1024 * 1024)])

    def test_platform_reference_and_bytes_never_enter_repr_or_audit(self) -> None:
        telegram, _ = self.telegram_adapter()
        prepared = telegram.prepare(
            context=context(),
            user_question="describe",
            references=(self.reference(),),
        )
        flattened = repr(prepared) + repr(prepared.audit_metadata())
        self.assertNotIn(PLATFORM_REF, flattened)
        self.assertNotIn("offline-fixture", flattened)
        self.assertNotIn("describe", repr(prepared.audit_metadata()))

    def test_prepared_streams_are_one_shot_and_work_with_fake_staging(self) -> None:
        telegram, _ = self.telegram_adapter()
        prepared = telegram.prepare(
            context=context(),
            user_question="describe",
            references=(self.reference(),),
            analysis_modes=("describe",),
        )
        staging = InMemoryVisionMediaStagingFake(
            policy=staging_policy(),
            now=lambda: NOW + timedelta(seconds=1),
            next_id=CounterIds(),
        )
        ticket = staging.stage_verified_streams(
            envelope=prepared.delivery.to_vision_envelope(),
            streams=prepared.take_streams_once(),
            expires_at=NOW + timedelta(seconds=301),
        )
        with self.assertRaises(MediaTransportRejected):
            prepared.take_streams_once()
        lease = staging.lease_once(
            ticket=ticket,
            media_id=ticket.media[0].media_id,
            now=NOW + timedelta(seconds=2),
        )
        self.assertEqual(staging.read_once(lease, maximum_bytes=1024), PNG)

    def test_wrong_channel_size_or_probe_dimensions_fail_closed(self) -> None:
        telegram, _ = self.telegram_adapter()
        cases = (
            (context(channel="astrbot_qq"), self.reference()),
            (context(), self.reference(declared_byte_length=len(PNG) + 1)),
            (context(), self.reference(declared_width=641)),
        )
        for selected_context, reference in cases:
            with self.subTest(reference=repr(reference), channel=selected_context.channel_kind):
                with self.assertRaises(MediaTransportRejected):
                    telegram.prepare(
                        context=selected_context,
                        user_question="describe",
                        references=(reference,),
                    )

    def test_duplicate_platform_reference_is_rejected_before_download(self) -> None:
        telegram, downloader = self.telegram_adapter()
        with self.assertRaises(MediaTransportRejected):
            telegram.prepare(
                context=context(),
                user_question="describe",
                references=(self.reference(), self.reference()),
            )
        self.assertEqual(downloader.calls, [])

    def test_download_and_probe_failures_are_normalized_without_detail(self) -> None:
        adapters = (
            TelegramMediaTransportAdapter(
                downloader=FailingDownloader(),
                probe=FakeProbe(),
                media_id_factory=media_id,
                delivery_id_factory=delivery_id,
                now=lambda: NOW,
            ),
            TelegramMediaTransportAdapter(
                downloader=FakeDownloader({PLATFORM_REF: PNG}),
                probe=FailingProbe(),
                media_id_factory=media_id,
                delivery_id_factory=delivery_id,
                now=lambda: NOW,
            ),
        )
        for adapter in adapters:
            with self.subTest(adapter=type(adapter.downloader).__name__):
                with self.assertRaisesRegex(
                    MediaTransportRejected,
                    "^media transport rejected$",
                ) as raised:
                    adapter.prepare(
                        context=context(),
                        user_question="describe",
                        references=(self.reference(),),
                    )
                self.assertIsNone(raised.exception.__cause__)


if __name__ == "__main__":
    unittest.main()
