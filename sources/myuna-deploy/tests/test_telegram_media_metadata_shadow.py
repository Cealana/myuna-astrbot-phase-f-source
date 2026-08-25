from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
CORE_SRC = ROOT.parent / "core" / "src"
if not CORE_SRC.is_dir():
    CORE_SRC = ROOT.parent / "core-tree" / "src"
PLUGIN = ROOT / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
COMPONENT = ROOT / "components/telegram-media-metadata-shadow"
for path in (ROOT / "scripts", CORE_SRC, PLUGIN, COMPONENT):
    sys.path.insert(0, str(path))

from telegram_media_metadata_protocol import (  # noqa: E402
    MediaMetadataEnvelopeRejected,
    build_signed_media_shadow_envelope,
    should_observe_private_image_shape,
    verify_signed_media_shadow_envelope,
)
from telegram_media_metadata_shadow_enqueue import (  # noqa: E402
    TelegramMediaMetadataJob,
    build_media_metadata_shadow_event,
)
import telegram_media_metadata_shadow_gateway as auth  # noqa: E402
from telegram_media_metadata_shadow.worker import (  # noqa: E402
    TRACE_FIELDS,
    handle_event,
)


NOW = datetime(2026, 7, 27, 4, 0, tzinfo=timezone.utc)
SECRET = b"synthetic-signing-secret-for-media-shadow"
PEPPER = b"synthetic-identity-pepper-for-media-shadow"


def envelope(**changes):
    values = {
        "sender_id": "123456789",
        "message_id": "42",
        "raw_timestamp": NOW.timestamp(),
        "image_count": 1,
        "caption_present": False,
        "signing_secret": SECRET,
        "channel_instance": "telegram-owner-dev",
        "now": NOW,
        "nonce": "n" * 32,
    }
    values.update(changes)
    return build_signed_media_shadow_envelope(**values)


class TelegramMediaMetadataShadowTests(unittest.TestCase):
    def test_shape_admission_is_private_nonbot_images_only(self) -> None:
        self.assertTrue(
            should_observe_private_image_shape(
                sender_id="123456789",
                is_private_chat=True,
                sender_is_bot=False,
                image_count=1,
                parts_supported=True,
            )
        )
        for changes in (
            {"is_private_chat": False},
            {"sender_is_bot": True},
            {"sender_is_bot": None},
            {"image_count": 0},
            {"image_count": 5},
            {"parts_supported": False},
            {"sender_id": "invalid"},
        ):
            values = {
                "sender_id": "123456789",
                "is_private_chat": True,
                "sender_is_bot": False,
                "image_count": 1,
                "parts_supported": True,
            }
            self.assertFalse(should_observe_private_image_shape(**{**values, **changes}))

    def test_signed_envelope_contains_shape_but_no_media_reference_or_caption(self) -> None:
        payload = envelope(caption_present=True, image_count=3)
        encoded = json.dumps(payload, ensure_ascii=False)
        self.assertIn('"attachment_count_bucket": "2-4"', encoded)
        self.assertIn('"caption_present": true', encoded)
        for forbidden in ("file_id", "https://", "base64://", "caption_text", "image_bytes", "width", "height", "mime"):
            self.assertNotIn(forbidden, encoded.casefold())
        verified = verify_signed_media_shadow_envelope(payload, signing_secret=SECRET)
        self.assertEqual(verified.attachment_count_bucket, "2-4")
        self.assertTrue(verified.caption_present)
        self.assertNotIn("123456789", repr(verified))

    def test_signature_and_extra_fields_fail_closed(self) -> None:
        tampered = envelope()
        tampered["event"]["caption_present"] = True
        with self.assertRaises(MediaMetadataEnvelopeRejected):
            verify_signed_media_shadow_envelope(tampered, signing_secret=SECRET)
        extra = envelope()
        extra["event"]["file_id"] = "forbidden"
        with self.assertRaises(MediaMetadataEnvelopeRejected):
            verify_signed_media_shadow_envelope(extra, signing_secret=SECRET)

    def test_auth_gateway_emits_only_identity_free_job_after_owner_verification(self) -> None:
        captured = []
        records = []
        config = auth.AuthConfig(
            binding_id="binding-owner",
            principal_id="principal-owner",
            namespace_id="namespace-owner",
            channel_instance="telegram-owner-dev",
        )
        result = auth.authenticate_and_enqueue(
            envelope(caption_present=True),
            config=config,
            signing_secret=SECRET,
            identity_pepper=PEPPER,
            limiter=auth.SlidingRateLimiter(),
            now=NOW,
            claim=lambda *_: True,
            owner_verified=lambda *_: True,
            record=lambda event, outcome, code: records.append((outcome, code)) or True,
            enqueue=lambda socket_path, job: captured.append((socket_path, job)) or "enqueued",
        )
        self.assertTrue(result)
        self.assertEqual(records, [("accepted", "media_shadow_observed")])
        self.assertEqual(len(captured), 1)
        flattened = repr(captured[0])
        for forbidden in ("123456789", "binding-owner", "principal-owner", "namespace-owner"):
            self.assertNotIn(forbidden, flattened)

    def test_unverified_owner_never_reaches_metadata_worker(self) -> None:
        calls = []
        result = auth.authenticate_and_enqueue(
            envelope(),
            config=auth.AuthConfig("binding-owner", "principal-owner", "namespace-owner", "telegram-owner-dev"),
            signing_secret=SECRET,
            identity_pepper=PEPPER,
            limiter=auth.SlidingRateLimiter(),
            now=NOW,
            claim=lambda *_: True,
            owner_verified=lambda *_: False,
            record=lambda *_: True,
            enqueue=lambda *_: calls.append("enqueue") or "enqueued",
        )
        self.assertFalse(result)
        self.assertEqual(calls, [])

    def test_worker_trace_is_bounded_identity_and_content_free(self) -> None:
        forbidden_phrase = "这段说明文字不能进入 Shadow"
        datagram = build_media_metadata_shadow_event(
            TelegramMediaMetadataJob(str(uuid4()), "1", True),
            monotonic_ns=1_000_000,
        )
        self.assertNotIn(forbidden_phrase.encode("utf-8"), datagram)
        trace = handle_event(datagram, observed_at=NOW, monotonic_ns=2_000_000)
        self.assertIsNotNone(trace)
        self.assertEqual(set(trace), TRACE_FIELDS)
        self.assertTrue(trace["shadow_only"])
        self.assertEqual(trace["production_effect"], "none")
        self.assertEqual(trace["visible_behavior"], "unchanged_silent_nontext_boundary")
        encoded = json.dumps(trace, ensure_ascii=False)
        for forbidden in (forbidden_phrase, "account", "binding", "principal", "namespace", "file_id", "caption_text", "token"):
            self.assertNotIn(forbidden, encoded.casefold())

    def test_worker_rejects_extra_or_raw_fields(self) -> None:
        invalid = json.dumps(
            {
                "schema": "myuna.telegram-media-metadata-shadow.event.v1",
                "boundary": "verified_owner_private_media_pre_download",
                "observation_uuid": str(uuid4()),
                "attachment_kind": "image_component",
                "attachment_count_bucket": "1",
                "caption_present": False,
                "enqueue_monotonic_ns": 1,
                "file_id": "forbidden",
            }
        ).encode()
        self.assertIsNone(handle_event(invalid))

    def test_expired_envelope_is_not_enqueued(self) -> None:
        calls = []
        result = auth.authenticate_and_enqueue(
            envelope(raw_timestamp=(NOW - timedelta(minutes=6)).timestamp()),
            config=auth.AuthConfig("binding-owner", "principal-owner", "namespace-owner", "telegram-owner-dev"),
            signing_secret=SECRET,
            identity_pepper=PEPPER,
            limiter=auth.SlidingRateLimiter(),
            now=NOW,
            claim=lambda *_: calls.append("claim") or True,
            owner_verified=lambda *_: True,
            record=lambda *_: True,
            enqueue=lambda *_: calls.append("enqueue") or "enqueued",
        )
        self.assertFalse(result)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
