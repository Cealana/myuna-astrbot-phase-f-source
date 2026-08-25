from __future__ import annotations

from datetime import datetime, timezone
import json
import unittest
from unittest.mock import patch

from tests import test_astrbot_telegram_gateway as p01b
from tests import test_telegram_owner_channel_r2 as owner_r2


class _Connection:
    def __init__(self) -> None:
        self.response = b""

    def sendall(self, value: bytes) -> None:
        self.response += value


class _Epoch:
    def __init__(self, readiness: str) -> None:
        self.readiness = readiness
        self.calls = 0

    def projection_readiness(self, _context) -> str:
        self.calls += 1
        return self.readiness


class P01BVisualPreflightV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = owner_r2.TelegramOwnerRuntimeR2Tests()
        self.fixture.setUp()

    def _envelope(self) -> dict[str, object]:
        current = datetime.now(timezone.utc)
        return owner_r2.protocol.build_signed_envelope(
            sender_id="123456789",
            message_text="Synthetic authenticated Caption.",
            message_id="preflight-synthetic-42",
            raw_timestamp=current.timestamp(),
            signing_secret=self.fixture.signing_secret,
            channel_instance="telegram-owner-dev",
            now=current,
            nonce_factory=lambda: "p" * 32,
        )

    def test_signed_preflight_and_typed_responses_are_strictly_bounded(self) -> None:
        payload = owner_r2.protocol.attach_visual_preflight(self._envelope())
        self.assertEqual(
            payload["routing"],
            owner_r2.protocol.VISUAL_PREFLIGHT_ROUTING,
        )
        self.assertEqual(set(payload), {"event", "routing", "signature"})

        for kind, detail in (
            ("visual_preflight_ready", None),
            ("visual_preflight_unavailable", "external_summary_required"),
            ("context_projection_unavailable", "external_turn_already_pending"),
        ):
            response = {"kind": kind, "schema": owner_r2.protocol.GATEWAY_RESPONSE_SCHEMA}
            if detail is not None:
                response["safe_detail_code"] = detail
            decoded = owner_r2.protocol.decode_gateway_response(
                json.dumps(response, separators=(",", ":")).encode("ascii")
            )
            self.assertEqual(decoded["kind"], kind)

        with self.assertRaises(owner_r2.protocol.GatewayTransportError):
            owner_r2.protocol.decode_gateway_response(
                b'{"kind":"visual_preflight_unavailable",'
                b'"safe_detail_code":"raw-private-detail",'
                b'"schema":"myuna.gateway-response.v3"}'
            )

    def test_runtime_preflight_is_read_only_and_stops_before_claim_or_core(self) -> None:
        payload = owner_r2.protocol.attach_visual_preflight(self._envelope())
        for readiness, expected_kind in (
            ("ready", "visual_preflight_ready"),
            ("external_summary_required", "visual_preflight_unavailable"),
            ("external_turn_already_pending", "visual_preflight_unavailable"),
        ):
            with self.subTest(readiness=readiness):
                connection = _Connection()
                epoch = _Epoch(readiness)
                with (
                    patch.object(owner_r2.runtime, "resolve_verified_owner", return_value=True),
                    patch.object(
                        owner_r2.runtime,
                        "claim_inbound",
                        side_effect=AssertionError("preflight must not claim"),
                    ),
                ):
                    handled = owner_r2.runtime._process_visual_preflight(
                        connection,
                        payload,
                        config=self.fixture.config,
                        signing_secret=self.fixture.signing_secret,
                        identity_pepper=self.fixture.identity_pepper,
                        hybrid_enabled=True,
                        external_epoch=epoch,
                    )
                self.assertTrue(handled)
                self.assertEqual(epoch.calls, 1)
                decoded = owner_r2.protocol.decode_gateway_response(
                    connection.response.split(b"\n", 1)[0]
                )
                self.assertEqual(decoded["kind"], expected_kind)

    def test_post_provider_failure_never_claims_that_no_model_was_called(self) -> None:
        event = p01b._DummyEvent("123456789", [p01b._DummyPlain("synthetic")])
        rejected = {"status": "rejected", "code": "owner-runtime-rejected"}
        ordinary = p01b.gateway._dispatch_existing_result(event, rejected)
        visual = p01b.gateway._dispatch_existing_result(
            event,
            rejected,
            visual_provider_called=True,
        )
        self.assertIn("未调用模型", ordinary)
        self.assertIn("视觉模型已完成图片证据提取", visual)
        self.assertNotIn("未调用模型", visual)
        self.assertIn("未调用 DeepSeek、记忆或工具", visual)

        typed = {
            "kind": "context_projection_unavailable",
            "safe_detail_code": "external_summary_required",
            "schema": owner_r2.protocol.GATEWAY_RESPONSE_SCHEMA,
        }
        self.assertEqual(
            p01b.gateway._dispatch_existing_result(event, typed),
            p01b.gateway._CONTEXT_PROJECTION_UNAVAILABLE_REPLY,
        )
        self.assertEqual(
            p01b.gateway._dispatch_existing_result(
                event,
                typed,
                visual_provider_called=True,
            ),
            p01b.gateway._VISION_POST_PROVIDER_GATE_FAILURE_REPLY,
        )


if __name__ == "__main__":
    unittest.main()
