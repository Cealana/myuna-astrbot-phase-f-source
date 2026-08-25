from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

from myuna_core.degradation_protocol import SAFE_DEGRADATION_SCHEMA
from myuna_core.natural_degradation import (
    DegradationCategory,
    natural_degradation_text,
)


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_PROTOCOL = (
    ROOT / "channels" / "astrbot-qq" / "plugin" / "myuna_gateway" / "protocol.py"
)
PLUGIN_MAIN = (
    ROOT / "channels" / "astrbot-qq" / "plugin" / "myuna_gateway" / "main.py"
)
GATEWAY_PROTOCOL = ROOT / "scripts" / "gateway_degradation_protocol.py"
OWNER_RUNTIME = ROOT / "scripts" / "qq_owner_runtime_gateway.py"
GOLDEN = (
    ROOT
    / "tests"
    / "fixtures"
    / "natural_degradation_r2b_gateway_astrbot_golden.json"
)


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


plugin_protocol = _load_module("myuna_r2b_plugin_protocol_test", PLUGIN_PROTOCOL)
gateway_protocol = _load_module("myuna_r2b_gateway_protocol_test", GATEWAY_PROTOCOL)


class NaturalDegradationR2BProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.golden = json.loads(GOLDEN.read_text(encoding="utf-8"))

    def projection(self, category: str) -> dict[str, object]:
        detail = f"{category}-test"
        return {
            "schema": self.golden["safe_degradation_schema"],
            "status": "degraded",
            "category": category,
            "retryable": True,
            "owner_action_required": False,
            "safe_detail_code": detail,
            "recovery_state": "active",
            "fingerprint": f"{category}:core:{detail}",
            "reply": self.golden["canonical_replies"][category],
        }

    def test_golden_canonical_replies_match_both_process_boundaries(self) -> None:
        expected = self.golden["canonical_replies"]
        self.assertEqual(gateway_protocol.CANONICAL_DEGRADATION_REPLIES, expected)
        self.assertEqual(plugin_protocol._CANONICAL_DEGRADATION_REPLIES, expected)

    def test_golden_contract_matches_the_formal_core_r2a_public_api(self) -> None:
        expected = {
            category.value: natural_degradation_text(category)
            for category in DegradationCategory
        }
        self.assertEqual(self.golden["safe_degradation_schema"], SAFE_DEGRADATION_SCHEMA)
        self.assertEqual(self.golden["canonical_replies"], expected)

    def test_every_golden_category_round_trips_gateway_to_astrbot(self) -> None:
        for category in self.golden["canonical_replies"]:
            with self.subTest(category=category):
                projection = self.projection(category)
                response = gateway_protocol.safe_degraded_reply_payload(projection)
                encoded = gateway_protocol.encode_gateway_response(response)
                decoded = plugin_protocol.decode_gateway_response(encoded)
                self.assertEqual(decoded["kind"], "safe_degraded_reply")
                self.assertEqual(decoded["degradation"], projection)

    def test_v2_accepted_reply_round_trips_without_changing_text(self) -> None:
        response = gateway_protocol.accepted_reply_payload("  嗯，收到了哦  ")
        decoded = plugin_protocol.decode_gateway_response(
            gateway_protocol.encode_gateway_response(response)
        )
        self.assertEqual(
            decoded,
            {
                "kind": "accepted_reply",
                "reply": "嗯，收到了哦",
                "schema": self.golden["gateway_response_schema"],
            },
        )

    def test_core_unreachable_fallback_is_fixed_content_free_and_golden(self) -> None:
        projection = gateway_protocol.deterministic_core_unreachable_projection()
        self.assertEqual(projection, self.golden["core_unreachable_projection"])
        response = gateway_protocol.safe_degraded_reply_payload(projection)
        decoded = plugin_protocol.decode_gateway_response(
            gateway_protocol.encode_gateway_response(response)
        )
        self.assertEqual(decoded["degradation"]["reply"], projection["reply"])
        self.assertNotIn("exception", json.dumps(projection, ensure_ascii=False).lower())

    def test_existing_v1_normal_and_rejection_shapes_remain_compatible(self) -> None:
        accepted = plugin_protocol.decode_gateway_response(
            b'{"code":"owner-runtime-reply","reply":" ok ","status":"accepted"}'
        )
        rejected = plugin_protocol.decode_gateway_response(
            b'{"code":"owner-runtime-unavailable","status":"rejected"}'
        )
        self.assertEqual(accepted["reply"], "ok")
        self.assertEqual(rejected["code"], "owner-runtime-unavailable")

    def test_free_form_or_noncanonical_degradation_reply_is_rejected(self) -> None:
        payload = self.projection("provider_transient_failure")
        payload["reply"] = "上游返回的自然语言，或者让失败的模型解释自己"
        with self.assertRaises(gateway_protocol.GatewayDegradationProtocolError):
            gateway_protocol.safe_degraded_reply_payload(payload)
        response = {
            "schema": self.golden["gateway_response_schema"],
            "kind": "safe_degraded_reply",
            "degradation": payload,
        }
        with self.assertRaises(plugin_protocol.GatewayTransportError):
            plugin_protocol.decode_gateway_response(
                json.dumps(response, ensure_ascii=False).encode("utf-8")
            )

    def test_unknown_protocol_category_and_recovery_versions_fail_closed(self) -> None:
        mutations = (
            ("schema", "myuna.safe-degradation.v999"),
            ("category", "free_form_failure"),
            ("recovery_state", "maybe"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                payload = self.projection("core_or_gateway_failure")
                payload[field] = value
                with self.assertRaises(
                    gateway_protocol.GatewayDegradationProtocolError
                ):
                    gateway_protocol.safe_degraded_reply_payload(payload)

    def test_extra_outer_or_inner_fields_fail_closed(self) -> None:
        payload = self.projection("core_or_gateway_failure")
        payload["raw_error"] = "synthetic upstream body"
        with self.assertRaises(gateway_protocol.GatewayDegradationProtocolError):
            gateway_protocol.safe_degraded_reply_payload(payload)

        valid = self.projection("core_or_gateway_failure")
        response = gateway_protocol.safe_degraded_reply_payload(valid)
        response["trace_id"] = "not-allowed"
        with self.assertRaises(gateway_protocol.GatewayDegradationProtocolError):
            gateway_protocol.encode_gateway_response(response)

    def test_integer_boolean_values_are_rejected(self) -> None:
        for field in ("retryable", "owner_action_required"):
            with self.subTest(field=field):
                payload = self.projection("provider_transient_failure")
                payload[field] = 1
                with self.assertRaises(
                    gateway_protocol.GatewayDegradationProtocolError
                ):
                    gateway_protocol.safe_degraded_reply_payload(payload)

    def test_unsafe_detail_and_fingerprint_are_rejected(self) -> None:
        payload = self.projection("core_or_gateway_failure")
        payload["safe_detail_code"] = "raw failure: user text\n"
        with self.assertRaises(gateway_protocol.GatewayDegradationProtocolError):
            gateway_protocol.safe_degraded_reply_payload(payload)
        payload = self.projection("core_or_gateway_failure")
        payload["fingerprint"] = "x" * 385
        with self.assertRaises(gateway_protocol.GatewayDegradationProtocolError):
            gateway_protocol.safe_degraded_reply_payload(payload)

    def test_gateway_response_byte_limit_is_enforced_after_utf8_encoding(self) -> None:
        response = gateway_protocol.accepted_reply_payload("字" * 2000)
        with self.assertRaises(gateway_protocol.GatewayDegradationProtocolError):
            gateway_protocol.encode_gateway_response(response)

    def test_unknown_v2_kind_and_schema_fail_closed_at_astrbot(self) -> None:
        valid = gateway_protocol.accepted_reply_payload("ok")
        for field, value in (
            ("kind", "model_generated_error"),
            ("schema", "myuna.gateway-response.v999"),
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(valid)
                payload[field] = value
                with self.assertRaises(plugin_protocol.GatewayTransportError):
                    plugin_protocol.decode_gateway_response(
                        json.dumps(payload).encode("utf-8")
                    )

    def test_astrbot_displays_only_the_validated_reply_and_keeps_llm_disabled(self) -> None:
        source = PLUGIN_MAIN.read_text(encoding="utf-8")
        self.assertIn('result.get("kind") == "safe_degraded_reply"', source)
        self.assertIn('result["degradation"]["reply"]', source)
        self.assertIn("event.should_call_llm(False)", source)
        self.assertIn("event.stop_event()", source)

    def test_r2c_uses_validation_for_shadow_but_not_the_visible_reply_encoder(self) -> None:
        source = OWNER_RUNTIME.read_text(encoding="utf-8")
        self.assertIn("gateway_degradation_protocol", source)
        self.assertIn("validate_core_failure_response", source)
        self.assertIn("deterministic_gateway_projection", source)
        self.assertNotIn("myuna.gateway-response.v2", source)
        self.assertNotIn("safe_degraded_reply", source)
        self.assertNotIn("safe_degraded_reply_payload", source)
        self.assertNotIn("encode_gateway_response", source)

    def test_protocol_rejections_do_not_echo_rejected_payloads(self) -> None:
        secret_marker = "synthetic-secret-marker"
        payload = self.projection("core_or_gateway_failure")
        payload["raw_error"] = secret_marker
        try:
            gateway_protocol.safe_degraded_reply_payload(payload)
        except gateway_protocol.GatewayDegradationProtocolError as exc:
            self.assertNotIn(secret_marker, str(exc))
        else:
            self.fail("invalid payload was accepted")


if __name__ == "__main__":
    unittest.main()
