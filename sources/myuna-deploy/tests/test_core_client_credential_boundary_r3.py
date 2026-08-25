from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from myuna_core.authenticated_conversation import AuthenticatedConversationContext


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


qq_runtime = _load(
    "qq_owner_runtime_gateway_r3_boundary_test",
    SCRIPTS / "qq_owner_runtime_gateway.py",
)
telegram_runtime = _load(
    "telegram_owner_runtime_gateway_r3_boundary_test",
    SCRIPTS / "telegram_owner_runtime_gateway.py",
)


class CoreClientCredentialBoundaryR3Tests(unittest.TestCase):
    def _exercise(self, runtime, config, expected_client: str, expected_channel: str):
        captured: dict[str, object] = {}
        raw = json.dumps(
            {
                "actual_route": "deepseek_default",
                "reply": "ok",
                "synthetic_memory": {"used": False},
            }
        ).encode("utf-8")

        class Response:
            status = 200

            def read(self, _limit):
                return raw

        class Connection:
            def __init__(self, *_args, **_kwargs):
                pass

            def request(self, method, path, *, body, headers):
                captured.update(
                    method=method,
                    path=path,
                    body=body,
                    headers=dict(headers),
                )

            def getresponse(self):
                return Response()

            def close(self):
                pass

        decision = runtime.RuntimeDecision(
            event_id="event-synthetic-1",
            channel_kind=expected_channel,
            channel_instance=config.channel_instance,
            conversation_id="conversation-synthetic-1",
            occurred_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
            nonce_fingerprint="c" * 64,
            payload_sha256="d" * 64,
            trace_id="trace-synthetic-1",
            account_fingerprint="e" * 64,
            message_text="private",
        )
        with patch.object(runtime, "HTTPConnection", Connection):
            reply = runtime.LoopbackCoreClient(config, b"synthetic-token").chat(
                [{"role": "user", "content": "private"}],
                decision=decision,
            )
        self.assertEqual(reply.reply, "ok")
        decoded = json.loads(captured["body"].decode("utf-8"))
        self.assertEqual(
            set(decoded), {"authenticated_context", "conversation"}
        )
        self.assertEqual(decoded["authenticated_context"]["client_id"], expected_client)
        self.assertEqual(decoded["authenticated_context"]["channel_kind"], expected_channel)
        parsed_context = AuthenticatedConversationContext.from_payload(
            decoded["authenticated_context"],
            authenticated_client_id=expected_client,
            authenticated_channel_kind=expected_channel,
        )
        self.assertEqual(parsed_context.principal_id, config.principal_id)
        self.assertEqual(parsed_context.namespace_id, config.namespace_id)
        self.assertFalse(parsed_context.consent_memory_candidate)
        self.assertEqual(decoded["conversation"]["messages"][0]["content"], "private")
        headers = captured["headers"]
        self.assertEqual(headers["X-Myuna-Client-Id"], expected_client)
        self.assertEqual(headers["X-Myuna-Channel-Kind"], expected_channel)
        self.assertEqual(headers["Authorization"], "Bearer synthetic-token")
        return headers

    def test_qq_runtime_uses_only_fixed_qq_core_identity(self) -> None:
        config = qq_runtime.RuntimeConfig(
            binding_id="binding-astrbot-qq-owner-cealana",
            principal_id="principal-owner-cealana",
            namespace_id="ns-owner-cealana-private",
            finalization_digest="a" * 64,
            evidence_sha256="b" * 64,
            channel_instance="napcat-dev",
            core_host="127.0.0.1",
            core_port=18081,
            max_requests_per_ten_minutes=12,
            max_history_messages=12,
            max_history_characters=12000,
        )
        self._exercise(
            qq_runtime,
            config,
            "qq-owner-private",
            "astrbot_qq",
        )

    def test_telegram_runtime_uses_only_fixed_telegram_core_identity(self) -> None:
        config = telegram_runtime.RuntimeConfig(
            channel_kind="astrbot_telegram",
            binding_id="binding-astrbot-telegram-owner-cealana",
            principal_id="principal-owner-cealana",
            namespace_id="ns-owner-cealana-private",
            finalization_digest="a" * 64,
            evidence_sha256="b" * 64,
            channel_instance="telegram-owner-dev",
            core_host="127.0.0.1",
            core_port=18081,
            max_requests_per_ten_minutes=12,
            max_history_messages=12,
            max_history_characters=12000,
        )
        self._exercise(
            telegram_runtime,
            config,
            "telegram-owner-private",
            "astrbot_telegram",
        )

    def test_channel_core_identities_are_distinct_constants(self) -> None:
        self.assertNotEqual(
            qq_runtime.CORE_CLIENT_ID,
            telegram_runtime.CORE_CLIENT_ID,
        )
        self.assertNotEqual(
            qq_runtime.CHANNEL_KIND,
            telegram_runtime.CHANNEL_KIND,
        )


if __name__ == "__main__":
    unittest.main()
