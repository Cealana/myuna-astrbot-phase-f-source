from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import json
import socket
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.config import load_settings
from myuna_core.http_api import build_server
from myuna_core.http_client_auth import LoadedHttpClientCredential


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


class HttpApiTests(unittest.TestCase):
    def test_health_is_live_while_readiness_is_closed(self) -> None:
        with TemporaryDirectory() as temp:
            settings = load_settings(
                {
                    "MYUNA_ENV": "dev",
                    "MYUNA_BIND_HOST": "127.0.0.1",
                    "MYUNA_PORT": str(free_loopback_port()),
                    "MYUNA_DATA_DIR": temp,
                    "MYUNA_LOG_DIR": temp,
                }
            )
            audit = AuditLogger(Path(temp), "dev")
            server = build_server(settings, audit)
            port = server.server_address[1]
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3) as response:
                    payload = json.load(response)
                    self.assertEqual(response.status, 200)
                    self.assertEqual(payload["status"], "alive")

                with self.assertRaises(HTTPError) as caught:
                    urlopen(f"http://127.0.0.1:{port}/readyz", timeout=3)
                self.assertEqual(caught.exception.code, 503)
                payload = json.loads(caught.exception.read().decode("utf-8"))
                self.assertIn("no_approved_definition", payload["reasons"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_chat_requires_bearer_token_and_does_not_log_content(self) -> None:
        class Result:
            def public_payload(self):
                return {"request_id": "test", "reply": "在。"}

        class Engine:
            def __init__(self):
                self.payload = None

            def converse(self, payload, *, request_id):
                self.payload = payload
                return Result()

        with TemporaryDirectory() as temp:
            settings = load_settings(
                {
                    "MYUNA_ENV": "dev",
                    "MYUNA_BIND_HOST": "127.0.0.1",
                    "MYUNA_PORT": str(free_loopback_port()),
                    "MYUNA_DATA_DIR": temp,
                    "MYUNA_LOG_DIR": temp,
                    "MYUNA_DEFINITION_RELEASE": "v5-test-release",
                    "MYUNA_DEFINITION_PATH": "/unused/release",
                    "MYUNA_CAPABILITY_MANIFEST": "/unused/capabilities.json",
                    "MYUNA_PROVIDERS_ENABLED": "deepseek",
                    "MYUNA_DEV_TOKEN_CREDENTIAL": "myuna_dev_token",
                }
            )
            audit = AuditLogger(Path(temp), "dev")
            engine = Engine()
            server = build_server(settings, audit, engine=engine, dev_token="test-token")
            port = server.server_address[1]
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = json.dumps(
                    {"messages": [{"role": "user", "content": "这段不能进日志"}]}
                ).encode("utf-8")
                unauthorized = Request(
                    f"http://127.0.0.1:{port}/v1/chat",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(HTTPError) as caught:
                    urlopen(unauthorized, timeout=3)
                self.assertEqual(caught.exception.code, 401)

                authorized = Request(
                    f"http://127.0.0.1:{port}/v1/chat",
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer test-token",
                    },
                    method="POST",
                )
                with urlopen(authorized, timeout=3) as response:
                    payload = json.load(response)
                self.assertEqual(payload["reply"], "在。")
                audit_text = (Path(temp) / "audit.jsonl").read_text(encoding="utf-8")
                self.assertNotIn("这段不能进日志", audit_text)
                self.assertNotIn("test-token", audit_text)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_scoped_clients_require_matching_token_and_identity_headers(self) -> None:
        class Result:
            def public_payload(self):
                return {
                    "request_id": "scoped-test",
                    "reply": "在。",
                    "synthetic_memory": {"used": False},
                }

        class Engine:
            def converse(self, payload, *, request_id):
                return Result()

        with TemporaryDirectory() as temp:
            settings = load_settings(
                {
                    "MYUNA_ENV": "dev",
                    "MYUNA_BIND_HOST": "127.0.0.1",
                    "MYUNA_PORT": str(free_loopback_port()),
                    "MYUNA_DATA_DIR": temp,
                    "MYUNA_LOG_DIR": temp,
                    "MYUNA_DEFINITION_RELEASE": "v5-test-release",
                    "MYUNA_DEFINITION_PATH": "/unused/release",
                    "MYUNA_CAPABILITY_MANIFEST": "/unused/capabilities.json",
                    "MYUNA_PROVIDERS_ENABLED": "deepseek",
                    "MYUNA_HTTP_CLIENT_CREDENTIALS": (
                        "qq-owner-private:astrbot_qq:qq_owner_core_token,"
                        "telegram-owner-private:astrbot_telegram:"
                        "telegram_owner_core_token"
                    ),
                }
            )
            clients = (
                LoadedHttpClientCredential(
                    client_id="qq-owner-private",
                    channel_kind="astrbot_qq",
                    token="qq-owner-test-token",
                ),
                LoadedHttpClientCredential(
                    client_id="telegram-owner-private",
                    channel_kind="astrbot_telegram",
                    token="telegram-owner-test-token",
                ),
            )
            audit = AuditLogger(Path(temp), "dev")
            server = build_server(
                settings,
                audit,
                engine=Engine(),
                http_clients=clients,
            )
            port = server.server_address[1]
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = json.dumps(
                    {"messages": [{"role": "user", "content": "边界测试"}]}
                ).encode("utf-8")

                def send(token: str, client_id: str, channel_kind: str) -> int:
                    candidate = Request(
                        f"http://127.0.0.1:{port}/v1/chat",
                        data=body,
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Content-Type": "application/json",
                            "X-Myuna-Channel-Kind": channel_kind,
                            "X-Myuna-Client-Id": client_id,
                        },
                        method="POST",
                    )
                    try:
                        with urlopen(candidate, timeout=3) as response:
                            return response.status
                    except HTTPError as exc:
                        return exc.code

                self.assertEqual(
                    send(
                        "qq-owner-test-token",
                        "qq-owner-private",
                        "astrbot_qq",
                    ),
                    200,
                )
                self.assertEqual(
                    send(
                        "telegram-owner-test-token",
                        "telegram-owner-private",
                        "astrbot_telegram",
                    ),
                    200,
                )
                self.assertEqual(
                    send(
                        "telegram-owner-test-token",
                        "qq-owner-private",
                        "astrbot_qq",
                    ),
                    401,
                )
                audit_text = (Path(temp) / "audit.jsonl").read_text(
                    encoding="utf-8"
                )
                self.assertIn("qq-owner-private", audit_text)
                self.assertIn("telegram-owner-private", audit_text)
                self.assertIn("astrbot_qq", audit_text)
                self.assertIn("astrbot_telegram", audit_text)
                self.assertNotIn("qq-owner-test-token", audit_text)
                self.assertNotIn("telegram-owner-test-token", audit_text)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
