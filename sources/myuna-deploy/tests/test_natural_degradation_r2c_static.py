from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "systemd/myuna-natural-degradation-shadow-dev.service"
SOCKET = ROOT / "systemd/myuna-natural-degradation-shadow-dev.socket"
WORKER = ROOT / "scripts/degradation_shadow/worker.py"
ENQUEUE = ROOT / "scripts/degradation_shadow_enqueue.py"
POST_REPLY = ROOT / "scripts/gateway_post_reply.py"
RUNTIME = ROOT / "scripts/qq_owner_runtime_gateway.py"


class NaturalDegradationR2CStaticTests(unittest.TestCase):
    def test_worker_has_no_credentials_network_or_privileged_identity(self) -> None:
        service = SERVICE.read_text(encoding="utf-8")
        socket_unit = SOCKET.read_text(encoding="utf-8")
        self.assertIn("User=myuna_degradation_shadow", service)
        self.assertIn("Group=myuna_degradation_shadow", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", service)
        self.assertIn("IPAddressDeny=any", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("CapabilityBoundingSet=", service)
        self.assertNotIn("LoadCredential=", service)
        self.assertNotIn("AF_INET", service)
        self.assertIn("SocketGroup=myuna-gateway", socket_unit)
        self.assertIn("SocketMode=0620", socket_unit)
        self.assertIn("ConditionPathExists=", service)
        self.assertIn("ConditionPathExists=", socket_unit)

    def test_worker_uses_its_own_top_level_private_log_directory(self) -> None:
        service = SERVICE.read_text(encoding="utf-8")
        self.assertIn(
            "LogsDirectory=myuna-natural-degradation-shadow",
            service,
        )
        self.assertIn(
            "--trace /var/log/myuna-natural-degradation-shadow/trace.jsonl",
            service,
        )
        self.assertNotIn("/var/log/myuna/natural-degradation-shadow", service)
        self.assertNotIn("SupplementaryGroups=myuna", service)

    def test_shadow_modules_have_no_model_memory_tool_or_remote_client(self) -> None:
        text = (
            WORKER.read_text(encoding="utf-8")
            + "\n"
            + ENQUEUE.read_text(encoding="utf-8")
        )
        for forbidden in (
            "DeepSeek",
            "OpenAI",
            "HTTPConnection",
            "urllib",
            "requests",
            "subprocess",
            "docker",
            "memory_store",
            "tool_call",
        ):
            self.assertNotIn(forbidden, text)

    def test_runtime_keeps_shadow_after_response_and_outside_astrbot(self) -> None:
        post_reply = POST_REPLY.read_text(encoding="utf-8")
        runtime = RUNTIME.read_text(encoding="utf-8")
        self.assertIn("with connection:", post_reply)
        self.assertIn("_send_degradation_shadow", post_reply)
        self.assertIn("DEGRADATION_SHADOW_MARKER", post_reply)
        self.assertIn('_respond(connection, "unavailable")', runtime)
        self.assertIn("return _degradation_fanout(", runtime)
        self.assertNotIn("safe_degraded_reply_payload", runtime)
        self.assertNotIn("encode_gateway_response", runtime)

    def test_worker_trace_contract_forbids_content_bearing_keys(self) -> None:
        worker = WORKER.read_text(encoding="utf-8")
        self.assertIn('"shadow_only": True', worker)
        self.assertIn('"production_effect": "none"', worker)
        for required in (
            '"message"',
            '"prompt"',
            '"reply"',
            '"account"',
            '"qq"',
            '"credential"',
            '"secret"',
            '"token"',
            '"memory"',
        ):
            self.assertIn(required, worker)


if __name__ == "__main__":
    unittest.main()
