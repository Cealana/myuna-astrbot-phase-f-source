from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "systemd" / "myuna-turn-route-shadow-dev.service"
SOCKET = ROOT / "systemd" / "myuna-turn-route-shadow-dev.socket"
CONFIG = ROOT / "config" / "turn-route-shadow-v1.json"
CLASSIFIER = ROOT / "scripts" / "turn_route_shadow" / "hybrid_classifier.py"
WORKER = ROOT / "scripts" / "turn_route_shadow" / "worker.py"
POST_REPLY = ROOT / "scripts" / "gateway_post_reply.py"
VALIDATION = ROOT / "docs" / "turn-route-shadow-r1-validation.json"
APPROVED_PLAN = ROOT / "docs" / "turn-route-shadow-r1-approved-plan.json"
README = ROOT / "README.md"


class TurnRouteShadowStaticTests(unittest.TestCase):
    def test_classifier_is_the_frozen_accepted_candidate(self) -> None:
        digest = hashlib.sha256(CLASSIFIER.read_bytes()).hexdigest()
        self.assertEqual(
            digest,
            "3a961875e11e0deb1aa48c5068a84e1fbdacd8b467e1a07e171078d47d8abc2b",
        )

    def test_exact_approved_plan_is_archived_with_the_candidate(self) -> None:
        digest = hashlib.sha256(APPROVED_PLAN.read_bytes()).hexdigest()
        self.assertEqual(
            digest,
            "aa63fb418623bc7780fc8dadd70c12651a07640488ae10e4fe5a9e7dcf22676f",
        )

    def test_systemd_template_has_no_credentials_or_broad_network(self) -> None:
        service = SERVICE.read_text(encoding="utf-8")
        socket_unit = SOCKET.read_text(encoding="utf-8")
        self.assertIn("User=myuna_shadow_classifier", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ProtectHome=yes", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET", service)
        self.assertIn("IPAddressDeny=any", service)
        self.assertIn("IPAddressAllow=127.0.0.1/32", service)
        self.assertIn("CapabilityBoundingSet=\n", service)
        self.assertNotIn("LoadCredential", service)
        self.assertNotIn("PrivateNetwork=yes", service)
        self.assertIn("ConditionPathExists=/etc/myuna-gateway/qq-owner-turn-route", service)
        self.assertIn("ListenDatagram=/run/myuna-turn-route-shadow-dev/shadow.sock", socket_unit)
        self.assertIn("SocketGroup=myuna-gateway", socket_unit)
        self.assertIn("SocketMode=0620", socket_unit)

    def test_runtime_config_loader_requires_root_owned_nonwritable_file(self) -> None:
        worker = WORKER.read_text(encoding="utf-8")
        self.assertIn("metadata.st_uid != 0", worker)
        self.assertIn("mode & 0o022", worker)

    def test_committed_config_is_inactive_and_pinned(self) -> None:
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertFalse(config["model_enabled"])
        self.assertEqual(config["model_endpoint"], "http://127.0.0.1:18093")
        self.assertEqual(config["trace_retention_days"], 7)
        self.assertEqual(
            config["expected_model_sha256"],
            "13c16f426047e2de38cd075bdade4a7bcbc8c774384876f677740cda65f8a983",
        )

    def test_source_contains_no_activation_or_service_control(self) -> None:
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (WORKER, POST_REPLY)
        )
        for forbidden in (
            "systemctl start",
            "systemctl enable",
            "docker restart",
            "wsl.exe --shutdown",
            "schtasks",
            "subprocess.run",
            "os.system",
        ):
            self.assertNotIn(forbidden, combined)

    def test_validation_and_repository_summary_claim_no_activation(self) -> None:
        result = json.loads(VALIDATION.read_text(encoding="utf-8"))
        self.assertFalse(result["activation_performed"])
        self.assertEqual(result["production_effect"], "none")
        self.assertFalse(result["live_state"]["turn_route_units_loaded"])
        readme = README.read_text(encoding="utf-8")
        self.assertIn("repository-only Turn/Route metadata Shadow candidate", readme)
        self.assertIn("No live files", readme)

    def test_post_reply_fanout_is_nonblocking_and_independent(self) -> None:
        text = POST_REPLY.read_text(encoding="utf-8")
        self.assertIn("with connection:", text)
        self.assertIn("_send_memory_shadow", text)
        self.assertIn("_send_turn_route_shadow", text)
        self.assertIn("except Exception:\n        pass", text)
        enqueue = (ROOT / "scripts" / "turn_route_enqueue.py").read_text(encoding="utf-8")
        self.assertIn("client.setblocking(False)", enqueue)
        self.assertNotIn("sleep(", enqueue)
        self.assertNotIn("for attempt", enqueue)
        self.assertNotIn("while True", enqueue)


if __name__ == "__main__":
    unittest.main()
