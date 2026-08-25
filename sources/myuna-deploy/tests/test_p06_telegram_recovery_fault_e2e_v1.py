from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import p06_telegram_recovery_fault_e2e_v1 as fault  # noqa: E402


class P06TelegramRecoveryFaultE2ETests(unittest.TestCase):
    def test_render_changes_only_core_port(self) -> None:
        payload = {
            "binding_id": "binding",
            "channel_kind": "telegram",
            "core_host": "127.0.0.1",
            "core_port": 8080,
            "namespace_id": "namespace",
        }
        rendered = json.loads(
            fault.render_fault_config(payload, 65431).decode("utf-8")
        )
        self.assertEqual(rendered["core_port"], 65431)
        expected = dict(payload)
        expected["core_port"] = 65431
        self.assertEqual(rendered, expected)

    def test_render_rejects_invalid_ports_and_missing_original(self) -> None:
        with self.assertRaises(fault.FaultRejected):
            fault.render_fault_config({"core_port": 8080}, 80)
        with self.assertRaises(fault.FaultRejected):
            fault.render_fault_config({}, 65431)

    def test_controller_preserves_runtime_identity_metadata(self) -> None:
        source = (
            ROOT / "scripts/p06_telegram_recovery_fault_e2e_v1.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "os.fchown(file_descriptor, metadata.uid, metadata.gid)",
            source,
        )
        self.assertIn(
            "ProtectedMetadata(uid=0, gid=_service_gid(), mode=0o640)",
            source,
        )
        self.assertIn("original_gid", source)
        self.assertIn("runtime stability rejected", source)

    def test_controller_is_telegram_owner_only_and_retains_evidence(self) -> None:
        source = (
            ROOT / "scripts/p06_telegram_recovery_fault_e2e_v1.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'SERVICE = "myuna-telegram-owner-runtime-dev.service"',
            source,
        )
        self.assertNotIn("myuna-core@qq.service", source)
        self.assertNotIn("docker", source)
        self.assertNotIn("/healthz", source)
        self.assertNotIn("/readyz", source)
        self.assertNotIn("shutil.rmtree", source)
        self.assertNotIn("STATE.unlink", source)
        self.assertIn("FAULT_E2E_STATE.previous.json", source)

    def test_state_is_content_free(self) -> None:
        source = (
            ROOT / "scripts/p06_telegram_recovery_fault_e2e_v1.py"
        ).read_text(encoding="utf-8")
        state_block = source.split(
            'state: dict[str, object] = {', 1
        )[1].split("}", 1)[0]
        for forbidden in (
            "binding_id",
            "principal_id",
            "namespace_id",
            "channel_instance",
            "message",
            "chat_id",
            "token",
            "secret",
        ):
            self.assertNotIn(forbidden, state_block)


if __name__ == "__main__":
    unittest.main()
