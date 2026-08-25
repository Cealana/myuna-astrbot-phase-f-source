from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeploymentContractTests(unittest.TestCase):
    def test_socket_is_parallel_and_owner_only(self) -> None:
        text = (ROOT / "deploy/myuna-owner-memory-read-v2.socket").read_text("utf-8")
        self.assertIn("/run/myuna-owner-memory-read-v2/worker.sock", text)
        self.assertIn("SocketUser=myuna_memory_runtime", text)
        self.assertIn("SocketGroup=myuna", text)
        self.assertIn("SocketMode=0660", text)
        self.assertNotIn("owner-memory-read-v1/worker.sock", text)

    def test_service_uses_fixed_release_and_hardening(self) -> None:
        text = (ROOT / "deploy/myuna-owner-memory-read-v2.service").read_text("utf-8")
        self.assertIn("/releases/r2-20260721", text)
        self.assertIn("User=myuna_memory_runtime", text)
        self.assertIn("PrivateNetwork=true", text)
        self.assertIn("ProtectSystem=strict", text)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", text)
        self.assertIn("CapabilityBoundingSet=", text)
        self.assertNotIn("EnvironmentFile=", text)

    def test_tmpfiles_does_not_touch_v1(self) -> None:
        text = (ROOT / "deploy/myuna-owner-memory-read-v2.tmpfiles.conf").read_text(
            "utf-8"
        )
        self.assertEqual(
            text.strip(),
            "d /run/myuna-owner-memory-read-v2 0750 myuna_memory_runtime myuna -",
        )


if __name__ == "__main__":
    unittest.main()
