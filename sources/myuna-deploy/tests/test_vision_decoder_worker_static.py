from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "systemd" / "myuna-vision-decoder-shadow-v1.service"
SOCKET = ROOT / "systemd" / "myuna-vision-decoder-shadow-v1.socket"
WORKER = (
    ROOT
    / "components"
    / "vision-decoder-worker"
    / "myuna_media_decoder"
    / "worker.py"
)


class VisionDecoderWorkerStaticTests(unittest.TestCase):
    def test_service_has_resource_and_network_confinement(self) -> None:
        text = SERVICE.read_text(encoding="utf-8")
        for required in (
            "User=myuna_media_decoder",
            "CPUQuota=100%",
            "MemoryMax=384M",
            "TasksMax=16",
            "PrivateNetwork=true",
            "RestrictAddressFamilies=AF_UNIX",
            "IPAddressDeny=any",
            "ProtectSystem=strict",
            "NoNewPrivileges=true",
            "ConditionPathExists=/etc/myuna-gateway/vision-decoder-shadow-v1-enabled",
        ):
            self.assertIn(required, text)

    def test_socket_is_private_and_marker_gated(self) -> None:
        text = SOCKET.read_text(encoding="utf-8")
        for required in (
            "ListenStream=/run/myuna-vision-decoder/decoder.sock",
            "SocketGroup=myuna-gateway",
            "SocketMode=0620",
            "DirectoryMode=0755",
            "ConditionPathExists=/etc/myuna-gateway/vision-decoder-shadow-v1-enabled",
        ):
            self.assertIn(required, text)

    def test_worker_has_no_channel_model_memory_or_network_client(self) -> None:
        text = WORKER.read_text(encoding="utf-8").lower()
        for forbidden in (
            "telegram",
            "bot-token",
            "deepseek",
            "openai",
            "memory",
            "requests",
            "urllib",
            "http://",
            "https://",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
