from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "host_cold_boot_readiness_v1.py"
SPEC = importlib.util.spec_from_file_location("host_cold_boot_readiness_v1", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class HostColdBootReadinessTests(unittest.TestCase):
    def test_all_expected_state_is_ready(self) -> None:
        with (
            mock.patch.object(module, "unit_state", return_value="active"),
            mock.patch.object(module, "system_state", return_value="running"),
            mock.patch.object(module, "container_state") as container,
            mock.patch.object(module, "archives_ready", return_value=(True, 2)),
            mock.patch.object(
                module,
                "network_ready",
                return_value={"default_route": True, "dns": True},
            ),
            mock.patch.object(module, "receipt_ready", return_value=True),
        ):
            container.side_effect = lambda name: module.EXPECTED_CONTAINERS[name]
            with mock.patch.dict(
                module.__dict__,
                {
                    "ISOLATED_UNITS": (),
                },
            ):
                result = module.collect()
        self.assertTrue(result["ready"])

    def test_isolated_unit_or_container_drift_fails_closed(self) -> None:
        def units(name: str) -> str:
            return "active" if name in module.REQUIRED_UNITS else "inactive"

        with (
            mock.patch.object(module, "unit_state", side_effect=units),
            mock.patch.object(
                module,
                "system_state",
                return_value="degraded-allowlisted",
            ),
            mock.patch.object(module, "container_state") as container,
            mock.patch.object(module, "archives_ready", return_value=(True, 2)),
            mock.patch.object(
                module,
                "network_ready",
                return_value={"default_route": True, "dns": True},
            ),
            mock.patch.object(module, "receipt_ready", return_value=True),
        ):
            container.side_effect = lambda name: (
                "running|healthy|wrong-project|astrbot-telegram|on-failure|3"
                if name == "myuna-astrbot-telegram-dev"
                else module.EXPECTED_CONTAINERS[name]
            )
            self.assertFalse(module.collect()["ready"])

    def test_unexpected_degraded_unit_fails_closed(self) -> None:
        with mock.patch.object(module, "run") as run:
            run.side_effect = [
                mock.Mock(returncode=1, stdout="degraded\n"),
                mock.Mock(
                    returncode=0,
                    stdout="unexpected.service loaded failed failed unexpected\n",
                ),
            ]
            self.assertEqual(module.system_state(), "not-ready")

    def test_source_contains_no_http_or_real_message_path(self) -> None:
        text = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("/healthz", text)
        self.assertNotIn("/readyz", text)
        self.assertNotIn("sendMessage", text)
        self.assertNotIn("chat/completions", text)
        self.assertNotIn("requests.", text)
        self.assertNotIn("http.client", text)

    def test_windows_task_is_bounded_and_does_not_enable_autologon(self) -> None:
        installer = (
            ROOT / "scripts" / "windows" / "Install-MyunaHostColdBootTask.ps1"
        ).read_text(encoding="utf-8")
        launcher = (
            ROOT / "scripts" / "windows" / "Start-MyunaHostColdBoot.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("-RestartCount 12", installer)
        self.assertIn("-RestartInterval", installer)
        self.assertIn("-LogonType Interactive", installer)
        self.assertIn("-RunLevel Limited", installer)
        self.assertIn("$env:ProgramFiles", installer)
        self.assertNotIn("AutoAdminLogon", installer)
        self.assertNotIn("DefaultPassword", installer)
        self.assertNotIn("healthz", launcher)
        self.assertNotIn("readyz", launcher)
        self.assertIn("Get-NetRoute", launcher)
        self.assertIn("HardwareInterface", launcher)
        self.assertIn("DestinationPrefix '0.0.0.0/0'", launcher)
        self.assertNotIn("Get-NetAdapter -Name 'WLAN'", launcher)
        self.assertIn("AddSeconds(390)", launcher)
        self.assertIn("Get-Process -Name 'cc-switch'", launcher)
        self.assertIn("Get-ItemPropertyValue", launcher)
        self.assertIn("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", launcher)
        self.assertIn("running-with-run-entry", launcher)
        self.assertIn("PandaFan Elevated AutoStart", launcher)
        self.assertIn("Principal.RunLevel.ToString() -eq 'Highest'", launcher)
        self.assertIn("Start-PandaFanAutoconnect.ps1", launcher)
        self.assertIn("Get-PandaFanApplicationState", launcher)
        self.assertIn("connect_state.status", launcher)
        self.assertIn("configFile.LastWriteTimeUtc", launcher)
        self.assertIn("DateTimeOffset]::Parse($windowsBootTime)", launcher)
        self.assertIn("connected-and-tun-up", launcher)
        self.assertIn("'http://127.0.0.1:10079/configs'", launcher)
        self.assertIn("-Method Patch", launcher)
        self.assertIn("'{\"tun\":{\"enable\":true}}'", launcher)
        self.assertIn("pandafan-tun-enable-requested", launcher)
        self.assertIn("ChatGPT.lnk", launcher)
        self.assertIn("MainWindowHandle", launcher)
        self.assertIn("Get-Process -Name 'codex'", launcher)
        self.assertIn("Test-ControllerLauncher", launcher)
        self.assertIn("CONTROLLER_LAUNCHER_EXITED", launcher)
        self.assertIn("controller-launcher-exited", launcher)
        self.assertIn("Start-Sleep -Seconds 3", launcher)
        self.assertIn("$keepAlive.WaitForExit(3000)", launcher)
        self.assertNotIn("Start-Sleep -Milliseconds 500", launcher)

    def test_pandafan_wrapper_is_bounded_and_preserves_private_config(self) -> None:
        wrapper = (
            ROOT / "scripts" / "windows" / "Start-PandaFanAutoconnect.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("auto_connect_on_start", wrapper)
        self.assertIn("user_disconnected", wrapper)
        self.assertIn("last_connect_line", wrapper)
        self.assertIn("connect_state.status", wrapper)
        self.assertIn("PandaFanHealthWatchdog-26856", wrapper)
        self.assertIn("pandafan-autoconnect-watchdog-owned", wrapper)
        self.assertNotIn("PANDAFAN_STARTUP_MUTEX_REJECTED", wrapper)
        self.assertIn("$attempt -le 2", wrapper)
        self.assertIn("AddSeconds(90)", wrapper)
        self.assertIn("configLastWrite -ge $attemptStartedAt", wrapper)
        self.assertIn("[System.IO.File]::Replace", wrapper)
        self.assertNotIn("ConvertTo-Json -Depth", wrapper)
        self.assertNotIn("selected_line", wrapper)
        self.assertNotIn("Write-Output", wrapper)


if __name__ == "__main__":
    unittest.main()
