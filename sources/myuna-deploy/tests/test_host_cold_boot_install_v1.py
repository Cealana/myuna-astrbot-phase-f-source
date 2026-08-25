from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder = load_module(
    "build_host_cold_boot_release_v1_for_install_test",
    ROOT / "scripts" / "build_host_cold_boot_release_v1.py",
)
installer = load_module(
    "install_host_cold_boot_release_v1_for_test",
    ROOT / "scripts" / "install_host_cold_boot_release_v1.py",
)


class HostColdBootInstallTests(unittest.TestCase):
    def test_linux_install_is_exact_atomic_and_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "staging"
            destination = root / "installed"
            release = builder.build(ROOT, staging, "2" * 40)

            first, created = installer.install(
                release,
                release.name,
                destination_root=destination,
                allowed_source_roots=(staging,),
            )
            second, reused = installer.install(
                release,
                release.name,
                destination_root=destination,
                allowed_source_roots=(staging,),
            )

            self.assertTrue(created)
            self.assertFalse(reused)
            self.assertEqual(first, second)
            self.assertEqual(
                {path.name for path in first.iterdir()},
                installer.EXPECTED_FILES,
            )
            self.assertEqual(first.stat().st_uid, 0)
            self.assertTrue(
                all(path.stat().st_uid == 0 for path in first.iterdir())
            )

    def test_digest_and_extra_file_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "staging"
            release = builder.build(ROOT, staging, "3" * 40)
            with self.assertRaisesRegex(installer.InstallRejected, "release_digest_rejected"):
                installer.verify_release(
                    release,
                    "bad",
                    allowed_source_roots=(staging,),
                )

            copied = root / "copied" / release.name
            shutil.copytree(release, copied)
            (copied / "unexpected.txt").write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(installer.InstallRejected, "release_file_set_rejected"):
                installer.verify_release(
                    copied,
                    release.name,
                    allowed_source_roots=(root / "copied",),
                )

    def test_windows_installers_preserve_privilege_boundaries(self) -> None:
        release_installer = (
            ROOT / "scripts" / "windows" / "Install-MyunaHostColdBootRelease.ps1"
        ).read_text(encoding="utf-8")
        task_installer = (
            ROOT / "scripts" / "windows" / "Install-MyunaHostColdBootTask.ps1"
        ).read_text(encoding="utf-8")
        combined = release_installer + task_installer

        for forbidden in (
            "AutoAdminLogon",
            "DefaultPassword",
            "Restart-Computer",
            "wsl --terminate",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("TASK_INSTALL_ROLLED_BACK", task_installer)
        self.assertIn("ADMINISTRATOR_REQUIRED", release_installer)
        self.assertIn("Set-Acl", release_installer)
        self.assertNotIn("icacls.exe", release_installer)
        self.assertIn("S-1-5-32-545", release_installer)
        self.assertIn("Invoke-WslNative", release_installer)
        self.assertIn("Invoke-WslNative", task_installer)
        self.assertIn("ConvertTo-WslDrivePath", release_installer)
        self.assertNotIn("/usr/bin/wslpath", release_installer)
        self.assertIn("$ErrorActionPreference = 'Continue'", release_installer)
        self.assertIn("$nativeExitCode = $LASTEXITCODE", release_installer)

        wrapper = (
            ROOT / "scripts" / "windows" / "Invoke-MyunaHostColdBootInstall.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("Write-AtomicInstallReceipt", wrapper)
        self.assertIn("Preserve-PreviousInstallReceipt", wrapper)
        self.assertIn("install-receipts", wrapper)
        self.assertIn("INSTALL_FAILED_SANITIZED", wrapper)
        self.assertNotIn("/healthz", wrapper)
        self.assertNotIn("/readyz", wrapper)

    def test_postboot_verifier_is_current_boot_and_no_audit(self) -> None:
        verifier = (
            ROOT / "scripts" / "windows" / "Test-MyunaHostColdBoot.ps1"
        ).read_text(encoding="utf-8")
        launcher = (
            ROOT / "scripts" / "windows" / "Start-MyunaHostColdBoot.ps1"
        ).read_text(encoding="utf-8")
        task_installer = (
            ROOT / "scripts" / "windows" / "Install-MyunaHostColdBootTask.ps1"
        ).read_text(encoding="utf-8")
        release_installer = (
            ROOT / "scripts" / "windows" / "Install-MyunaHostColdBootRelease.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("LastBootUpTime", verifier)
        self.assertIn("CURRENT_BOOT_READY_NO_AUDIT", verifier)
        self.assertIn("--verify-only", verifier)
        self.assertIn("Get-NetRoute", verifier)
        self.assertIn("HardwareInterface", verifier)
        self.assertIn("windows_network", verifier)
        self.assertNotIn("Get-NetAdapter -Name 'WLAN'", verifier)
        self.assertIn("Get-Process -Name 'cc-switch'", verifier)
        self.assertIn("Get-ItemPropertyValue", verifier)
        self.assertIn("running-with-run-entry", verifier)
        self.assertIn("PandaFan Elevated AutoStart", verifier)
        self.assertIn("windows_pandafan", verifier)
        self.assertNotIn("-Method Patch", verifier)
        self.assertIn("ChatGPT.lnk", verifier)
        self.assertIn("windows_chatgpt", verifier)
        self.assertNotIn("/healthz", verifier)
        self.assertNotIn("/readyz", verifier)
        self.assertNotIn("sendMessage", verifier)
        self.assertIn("windows_boot_time", launcher)
        self.assertIn("windows_boot_time", task_installer)
        self.assertIn("windows_network", launcher)
        self.assertIn("windows_network", task_installer)
        self.assertIn("windows_pandafan", task_installer)
        self.assertIn("windows_chatgpt", task_installer)
        self.assertIn("Start-PandaFanAutoconnect.ps1", task_installer)
        self.assertIn("pandafan-task.xml", task_installer)
        self.assertIn("PANDAFAN_TASK_POSTSTATE_REJECTED", task_installer)
        self.assertIn("Test-ControllerLauncher", launcher)
        self.assertNotIn("$keepAlive.WaitForExit()", launcher)
        self.assertIn("$currentTaskState -eq 'Running'", task_installer)
        self.assertIn("LockAfterReady", launcher)
        self.assertIn("--lock-after-ready", task_installer)
        self.assertIn("LockAfterReady", release_installer)
        self.assertIn("Invoke-WslNative", verifier)
        vbs = (
            ROOT / "scripts" / "windows" / "Start-MyunaHostColdBoot.vbs"
        ).read_text(encoding="utf-8")
        self.assertIn('"--lock-after-ready"', vbs)

    def test_autologon_verifier_never_reads_credentials(self) -> None:
        verifier = (
            ROOT / "scripts" / "windows" / "Test-MyunaAutologonState.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("AUTOLOGON_READY_SANITIZED", verifier)
        self.assertIn("plaintext_registry_password_present", verifier)
        self.assertIn("lsa_secret_read = $false", verifier)
        self.assertNotIn("LsaRetrievePrivateData", verifier)
        self.assertNotIn("-Name 'DefaultPassword'", verifier)


if __name__ == "__main__":
    unittest.main()
