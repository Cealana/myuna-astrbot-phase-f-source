from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


CANDIDATE_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
FORMAL_SCRIPTS = Path("/srv/myuna/repos/deploy/scripts")
FORMAL_TESTS = Path("/srv/myuna/repos/deploy/tests")
sys.path[:0] = [str(CANDIDATE_SCRIPTS), str(FORMAL_SCRIPTS), str(FORMAL_TESTS)]

from core_release_selector_upgrade import (  # noqa: E402
    ROLLBACK_BINDING_PATH,
    ROLLBACK_ENV_PATH,
    ROLLBACK_SELECTOR_PATH,
    SELECTOR_DROPIN,
    TARGET_BINDING_PATH,
    TARGET_CREDENTIAL_PATH,
    TARGET_ENV_PATH,
    TARGET_SELECTOR_PATH,
    TELEGRAM_CREDENTIAL_DROPIN,
)
from core_release_selector_upgrade_executor import (  # noqa: E402
    JournaledUpgradeExecutor,
    MemoryJournal,
    UpgradeBundle,
)
from core_release_selector_upgrade_sandbox_backend import (  # noqa: E402
    CORE_UNIT,
    GATEWAY_SERVICE,
    GATEWAY_SOCKET,
    FakeLifecycleRunner,
    FakeReleaseVerifier,
    SandboxBackendError,
    SandboxFilesystemBackend,
)
from test_core_release_selector_upgrade_executor import bundle_payloads  # noqa: E402


class SandboxBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "root"
        self.root.mkdir()
        payloads, plan_digest = bundle_payloads()
        self.bundle = UpgradeBundle.load(payloads, approved_plan_digest=plan_digest)
        self.states = {
            CORE_UNIT: ("inactive", "dead"),
            GATEWAY_SOCKET: ("active", "listening"),
            GATEWAY_SERVICE: ("inactive", "dead"),
        }
        self.runner = FakeLifecycleRunner(self.states)
        self.verifier = FakeReleaseVerifier()
        self.backend = SandboxFilesystemBackend(
            root=self.root,
            runner=self.runner,
            verifier=self.verifier,
        )
        self._seed_prestate()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, absolute: str, payload: bytes, mode: int) -> None:
        path = self.root / absolute.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(mode)

    def _seed_prestate(self) -> None:
        self._write(
            "/etc/myuna/core-release-selector/qq.binding.json",
            self.bundle.payloads[ROLLBACK_BINDING_PATH],
            0o640,
        )
        self._write(
            "/etc/systemd/system/myuna-core@qq.service.d/" + SELECTOR_DROPIN,
            self.bundle.payloads[ROLLBACK_SELECTOR_PATH],
            0o644,
        )
        self._write(
            "/etc/myuna/qq.env",
            self.bundle.payloads[ROLLBACK_ENV_PATH],
            0o640,
        )
        release = self.bundle.plan["target"]["selected_release"]["tree_sha256"]
        self._write(
            "/srv/myuna/releases/core/" + release + "/TREE_SHA256",
            (release + "\n").encode(),
            0o444,
        )

    def test_r2c_rejects_live_root(self) -> None:
        with self.assertRaises(SandboxBackendError):
            SandboxFilesystemBackend(
                root=Path("/"),
                runner=self.runner,
                verifier=self.verifier,
            )

    def test_r2c_rejects_symlink_root(self) -> None:
        link = Path(self.temporary.name) / "root-link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(SandboxBackendError):
            SandboxFilesystemBackend(
                root=link,
                runner=self.runner,
                verifier=self.verifier,
            )

    def test_happy_path_applies_exact_files_and_restores_gateway(self) -> None:
        journal = MemoryJournal()
        result = JournaledUpgradeExecutor(
            bundle=self.bundle,
            backend=self.backend,
            journal=journal,
        ).execute()
        self.assertEqual(result["status"], "activated")
        self.assertEqual(
            self.backend.binding.read_bytes(),
            self.bundle.payloads[TARGET_BINDING_PATH],
        )
        self.assertEqual(
            self.backend.selector.read_bytes(),
            self.bundle.payloads[TARGET_SELECTOR_PATH],
        )
        self.assertEqual(
            self.backend.environment.read_bytes(),
            self.bundle.payloads[TARGET_ENV_PATH],
        )
        self.assertEqual(
            self.backend.credential.read_bytes(),
            self.bundle.payloads[TARGET_CREDENTIAL_PATH],
        )
        self.assertEqual(self.runner.daemon_reload_count, 1)
        self.assertEqual(self.runner.states[CORE_UNIT], ("active", "running"))
        self.assertEqual(
            self.runner.states[GATEWAY_SOCKET],
            ("active", "listening"),
        )
        self.assertEqual(
            self.runner.states[GATEWAY_SERVICE],
            ("inactive", "dead"),
        )

    def test_prestate_hash_drift_fails_before_lifecycle(self) -> None:
        self.backend.environment.write_text("drift\n", encoding="utf-8")
        journal = MemoryJournal()
        with self.assertRaises(SandboxBackendError):
            JournaledUpgradeExecutor(
                bundle=self.bundle,
                backend=self.backend,
                journal=journal,
            ).execute()
        self.assertEqual(self.runner.events, [])

    def test_credential_preexistence_fails_closed(self) -> None:
        self._write(
            "/etc/systemd/system/myuna-core@qq.service.d/"
            + TELEGRAM_CREDENTIAL_DROPIN,
            b"unexpected\n",
            0o644,
        )
        with self.assertRaises(SandboxBackendError):
            self.backend.verify_exact_prestate(self.bundle)

    def test_restore_files_removes_only_new_credential(self) -> None:
        snapshot = self.backend.verify_exact_prestate(self.bundle)
        self.backend.quiesce_gateway(self.bundle)
        self.backend.apply_files(self.bundle)
        self.assertTrue(self.backend.credential.exists())
        self.backend.restore_files(self.bundle)
        self.assertFalse(self.backend.credential.exists())
        self.assertEqual(
            self.backend.binding.read_bytes(),
            self.bundle.payloads[ROLLBACK_BINDING_PATH],
        )
        self.backend.restore_prestate(self.bundle, snapshot)

    def test_active_prestate_is_restored(self) -> None:
        self.runner.states[CORE_UNIT] = ("active", "running")
        self.runner.states[GATEWAY_SERVICE] = ("active", "running")
        self.bundle.plan["prestate"]["service_states"][CORE_UNIT] = {
            "active_state": "active",
            "sub_state": "running",
        }
        self.bundle.plan["prestate"]["service_states"][GATEWAY_SERVICE] = {
            "active_state": "active",
            "sub_state": "running",
        }
        snapshot = self.backend.verify_exact_prestate(self.bundle)
        self.backend.quiesce_gateway(self.bundle)
        self.backend.restore_prestate(self.bundle, snapshot)
        self.assertEqual(self.runner.states[CORE_UNIT], ("active", "running"))
        self.assertEqual(
            self.runner.states[GATEWAY_SERVICE],
            ("active", "running"),
        )


if __name__ == "__main__":
    unittest.main()
