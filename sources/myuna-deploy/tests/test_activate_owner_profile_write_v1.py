from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import activate_owner_profile_write_v1 as activation
from owner_profile_write_environment_v1 import OwnerProfileWriteTarget


WRITER_SERVICE = b"""[Service]
User=myuna_owner_profile
Group=myuna_owner_profile
ExecStart=/usr/bin/python3 -m myuna_core.owner_profile.write_socket_worker
RestrictAddressFamilies=AF_UNIX AF_INET
IPAddressDeny=any
IPAddressAllow=localhost
ReadOnlyPaths=/opt/myuna/owner-profile-write-v1 /etc/myuna-owner-profile-write-v1
"""
WRITER_SOCKET = b"""[Socket]
ListenStream=/run/myuna-owner-profile-write-v1/profile-write.sock
SocketUser=myuna_owner_profile
SocketGroup=myuna
SocketMode=0660
Service=myuna-owner-profile-write-v1.service
"""
WRITER_TMPFILES = (
    b"d /run/myuna-owner-profile-write-v1 0750 "
    b"myuna_owner_profile myuna -\n"
    b"d /var/log/myuna-owner-profile-write-v1 0700 "
    b"myuna_owner_profile myuna_owner_profile -\n"
)


class FakeSystemd:
    def __init__(self, *, fail_core_restart_once: bool = False) -> None:
        self.active = {
            activation.CORE_SERVICE,
            activation.READ_SERVICE,
            activation.READ_SOCKET,
            activation.LOCAL_PROVIDER_SERVICE,
        }
        self.enabled: set[str] = set()
        self.commands: list[tuple[str, ...]] = []
        self.fail_core_restart_once = fail_core_restart_once

    def state(self, kind: str, unit: str) -> bool:
        return unit in (self.active if kind == "is-active" else self.enabled)

    def systemctl(self, *arguments: str, check: bool = True) -> None:
        self.commands.append(arguments)
        if (
            self.fail_core_restart_once
            and arguments == ("restart", activation.CORE_SERVICE)
        ):
            self.fail_core_restart_once = False
            raise activation.OwnerProfileWriteActivationError(
                "synthetic_core_restart_failure"
            )
        command = arguments[0]
        unit = arguments[-1]
        if command == "disable":
            self.enabled.discard(unit)
            if "--now" in arguments:
                self.active.discard(unit)
        elif command == "enable":
            self.enabled.add(unit)
            if "--now" in arguments:
                self.active.add(unit)
        elif command in {"start", "restart"}:
            self.active.add(unit)
        elif command == "stop":
            self.active.discard(unit)


class ActivateOwnerProfileWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.digest = "a" * 64
        self.code_digest = "c" * 64
        self.profile_digest = "b" * 64
        self.release_root = self.root / "core-releases"
        self.release = self.release_root / self.digest
        self.release.mkdir(parents=True)
        self.writer_code_root = self.root / "writer-code"
        self.writer_release = self.writer_code_root / self.code_digest
        deploy = self.writer_release / "deploy"
        deploy.mkdir(parents=True)
        (deploy / activation.WRITER_SERVICE).write_bytes(WRITER_SERVICE)
        (deploy / activation.WRITER_SOCKET).write_bytes(WRITER_SOCKET)
        (deploy / "myuna-owner-profile-write-v1.tmpfiles.conf").write_bytes(
            WRITER_TMPFILES
        )
        self.etc = self.root / "etc"
        self.systemd = self.etc / "systemd"
        self.tmpfiles = self.etc / "tmpfiles.d"
        self.myuna = self.etc / "myuna"
        self.capabilities = self.myuna / "capabilities"
        self.dropins = self.systemd / "myuna-core@qq.service.d"
        for directory in (
            self.systemd,
            self.tmpfiles,
            self.myuna,
            self.capabilities,
            self.dropins,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        self.control_root = self.root / "control"
        self.write_root = self.root / "write-state"
        self.write_root.mkdir(mode=0o700)
        self.paths = activation.ActivationPaths(
            deploy_root=ROOT,
            core_release_root=self.release_root,
            writer_code_root=self.writer_code_root,
            writer_environment=(
                self.etc / "myuna-owner-profile-write-v1" / "writer.env"
            ),
            writer_capability_profile=(
                self.writer_code_root.parent / "capability"
                / "owner-private-profile-write-v1.json"
            ),
            writer_service=self.systemd / activation.WRITER_SERVICE,
            writer_socket=self.systemd / activation.WRITER_SOCKET,
            writer_tmpfiles=self.tmpfiles / "writer.conf",
            read_profile=self.capabilities / "read.json",
            write_profile=self.capabilities / "write.json",
            capability_manifest=self.capabilities / "manifest.json",
            core_environment=self.myuna / "core.env",
            core_dropin=self.dropins / "write.conf",
            control_root=self.control_root,
            backup_root=self.control_root / "backups",
            journal=self.control_root / "PENDING.json",
            receipt_root=self.control_root / "receipts",
            write_root=self.write_root,
        )
        self.target = OwnerProfileWriteTarget(
            core_release_sha256=self.digest,
            write_code_release_sha256=self.code_digest,
            owner_profile_uid=self.uid,
            core_peer_uid=self.uid,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def successful_run(
        arguments: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(arguments, 0, "", "")

    def activate_with(
        self,
        systemd: FakeSystemd,
        *,
        prepare_state=None,
        restore_state=None,
        run=None,
    ):
        prepare_state = prepare_state or mock.Mock(return_value=True)
        restore_state = restore_state or mock.Mock(return_value=True)
        run = run or self.successful_run

        def show(_unit: str, property_name: str) -> str:
            if property_name == "WorkingDirectory":
                return self.release.as_posix()
            return (
                "llama-server --host 127.0.0.1 --alias myuna-local-owner-v1 "
                "--offline --log-disable"
            )

        with (
            mock.patch.object(
                activation,
                "_show",
                side_effect=show,
            ),
            mock.patch.object(activation, "_unit_state", systemd.state),
            mock.patch.object(activation, "_systemctl", systemd.systemctl),
            mock.patch.object(activation, "_run", side_effect=run),
        ):
            result = activation.activate(
                self.target,
                initial_profile_revision=2,
                initial_profile_sha256=self.profile_digest,
                service_uid=self.uid,
                service_gid=self.gid,
                paths=self.paths,
                root_uid=self.uid,
                root_gid=self.gid,
                prepare_state=prepare_state,
                restore_state=restore_state,
            )
        return result, prepare_state, restore_state

    def test_candidate_files_separate_read_and_write_policies(self) -> None:
        candidates = activation.candidate_files(self.target, paths=self.paths)
        core_environment = candidates["core_environment"][1].decode("ascii")
        writer_environment = candidates["writer_environment"][1].decode("ascii")
        self.assertIn("owner-private-profile-read-v1.json", core_environment)
        self.assertIn("owner-private-profile-write-v1.json", writer_environment)
        self.assertIn(self.code_digest, writer_environment)
        self.assertIn(
            "/opt/myuna/owner-profile-write-v1/releases/",
            writer_environment,
        )
        self.assertIn(
            "/opt/myuna/owner-profile-write-v1/capability/",
            writer_environment,
        )
        self.assertNotIn("/srv/myuna", writer_environment)
        write_profile = json.loads(candidates["write_profile"][1])
        self.assertEqual(
            candidates[activation.WRITER_CAPABILITY_KEY][1],
            candidates["write_profile"][1],
        )
        self.assertEqual(candidates[activation.WRITER_CAPABILITY_KEY][2], 0o440)
        self.assertEqual(
            write_profile["subject"]["channel_kinds"],
            ["astrbot_telegram"],
        )

    def test_activation_is_content_free_and_stops_before_owner_e2e(self) -> None:
        receipt, prepare_state, restore_state = self.activate_with(FakeSystemd())
        self.assertEqual(
            receipt["status"],
            "PROFILE_WRITE_LIVE_READY_AWAITING_OWNER_E2E",
        )
        self.assertTrue(self.paths.writer_socket.is_file())
        self.assertTrue(self.paths.core_dropin.is_file())
        self.assertFalse(self.paths.journal.exists())
        self.assertTrue(self.paths.writer_capability_profile.is_file())
        self.assertEqual(
            self.paths.writer_capability_profile.stat().st_mode & 0o777,
            0o440,
        )
        self.assertTrue(receipt["writer_capability_isolated"])
        receipts = list(self.paths.receipt_root.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        self.assertFalse(receipt["owner_channel_e2e_performed"])
        self.assertFalse(receipt["memory_write_performed"])
        self.assertNotIn(self.profile_digest, json.dumps(receipt))
        prepare_state.assert_called_once()
        restore_state.assert_not_called()

    def test_postwrite_failure_restores_files_and_root_ownership(self) -> None:
        original = b"synthetic-old-core-env\n"
        self.paths.core_environment.write_bytes(original)
        self.paths.core_environment.chmod(0o644)
        prepare_state = mock.Mock(return_value=True)
        restore_state = mock.Mock(return_value=True)
        with self.assertRaisesRegex(
            activation.OwnerProfileWriteActivationError,
            "synthetic_core_restart_failure",
        ):
            self.activate_with(
                FakeSystemd(fail_core_restart_once=True),
                prepare_state=prepare_state,
                restore_state=restore_state,
            )
        self.assertEqual(self.paths.core_environment.read_bytes(), original)
        self.assertFalse(self.paths.writer_socket.exists())
        self.assertFalse(self.paths.core_dropin.exists())
        self.assertFalse(self.paths.journal.exists())
        self.assertFalse(self.paths.writer_capability_profile.exists())
        self.assertFalse(self.paths.writer_capability_profile.parent.exists())
        self.assertEqual(list(self.paths.receipt_root.glob("*.json")), [])
        restore_state.assert_called_once()

    def test_pending_journal_and_wrong_selected_release_fail_closed(self) -> None:
        self.control_root.mkdir(mode=0o700)
        self.paths.journal.write_bytes(b"synthetic-pending\n")
        self.paths.journal.chmod(0o600)
        with self.assertRaisesRegex(
            activation.OwnerProfileWriteActivationError,
            "activation_preflight_rejected",
        ):
            self.activate_with(FakeSystemd())
        self.paths.journal.unlink()
        with mock.patch.object(activation, "_show", return_value="/wrong"):
            with self.assertRaisesRegex(
                activation.OwnerProfileWriteActivationError,
                "activation_core_release_not_selected",
            ):
                activation.activate(
                    self.target,
                    initial_profile_revision=2,
                    initial_profile_sha256=self.profile_digest,
                    service_uid=self.uid,
                    service_gid=self.gid,
                    paths=self.paths,
                    root_uid=self.uid,
                    root_gid=self.gid,
                )

    def test_provider_logging_or_network_drift_fails_before_mutation(self) -> None:
        def show(_unit: str, property_name: str) -> str:
            if property_name == "WorkingDirectory":
                return self.release.as_posix()
            return "llama-server --host 0.0.0.0 --alias myuna-local-owner-v1"

        prepare_state = mock.Mock(return_value=True)
        with (
            mock.patch.object(activation, "_show", side_effect=show),
            self.assertRaisesRegex(
                activation.OwnerProfileWriteActivationError,
                "activation_local_provider_boundary_rejected",
            ),
        ):
            activation.activate(
                self.target,
                initial_profile_revision=2,
                initial_profile_sha256=self.profile_digest,
                service_uid=self.uid,
                service_gid=self.gid,
                paths=self.paths,
                root_uid=self.uid,
                root_gid=self.gid,
                prepare_state=prepare_state,
            )
        prepare_state.assert_not_called()

    def test_unreadable_writer_capability_rolls_back_before_service_restart(self) -> None:
        prepare_state = mock.Mock(return_value=True)
        restore_state = mock.Mock(return_value=True)

        def reject_writer_access(
            arguments: list[str], *, check: bool = True
        ) -> subprocess.CompletedProcess[str]:
            if arguments[:5] == [
                "/usr/sbin/runuser",
                "-u",
                pwd.getpwuid(self.uid).pw_name,
                "--",
                "/usr/bin/test",
            ]:
                return subprocess.CompletedProcess(arguments, 1, "", "")
            return self.successful_run(arguments, check=check)

        with self.assertRaisesRegex(
            activation.OwnerProfileWriteActivationError,
            "activation_writer_capability_unreadable",
        ):
            self.activate_with(
                FakeSystemd(),
                prepare_state=prepare_state,
                restore_state=restore_state,
                run=reject_writer_access,
            )
        self.assertFalse(self.paths.writer_capability_profile.exists())
        self.assertFalse(self.paths.writer_capability_profile.parent.exists())
        self.assertFalse(self.paths.journal.exists())
        restore_state.assert_called_once()


if __name__ == "__main__":
    unittest.main()
