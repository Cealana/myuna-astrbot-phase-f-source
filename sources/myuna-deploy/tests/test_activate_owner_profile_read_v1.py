from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import activate_owner_profile_read_v1 as activation
from activate_owner_profile_read_v1 import (
    ActivationPaths,
    ENVIRONMENT_MODE,
    PRIVATE_DIRECTORY_MODE,
    UNIT_MODE,
    OwnerProfileActivationError,
    activate,
    validate_code_release,
)
from install_owner_profile_read_code_v1 import (
    SOURCE_FILES,
    build_code_bundle,
    install_code_release,
)
from myuna_core.owner_profile.loader import build_receipt
from owner_profile_read_selector_v1 import OwnerProfileReadTarget


PROFILE_BYTES = """schema_version = 1
document_type = "owner_profile_baseline"
profile_id = "synthetic-activation-profile"
profile_revision = 2

[[sections]]
section_id = "synthetic-section"
topic_key = "synthetic-topic"
category = "long_term_preference"
title = "Synthetic Unicode 中文"
body = "Synthetic stable activation preference."
keywords = ["synthetic", "中文"]
""".encode("utf-8")
SOURCE_COMMIT = "a" * 40


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


class FakeServices:
    def __init__(self) -> None:
        self.socket_active = False
        self.socket_enabled = False
        self.service_active = False
        self.commands: list[tuple[str, ...]] = []

    def unit_state(self, kind: str, unit: str) -> bool:
        if unit == activation.SOCKET_UNIT_NAME:
            return (
                self.socket_active
                if kind == "is-active"
                else self.socket_enabled
            )
        if unit == activation.SERVICE_UNIT_NAME and kind == "is-active":
            return self.service_active
        return False

    def systemctl(self, *arguments: str, check: bool = True) -> None:
        self.commands.append(arguments)
        if not arguments:
            return
        command = arguments[0]
        if command == "enable" and activation.SOCKET_UNIT_NAME in arguments:
            self.socket_enabled = True
            if "--now" in arguments:
                self.socket_active = True
        elif command == "disable" and activation.SOCKET_UNIT_NAME in arguments:
            self.socket_enabled = False
            if "--now" in arguments:
                self.socket_active = False
        elif command == "start" and activation.SOCKET_UNIT_NAME in arguments:
            self.socket_active = True
        elif command == "start" and activation.SERVICE_UNIT_NAME in arguments:
            self.service_active = True
        elif command == "stop" and activation.SERVICE_UNIT_NAME in arguments:
            self.service_active = False


class ActivateOwnerProfileReadV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o755)
        self.uid = os.geteuid()
        self.gid = os.getegid()

        source = self.root / "source"
        source.mkdir(mode=0o755)
        for index, relative in enumerate(SOURCE_FILES, start=1):
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = f"synthetic-source-{index}\n".encode("ascii")
            if relative.endswith(".service"):
                payload = b"\n".join(
                    (
                        b"User=myuna_owner_profile",
                        b"Group=myuna_owner_profile",
                        b"EnvironmentFile=/etc/myuna-owner-profile-read-v1/selector.env",
                        b"ExecStart=/usr/bin/python3 -m myuna_core.owner_profile.socket_worker",
                        b"PrivateNetwork=true",
                        b"RestrictAddressFamilies=AF_UNIX",
                        (
                            b"ReadOnlyPaths=/var/lib/myuna-owner-profile-v1 "
                            b"/var/lib/myuna-owner-profile-write-v1"
                        ),
                        b"",
                    )
                )
            elif relative.endswith(".socket"):
                payload = b"\n".join(
                    (
                        b"ListenStream=/run/myuna-owner-profile-read-v1/profile.sock",
                        b"SocketUser=myuna_owner_profile",
                        b"SocketGroup=myuna",
                        b"SocketMode=0660",
                        b"Service=myuna-owner-profile-read-v1.service",
                        b"",
                    )
                )
            elif relative.endswith(".tmpfiles.conf"):
                payload = (
                    b"d /run/myuna-owner-profile-read-v1 0750 "
                    b"myuna_owner_profile myuna -\n"
                )
            path.write_bytes(payload)
        code_parent = self.root / "opt"
        code_parent.mkdir(mode=0o755)
        code_destination_root = code_parent / "owner-profile-read-v1"
        self.bundle = build_code_bundle(source, source_commit=SOURCE_COMMIT)
        self.code_release, _ = install_code_release(
            self.bundle,
            destination_root=code_destination_root,
            uid=self.uid,
            gid=self.gid,
        )

        profile_parent = self.root / "var-lib"
        profile_parent.mkdir(mode=0o755)
        self.profile_root = profile_parent / "myuna-owner-profile-v1"
        self.profile_root.mkdir(mode=0o710)
        self.profile_releases = self.profile_root / "releases"
        self.profile_releases.mkdir(mode=0o710)
        self.profile_digest = sha256(PROFILE_BYTES).hexdigest()
        self.profile_release = self.profile_releases / (
            f"r2-{self.profile_digest}"
        )
        self.profile_release.mkdir(mode=0o700)
        profile = self.profile_release / "profile.toml"
        receipt = self.profile_release / "receipt.json"
        profile.write_bytes(PROFILE_BYTES)
        receipt.write_bytes(canonical(build_receipt(PROFILE_BYTES)))
        profile.chmod(0o600)
        receipt.chmod(0o600)

        self.etc = self.root / "etc"
        self.etc.mkdir(mode=0o755)
        self.systemd = self.etc / "systemd-system"
        self.systemd.mkdir(mode=0o755)
        self.tmpfiles = self.etc / "tmpfiles.d"
        self.tmpfiles.mkdir(mode=0o755)
        activation_root = self.profile_root / "activation"
        self.paths = ActivationPaths(
            code_release_root=code_destination_root / "releases",
            profile_release_root=self.profile_releases,
            environment=(
                self.etc
                / "myuna-owner-profile-read-v1"
                / "selector.env"
            ),
            service_unit=self.systemd / activation.SERVICE_UNIT_NAME,
            socket_unit=self.systemd / activation.SOCKET_UNIT_NAME,
            tmpfiles=self.tmpfiles / activation.TMPFILES_NAME,
            backup_root=activation_root / "backups",
            activation_root=activation_root,
            receipt=activation_root / "LAST_ACTIVATION.json",
            journal=activation_root / "PENDING.json",
        )
        self.target = OwnerProfileReadTarget(
            code_release_sha256=self.bundle.release_sha256,
            profile_revision=2,
            profile_sha256=self.profile_digest,
            profile_owner_uid=self.uid,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def successful_run(
        arguments: list[str],
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(arguments, 0, "", "")

    def activate_with(self, services: FakeServices) -> dict[str, object]:
        with (
            patch.object(activation, "_systemctl", services.systemctl),
            patch.object(activation, "_unit_state", services.unit_state),
            patch.object(activation, "_run", self.successful_run),
        ):
            return activate(
                self.target,
                paths=self.paths,
                root_uid=self.uid,
                root_gid=self.gid,
                service_gid=self.gid,
            )

    def test_exact_activation_is_content_free_and_local_only(self) -> None:
        services = FakeServices()
        receipt = self.activate_with(services)

        self.assertEqual(
            receipt["status"],
            "LOCAL_READ_SERVICE_READY_PROVIDER_EGRESS_BLOCKED",
        )
        self.assertTrue(services.socket_active)
        self.assertTrue(services.socket_enabled)
        self.assertFalse(services.service_active)
        self.assertFalse(self.paths.journal.exists())
        self.assertTrue(self.paths.receipt.is_file())
        self.assertEqual(
            stat.S_IMODE(self.paths.environment.parent.stat().st_mode),
            PRIVATE_DIRECTORY_MODE,
        )
        self.assertEqual(
            stat.S_IMODE(self.paths.environment.stat().st_mode),
            ENVIRONMENT_MODE,
        )
        for path in (
            self.paths.service_unit,
            self.paths.socket_unit,
            self.paths.tmpfiles,
        ):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), UNIT_MODE)
        serialized = json.dumps(receipt, sort_keys=True)
        self.assertNotIn(self.profile_digest, serialized)
        self.assertNotIn("synthetic-activation-profile", serialized)
        self.assertFalse(receipt["provider_context_enabled"])
        self.assertFalse(receipt["owner_channel_e2e_performed"])
        backups = list(self.paths.backup_root.iterdir())
        self.assertEqual(len(backups), 1)
        self.assertTrue((backups[0] / "MANIFEST.json").is_file())

    def test_postwrite_failure_restores_exact_prestate(self) -> None:
        self.paths.environment.parent.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        originals: dict[Path, bytes] = {}
        for index, (path, mode) in enumerate(
            (
                (self.paths.environment, ENVIRONMENT_MODE),
                (self.paths.service_unit, UNIT_MODE),
                (self.paths.socket_unit, UNIT_MODE),
                (self.paths.tmpfiles, UNIT_MODE),
            ),
            start=1,
        ):
            payload = f"synthetic-prestate-{index}\n".encode("ascii")
            path.write_bytes(payload)
            path.chmod(mode)
            originals[path] = payload
        services = FakeServices()

        def failed_run(
            arguments: list[str],
            *,
            check: bool = True,
        ) -> subprocess.CompletedProcess[str]:
            raise OwnerProfileActivationError("synthetic_activation_failure")

        with (
            patch.object(activation, "_systemctl", services.systemctl),
            patch.object(activation, "_unit_state", services.unit_state),
            patch.object(activation, "_run", failed_run),
            self.assertRaisesRegex(
                OwnerProfileActivationError,
                "synthetic_activation_failure",
            ),
        ):
            activate(
                self.target,
                paths=self.paths,
                root_uid=self.uid,
                root_gid=self.gid,
                service_gid=self.gid,
            )
        for path, payload in originals.items():
            self.assertEqual(path.read_bytes(), payload)
        self.assertFalse(self.paths.journal.exists())
        self.assertFalse(self.paths.receipt.exists())
        self.assertFalse(services.socket_active)
        self.assertFalse(services.socket_enabled)

    def test_code_drift_and_pending_journal_fail_closed(self) -> None:
        manifest = self.code_release / "MANIFEST.json"
        manifest.chmod(0o600)
        with self.assertRaisesRegex(
            OwnerProfileActivationError,
            "activation_code_metadata_rejected",
        ):
            validate_code_release(
                self.target,
                paths=self.paths,
                service_gid=self.gid,
                root_uid=self.uid,
            )
        manifest.chmod(0o440)

        self.paths.activation_root.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        self.paths.journal.write_bytes(b"synthetic-pending\n")
        self.paths.journal.chmod(0o600)
        with self.assertRaisesRegex(
            OwnerProfileActivationError,
            "activation_recovery_required",
        ):
            self.activate_with(FakeServices())
        self.assertEqual(
            self.paths.journal.read_bytes(),
            b"synthetic-pending\n",
        )


if __name__ == "__main__":
    unittest.main()
