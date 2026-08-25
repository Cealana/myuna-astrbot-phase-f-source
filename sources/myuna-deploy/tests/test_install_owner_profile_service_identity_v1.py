from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest

from install_owner_profile_service_identity_v1 import (
    FILE_MODE,
    SERVICE_HOME,
    SERVICE_SHELL,
    SYSUSERS_BYTES,
    SYSUSERS_PATH,
    OwnerProfileIdentityInstallError,
    install_identity_config,
    validate_service_identity,
)


class InstallOwnerProfileServiceIdentityV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.parent = self.root / "sysusers.d"
        self.parent.mkdir(mode=0o755)
        self.destination = self.parent / SYSUSERS_PATH.name
        self.uid = os.geteuid()
        self.gid = os.getegid()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def install(self) -> bool:
        return install_identity_config(
            self.destination,
            uid=self.uid,
            gid=self.gid,
        )

    def test_exact_config_install_is_deterministic_and_idempotent(self) -> None:
        self.assertTrue(self.install())
        self.assertEqual(self.destination.read_bytes(), SYSUSERS_BYTES)
        metadata = self.destination.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), FILE_MODE)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertFalse(self.install())

    def test_conflicting_config_and_parent_drift_are_preserved(self) -> None:
        self.destination.write_bytes(b"synthetic-conflict\n")
        self.destination.chmod(FILE_MODE)
        with self.assertRaisesRegex(
            OwnerProfileIdentityInstallError,
            "identity_config_rejected",
        ):
            self.install()
        self.assertEqual(self.destination.read_bytes(), b"synthetic-conflict\n")

        self.destination.unlink()
        self.parent.chmod(0o750)
        with self.assertRaisesRegex(
            OwnerProfileIdentityInstallError,
            "identity_install_parent_rejected",
        ):
            self.install()
        self.assertFalse(self.destination.exists())

    def test_symlink_config_is_rejected_without_touching_target(self) -> None:
        outside = self.root / "outside"
        outside.write_bytes(b"synthetic-outside\n")
        self.destination.symlink_to(outside)
        with self.assertRaisesRegex(
            OwnerProfileIdentityInstallError,
            "identity_config_rejected",
        ):
            self.install()
        self.assertEqual(outside.read_bytes(), b"synthetic-outside\n")

    def test_identity_validation_requires_inert_matching_account(self) -> None:
        account = SimpleNamespace(
            pw_uid=123,
            pw_gid=456,
            pw_dir=SERVICE_HOME,
            pw_shell=SERVICE_SHELL,
        )
        group = SimpleNamespace(gr_gid=456)
        self.assertEqual(
            validate_service_identity(
                account_lookup=lambda _: account,
                group_lookup=lambda _: group,
            ),
            (123, 456),
        )

        variants = (
            {"pw_uid": 0},
            {"pw_gid": 999},
            {"pw_dir": "/home/synthetic"},
            {"pw_shell": "/bin/sh"},
        )
        for changes in variants:
            broken = SimpleNamespace(**(vars(account) | changes))
            with self.subTest(changes=changes), self.assertRaisesRegex(
                OwnerProfileIdentityInstallError,
                "profile_service_identity_rejected",
            ):
                validate_service_identity(
                    account_lookup=lambda _: broken,
                    group_lookup=lambda _: group,
                )

    def test_path_name_is_fixed(self) -> None:
        with self.assertRaisesRegex(
            OwnerProfileIdentityInstallError,
            "identity_install_path_rejected",
        ):
            install_identity_config(
                self.parent / "wrong.conf",
                uid=self.uid,
                gid=self.gid,
            )


if __name__ == "__main__":
    unittest.main()
