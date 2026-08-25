from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


class OwnerProfileDeployContractTests(unittest.TestCase):
    def test_service_uses_dedicated_identity_and_root_selector(self) -> None:
        payload = (
            DEPLOY / "myuna-owner-profile-read-v1.service"
        ).read_text(encoding="utf-8")
        required = {
            "User=myuna_owner_profile",
            "Group=myuna_owner_profile",
            (
                "EnvironmentFile=/etc/myuna-owner-profile-read-v1/"
                "selector.env"
            ),
            (
                "ExecStart=/usr/bin/python3 -m "
                "myuna_core.owner_profile.socket_worker"
            ),
            "PrivateNetwork=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "RestrictAddressFamilies=AF_UNIX",
            (
                "ReadOnlyPaths=/var/lib/myuna-owner-profile-v1 "
                "/var/lib/myuna-owner-profile-write-v1"
            ),
        }
        self.assertTrue(required.issubset(set(payload.splitlines())))
        self.assertNotIn("/etc/myuna/owner-profile-read-v1.env", payload)
        self.assertNotIn("ReadWritePaths=", payload)

    def test_socket_is_owner_channel_group_readable_only(self) -> None:
        payload = (
            DEPLOY / "myuna-owner-profile-read-v1.socket"
        ).read_text(encoding="utf-8")
        required = {
            "ListenStream=/run/myuna-owner-profile-read-v1/profile.sock",
            "SocketUser=myuna_owner_profile",
            "SocketGroup=myuna",
            "SocketMode=0660",
            "DirectoryMode=0750",
            "RemoveOnStop=true",
            "Service=myuna-owner-profile-read-v1.service",
        }
        self.assertTrue(required.issubset(set(payload.splitlines())))

    def test_sysusers_and_tmpfiles_contracts_are_exact(self) -> None:
        sysusers = (
            DEPLOY / "myuna-owner-profile-read-v1.sysusers.conf"
        ).read_bytes()
        tmpfiles = (
            DEPLOY / "myuna-owner-profile-read-v1.tmpfiles.conf"
        ).read_bytes()
        self.assertEqual(
            sysusers,
            (
                b'u myuna_owner_profile - "Myuna Owner Profile read-only '
                b'service" /nonexistent /usr/sbin/nologin\n'
            ),
        )
        self.assertEqual(
            tmpfiles,
            (
                b"d /run/myuna-owner-profile-read-v1 0750 "
                b"myuna_owner_profile myuna -\n"
            ),
        )


if __name__ == "__main__":
    unittest.main()
