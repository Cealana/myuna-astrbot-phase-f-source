from __future__ import annotations

from pathlib import Path
import unittest


class OwnerProfileWriteDeployContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.deploy = Path(__file__).parents[1] / "deploy"

    def test_writer_service_is_local_bounded_and_non_root(self) -> None:
        lines = set(
            (self.deploy / "myuna-owner-profile-write-v1.service")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        required = {
            "User=myuna_owner_profile",
            "Group=myuna_owner_profile",
            "ExecStart=/usr/bin/python3 -m myuna_core.owner_profile.write_socket_worker",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "RestrictAddressFamilies=AF_UNIX AF_INET",
            "IPAddressDeny=any",
            "IPAddressAllow=localhost",
            (
                "ReadWritePaths=/var/lib/myuna-owner-profile-write-v1 "
                "/var/log/myuna-owner-profile-write-v1"
            ),
            (
                "ReadOnlyPaths=/opt/myuna/owner-profile-write-v1 "
                "/etc/myuna-owner-profile-write-v1"
            ),
        }
        self.assertTrue(required <= lines)
        self.assertNotIn("PrivateNetwork=true", lines)
        self.assertFalse(
            any(line.startswith("SupplementaryGroups=") for line in lines)
        )
        self.assertFalse(any("/srv/myuna" in line for line in lines))

    def test_writer_socket_is_private_to_service_and_core_group(self) -> None:
        lines = set(
            (self.deploy / "myuna-owner-profile-write-v1.socket")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        self.assertTrue(
            {
                (
                    "ListenStream=/run/myuna-owner-profile-write-v1/"
                    "profile-write.sock"
                ),
                "SocketUser=myuna_owner_profile",
                "SocketGroup=myuna",
                "SocketMode=0660",
                "MaxConnections=2",
            }
            <= lines
        )

    def test_tmpfiles_contract_contains_no_profile_content_path(self) -> None:
        payload = (
            self.deploy / "myuna-owner-profile-write-v1.tmpfiles.conf"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            payload,
            (
                "d /run/myuna-owner-profile-write-v1 0750 "
                "myuna_owner_profile myuna -\n"
                "d /var/log/myuna-owner-profile-write-v1 0700 "
                "myuna_owner_profile myuna_owner_profile -\n"
            ),
        )
        self.assertNotIn("profile.toml", payload)


if __name__ == "__main__":
    unittest.main()
