from __future__ import annotations

import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest

from p07_policy_overlay_acl import (
    PolicyOverlayAclRejected,
    apply_policy_overlay_acl,
    inspect_policy_overlay_acl,
)


@unittest.skipUnless(os.geteuid() == 0, "root-only ACL fixture")
class PolicyOverlayAclTests(unittest.TestCase):
    def test_exact_two_service_identity_acl_with_runtime_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o755)
            path = Path(directory) / "overlay.json"
            path.write_text("{}\n", encoding="ascii")
            projection = apply_policy_overlay_acl(
                path,
                core_uid=999,
                telegram_uid=988,
                file_gid=982,
            )
            self.assertEqual(projection.file_uid, 0)
            self.assertEqual(projection.file_gid, 982)
            self.assertEqual(projection.file_mode, 0o640)
            self.assertEqual(len(projection.digest), 64)
            self.assertEqual(
                inspect_policy_overlay_acl(
                    path,
                    core_uid=999,
                    telegram_uid=988,
                    file_gid=982,
                ),
                projection,
            )
            for user in ("myuna", "myuna-gateway-telegram"):
                identity = pwd.getpwnam(user)
                completed = subprocess.run(
                    [
                        "/usr/sbin/runuser",
                        "-u",
                        user,
                        "--",
                        "/usr/bin/python3",
                        "-B",
                        "-c",
                        "from pathlib import Path; assert Path(__import__('sys').argv[1]).read_bytes() == b'{}\\n'",
                        str(path),
                    ],
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
                self.assertEqual(completed.returncode, 0, identity.pw_uid)

    def test_extra_identity_mode_gid_and_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "overlay.json"
            path.write_text("{}\n", encoding="ascii")
            apply_policy_overlay_acl(
                path,
                core_uid=999,
                telegram_uid=988,
                file_gid=982,
            )
            subprocess.run(
                ["/usr/bin/setfacl", "-m", "u:987:r--", "--", str(path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            with self.assertRaisesRegex(PolicyOverlayAclRejected, "acl_rejected"):
                inspect_policy_overlay_acl(
                    path,
                    core_uid=999,
                    telegram_uid=988,
                    file_gid=982,
                )
            link = root / "link"
            link.symlink_to(path)
            with self.assertRaisesRegex(PolicyOverlayAclRejected, "type_rejected"):
                inspect_policy_overlay_acl(
                    link,
                    core_uid=999,
                    telegram_uid=988,
                    file_gid=982,
                )

    def test_same_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "overlay.json"
            path.write_text("{}\n", encoding="ascii")
            with self.assertRaisesRegex(PolicyOverlayAclRejected, "identity_rejected"):
                apply_policy_overlay_acl(
                    path,
                    core_uid=999,
                    telegram_uid=999,
                    file_gid=982,
                )


if __name__ == "__main__":
    unittest.main()
