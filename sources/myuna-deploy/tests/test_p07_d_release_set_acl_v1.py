from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from p07_d_release_set_acl import (
    ReleaseSetAclRejected,
    apply_release_set_acl,
    inspect_release_set_acl,
)


@unittest.skipUnless(os.geteuid() == 0, "root-only ACL fixture")
class ReleaseSetAclTests(unittest.TestCase):
    def test_exact_two_service_identity_acl_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release-set.json"
            path.write_text("{}", encoding="utf-8")
            projection = apply_release_set_acl(path, core_uid=999, telegram_uid=988)
            self.assertEqual(projection.file_uid, 0)
            self.assertEqual(projection.file_gid, 0)
            self.assertEqual(projection.file_mode, 0o640)
            self.assertEqual(
                inspect_release_set_acl(path, core_uid=999, telegram_uid=988),
                projection,
            )
            self.assertEqual(len(projection.digest), 64)

    def test_extra_identity_mode_and_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "release-set.json"
            path.write_text("{}", encoding="utf-8")
            apply_release_set_acl(path, core_uid=999, telegram_uid=988)
            subprocess.run(
                ["/usr/bin/setfacl", "-m", "u:987:r--", "--", str(path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            with self.assertRaisesRegex(ReleaseSetAclRejected, "acl_rejected"):
                inspect_release_set_acl(path, core_uid=999, telegram_uid=988)
            link = root / "link"
            link.symlink_to(path)
            with self.assertRaisesRegex(ReleaseSetAclRejected, "type_rejected"):
                inspect_release_set_acl(link, core_uid=999, telegram_uid=988)

    def test_same_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release-set.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseSetAclRejected, "identity_rejected"):
                apply_release_set_acl(path, core_uid=999, telegram_uid=999)


if __name__ == "__main__":
    unittest.main()
