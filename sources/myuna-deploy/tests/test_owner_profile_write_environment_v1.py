from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from owner_profile_write_environment_v1 import (
    OwnerProfileWriteEnvironmentError,
    OwnerProfileWriteTarget,
    environment_audit_projection,
    parse_environment,
    render_environment,
)


class OwnerProfileWriteEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = OwnerProfileWriteTarget(
            core_release_sha256="a" * 64,
            write_code_release_sha256="b" * 64,
            owner_profile_uid=1001,
            core_peer_uid=1002,
        )

    def test_exact_environment_round_trip(self) -> None:
        payload = render_environment(self.target)
        self.assertEqual(parse_environment(payload), self.target)
        text = payload.decode("ascii")
        self.assertIn(
            "PYTHONPATH=/opt/myuna/owner-profile-write-v1/releases/"
            + "b" * 64
            + "/src\n",
            text,
        )
        self.assertIn(
            "MYUNA_OWNER_PROFILE_SELECTED_CORE_RELEASE_SHA256="
            + "a" * 64
            + "\n",
            text,
        )
        self.assertIn(
            "MYUNA_OWNER_PROFILE_WRITE_CAPABILITY_PROFILE="
            "/opt/myuna/owner-profile-write-v1/capability/"
            "owner-private-profile-write-v1.json\n",
            text,
        )
        self.assertIn(
            "MYUNA_OWNER_PROFILE_ROOT=/var/lib/myuna-owner-profile-write-v1\n",
            text,
        )
        self.assertNotIn("token", text.casefold())
        self.assertNotIn("secret", text.casefold())
        self.assertNotIn("/etc/myuna/capabilities", text)

    def test_unknown_duplicate_and_reordered_fields_fail_closed(self) -> None:
        payload = render_environment(self.target)
        lines = payload.splitlines(keepends=True)
        malformed = (
            b"UNKNOWN=value\n" + b"".join(lines[1:])
        )
        with self.assertRaises(OwnerProfileWriteEnvironmentError):
            parse_environment(malformed)
        with self.assertRaises(OwnerProfileWriteEnvironmentError):
            parse_environment(b"".join(reversed(lines)))
        with self.assertRaises(OwnerProfileWriteEnvironmentError):
            parse_environment(payload + lines[-1])

    def test_noncanonical_release_uid_and_endpoint_fail_closed(self) -> None:
        payload = render_environment(self.target)
        for before, after in (
            (b"a" * 64, b"A" * 64),
            (b"OWNER_UID=1001", b"OWNER_UID=0"),
            (b"127.0.0.1:879", b"127.0.0.1:880"),
        ):
            with self.subTest(after=after):
                with self.assertRaises(OwnerProfileWriteEnvironmentError):
                    parse_environment(payload.replace(before, after, 1))

    def test_audit_projection_is_content_free(self) -> None:
        projection = environment_audit_projection(
            self.target,
            outcome="accepted",
        )
        self.assertTrue(projection["core_release_pinned"])
        self.assertFalse(projection["profile_digest_recorded"])
        self.assertFalse(projection["raw_content_recorded"])
        serialized = repr(projection)
        self.assertNotIn("a" * 64, serialized)
        self.assertNotIn("1001", serialized)


if __name__ == "__main__":
    unittest.main()
