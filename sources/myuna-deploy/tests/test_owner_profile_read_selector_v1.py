from __future__ import annotations

import json
import unittest

from owner_profile_read_selector_v1 import (
    OwnerProfileReadTarget,
    OwnerProfileSelectorError,
    parse_environment,
    render_environment,
    selector_audit_projection,
)


class OwnerProfileReadSelectorV1Tests(unittest.TestCase):
    def target(self) -> OwnerProfileReadTarget:
        return OwnerProfileReadTarget(
            code_release_sha256="a" * 64,
            profile_revision=2,
            profile_sha256="b" * 64,
            profile_owner_uid=1234,
        )

    def test_environment_round_trip_is_exact_and_deterministic(self) -> None:
        target = self.target()
        encoded = render_environment(target)
        self.assertEqual(parse_environment(encoded), target)
        self.assertEqual(render_environment(parse_environment(encoded)), encoded)
        self.assertEqual(len(encoded.splitlines()), 5)
        self.assertIn(
            b"MYUNA_OWNER_PROFILE_ROOT=/var/lib/myuna-owner-profile-write-v1",
            encoded,
        )

    def test_unknown_reordered_conflicting_or_malformed_values_reject(self) -> None:
        valid = render_environment(self.target())
        lines = valid.splitlines()
        variants = (
            b"",
            b"\xff",
            valid[:-1],
            b"\n".join(reversed(lines)) + b"\n",
            valid + b"UNKNOWN=value\n",
            valid.replace(b"/src", b"/src/../src"),
            valid.replace(b"b" * 64, b"g" * 64, 1),
            valid.replace(b"1234", b"0"),
            valid.replace(b"1234", b"true"),
            valid.replace(
                b"MYUNA_OWNER_PROFILE_INITIAL_REVISION=2",
                b"MYUNA_OWNER_PROFILE_INITIAL_REVISION=02",
            ),
        )
        for index, payload in enumerate(variants):
            with self.subTest(index=index, payload=payload[:40]), self.assertRaisesRegex(
                OwnerProfileSelectorError,
                "selector_environment_rejected|selector_target_rejected",
            ):
                parse_environment(payload)

    def test_target_rejects_boolean_and_invalid_digests(self) -> None:
        variants = (
            {"code_release_sha256": "bad"},
            {"profile_sha256": "bad"},
            {"profile_revision": True},
            {"profile_revision": 0},
            {"profile_owner_uid": True},
            {"profile_owner_uid": 0},
        )
        baseline = {
            "code_release_sha256": "a" * 64,
            "profile_revision": 2,
            "profile_sha256": "b" * 64,
            "profile_owner_uid": 1234,
        }
        for changes in variants:
            with self.subTest(changes=changes), self.assertRaisesRegex(
                OwnerProfileSelectorError,
                "selector_target_rejected",
            ):
                OwnerProfileReadTarget(**(baseline | changes))

    def test_audit_projection_excludes_private_selector_fields(self) -> None:
        target = self.target()
        projection = selector_audit_projection(target, outcome="accepted")
        serialized = json.dumps(projection, sort_keys=True)
        self.assertNotIn(target.profile_sha256, serialized)
        self.assertNotIn(target.code_release_sha256, serialized)
        self.assertNotIn(target.profile_release_path, serialized)
        self.assertNotIn(str(target.profile_owner_uid), serialized)
        self.assertFalse(projection["raw_content_recorded"])
        self.assertFalse(projection["profile_digest_recorded"])
        self.assertFalse(projection["profile_identity_recorded"])
        self.assertTrue(projection["dynamic_private_selector"])
        self.assertFalse(projection["profile_release_pinned"])


if __name__ == "__main__":
    unittest.main()
