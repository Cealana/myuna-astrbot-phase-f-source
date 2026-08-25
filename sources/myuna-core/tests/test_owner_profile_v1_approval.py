from __future__ import annotations

import json
import unittest

from myuna_core.owner_profile.approval import (
    APPROVAL_DECISION,
    APPROVAL_SCOPE,
    APPROVAL_TYPE,
    MAX_APPROVAL_BYTES,
    parse_profile_approval_bytes,
    verify_profile_approval,
)
from myuna_core.owner_profile.contracts import (
    OwnerProfile,
    OwnerProfileError,
    OwnerProfileSection,
)


PROFILE_ID = "synthetic-approved-profile"
PROFILE_DIGEST = "a" * 64


def synthetic_profile() -> OwnerProfile:
    return OwnerProfile(
        profile_id=PROFILE_ID,
        profile_revision=2,
        sections=(
            OwnerProfileSection(
                section_id="synthetic-section",
                topic_key="synthetic-topic",
                category="long_term_preference",
                title="Synthetic title",
                body="Synthetic stable preference.",
                keywords=("synthetic",),
            ),
        ),
        sha256=PROFILE_DIGEST,
        byte_count=256,
    )


def approval_payload(**changes: object) -> bytes:
    payload: dict[str, object] = {
        "schema_version": 1,
        "approval_type": APPROVAL_TYPE,
        "approval_scope": APPROVAL_SCOPE,
        "decision": APPROVAL_DECISION,
        "profile_schema_version": 1,
        "profile_id": PROFILE_ID,
        "profile_revision": 2,
        "profile_sha256": PROFILE_DIGEST,
    }
    payload.update(changes)
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


class OwnerProfileApprovalTests(unittest.TestCase):
    def test_exact_approval_is_accepted_without_raw_profile_content(self) -> None:
        approval = verify_profile_approval(
            synthetic_profile(),
            approval_payload(),
        )
        self.assertEqual(approval.profile_revision, 2)
        serialized = repr(approval)
        self.assertNotIn("Synthetic title", serialized)
        self.assertNotIn("Synthetic stable preference", serialized)

    def test_exact_profile_identity_revision_and_digest_are_bound(self) -> None:
        variants = (
            {"profile_id": "different-profile"},
            {"profile_revision": 3},
            {"profile_sha256": "b" * 64},
        )
        for changes in variants:
            with self.subTest(changes=changes), self.assertRaisesRegex(
                OwnerProfileError,
                "approval_mismatch",
            ):
                verify_profile_approval(
                    synthetic_profile(),
                    approval_payload(**changes),
                )

    def test_unknown_or_malformed_approval_fails_closed(self) -> None:
        unknown = json.loads(approval_payload())
        unknown["unknown"] = True
        variants = (
            b"",
            b"not-json",
            b"\xff",
            b"x" * (MAX_APPROVAL_BYTES + 1),
            json.dumps(unknown).encode("utf-8"),
            approval_payload(schema_version=2),
            approval_payload(schema_version=True),
            approval_payload(profile_schema_version=True),
            approval_payload(profile_revision=True),
            approval_payload(profile_revision=0),
            approval_payload(decision="proposed"),
            approval_payload(approval_scope="conversation"),
            approval_payload(profile_sha256="not-a-digest"),
        )
        for payload in variants:
            with self.subTest(payload_length=len(payload)), self.assertRaisesRegex(
                OwnerProfileError,
                "malformed_approval",
            ):
                parse_profile_approval_bytes(payload)


if __name__ == "__main__":
    unittest.main()
