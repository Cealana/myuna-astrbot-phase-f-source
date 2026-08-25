from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.owner_profile.contracts import MAX_PROFILE_BYTES
from myuna_core.owner_profile.loader import (
    build_receipt,
    load_approved_profile,
    parse_profile_bytes,
)
from myuna_core.owner_profile import OwnerProfileError


BASE_PROFILE = '''schema_version = 1
document_type = "owner_profile_baseline"
profile_id = "synthetic-owner-profile"
profile_revision = 1

[[sections]]
section_id = "about-owner"
topic_key = "about.owner"
category = "self_introduction"
title = "合成自我介绍"
body = "这是完全合成的测试资料，不代表真实 Owner。"
keywords = ["合成资料", "自我介绍"]

[[sections]]
section_id = "communication-style"
topic_key = "preference.communication"
category = "long_term_preference"
title = "合成沟通偏好"
body = "测试角色长期偏好先给结论，再说明可验证依据。"
keywords = ["沟通偏好", "先给结论"]

[[sections]]
section_id = "learning-goal"
topic_key = "goal.learning"
category = "long_term_goal"
title = "合成长期目标"
body = "测试角色希望长期学习可验证的软件设计方法。"
keywords = ["长期目标", "软件设计"]

[[sections]]
section_id = "garden-project"
topic_key = "project.garden"
category = "ongoing_project"
title = "合成花园项目"
body = "测试角色持续维护一个虚构的月光花园项目。"
keywords = ["花园项目", "持续项目"]
'''.encode("utf-8")


def create_release(root: Path, payload: bytes = BASE_PROFILE) -> tuple[Path, str]:
    receipt = build_receipt(payload)
    digest = str(receipt["profile_sha256"])
    revision = int(receipt["profile_revision"])
    release = root / f"r{revision}-{digest}"
    release.mkdir(mode=0o700)
    profile_path = release / "profile.toml"
    profile_path.write_bytes(payload)
    profile_path.chmod(0o600)
    receipt_path = release / "receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)
    return release, digest


class OwnerProfileLoaderTests(unittest.TestCase):
    def test_loads_exact_version_digest_unicode_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release, digest = create_release(Path(temporary))
            profile = load_approved_profile(release, expected_sha256=digest)
        self.assertEqual(profile.profile_revision, 1)
        self.assertEqual(profile.sha256, digest)
        self.assertEqual(len(profile.sections), 4)
        self.assertIn("完全合成", profile.sections[0].body)
        self.assertEqual(dict(profile.category_counts)["ongoing_project"], 1)

    def test_short_reads_still_verify_the_complete_exact_bytes(self) -> None:
        real_read = os.read
        with tempfile.TemporaryDirectory() as temporary:
            release, digest = create_release(Path(temporary))
            with patch(
                "myuna_core.owner_profile.loader.os.read",
                side_effect=lambda descriptor, maximum: real_read(
                    descriptor,
                    min(maximum, 7),
                ),
            ):
                profile = load_approved_profile(release, expected_sha256=digest)
        self.assertEqual(profile.sha256, digest)
        self.assertEqual(profile.byte_count, len(BASE_PROFILE))

    def test_digest_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release, digest = create_release(Path(temporary))
            with self.assertRaises(OwnerProfileError) as captured:
                load_approved_profile(release, expected_sha256="0" * 64)
        self.assertEqual(captured.exception.code, "release_identity_mismatch")
        self.assertNotEqual(digest, "0" * 64)

    def test_receipt_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release, digest = create_release(Path(temporary))
            receipt_path = release / "receipt.json"
            receipt = json.loads(receipt_path.read_text("utf-8"))
            receipt["section_count"] = 99
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            receipt_path.chmod(0o600)
            with self.assertRaises(OwnerProfileError) as captured:
                load_approved_profile(release, expected_sha256=digest)
        self.assertEqual(captured.exception.code, "receipt_mismatch")

    def test_unknown_schema_is_rejected(self) -> None:
        payload = BASE_PROFILE.replace(b"schema_version = 1", b"schema_version = 99")
        with self.assertRaises(OwnerProfileError) as captured:
            parse_profile_bytes(payload)
        self.assertEqual(captured.exception.code, "unknown_schema_version")

    def test_corrupt_toml_is_rejected(self) -> None:
        with self.assertRaises(OwnerProfileError) as captured:
            parse_profile_bytes(b"schema_version = [")
        self.assertEqual(captured.exception.code, "malformed_profile")

    def test_oversize_profile_is_rejected_before_parse(self) -> None:
        with self.assertRaises(OwnerProfileError) as captured:
            parse_profile_bytes(b"x" * (MAX_PROFILE_BYTES + 1))
        self.assertEqual(captured.exception.code, "profile_oversize")

    def test_duplicate_section_id_is_rejected(self) -> None:
        payload = BASE_PROFILE.replace(
            b'section_id = "garden-project"',
            b'section_id = "about-owner"',
        )
        with self.assertRaises(OwnerProfileError) as captured:
            parse_profile_bytes(payload)
        self.assertEqual(captured.exception.code, "duplicate_section_id")

    def test_duplicate_content_is_rejected(self) -> None:
        source = "这是完全合成的测试资料，不代表真实 Owner。".encode()
        replacement = "测试角色持续维护一个虚构的月光花园项目。".encode()
        payload = BASE_PROFILE.replace(replacement, source)
        with self.assertRaises(OwnerProfileError) as captured:
            parse_profile_bytes(payload)
        self.assertEqual(captured.exception.code, "duplicate_section_content")

    def test_conflicting_topic_key_is_rejected(self) -> None:
        payload = BASE_PROFILE.replace(
            b'topic_key = "project.garden"',
            b'topic_key = "about.owner"',
        )
        with self.assertRaises(OwnerProfileError) as captured:
            parse_profile_bytes(payload)
        self.assertEqual(captured.exception.code, "conflicting_topic_key")

    def test_permission_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release, digest = create_release(Path(temporary))
            (release / "profile.toml").chmod(0o640)
            with self.assertRaises(OwnerProfileError) as captured:
                load_approved_profile(release, expected_sha256=digest)
        self.assertEqual(captured.exception.code, "profile_permission_drift")

    def test_release_directory_permission_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release, digest = create_release(Path(temporary))
            release.chmod(0o750)
            with self.assertRaises(OwnerProfileError) as captured:
                load_approved_profile(release, expected_sha256=digest)
        self.assertEqual(captured.exception.code, "profile_permission_drift")

    def test_symlink_type_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release, digest = create_release(root)
            external = root / "external.toml"
            external.write_bytes(BASE_PROFILE)
            profile_path = release / "profile.toml"
            profile_path.unlink()
            profile_path.symlink_to(external)
            with self.assertRaises(OwnerProfileError) as captured:
                load_approved_profile(release, expected_sha256=digest)
        self.assertEqual(captured.exception.code, "profile_type_drift")

    def test_release_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release, digest = create_release(root)
            alias = root / f"alias-{release.name}"
            alias.symlink_to(release, target_is_directory=True)
            with self.assertRaises(OwnerProfileError) as captured:
                load_approved_profile(alias, expected_sha256=digest)
        self.assertEqual(captured.exception.code, "profile_type_drift")

    def test_owner_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release, digest = create_release(Path(temporary))
            with self.assertRaises(OwnerProfileError) as captured:
                load_approved_profile(
                    release,
                    expected_sha256=digest,
                    expected_owner_uid=os.geteuid() + 1,
                )
        self.assertEqual(captured.exception.code, "profile_permission_drift")


if __name__ == "__main__":
    unittest.main()
