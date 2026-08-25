from __future__ import annotations

import json
import unittest

from myuna_core.owner_profile import OwnerProfileError
from myuna_core.owner_profile.loader import parse_profile_bytes
from myuna_core.owner_profile.projection import (
    error_audit_projection,
    profile_v2_current_projection,
    render_profile_v2_current_context,
    success_audit_projection,
)
from myuna_core.owner_profile.contracts import profile_v2_manifests
from myuna_core.owner_profile.lifecycle import initial_profile_current
from myuna_core.owner_profile.retrieval import OwnerProfileIndex
from test_owner_profile_v1_loader import BASE_PROFILE


class OwnerProfileProjectionTests(unittest.TestCase):
    def test_success_projection_is_content_free_and_uses_new_namespace(self) -> None:
        profile = parse_profile_bytes(BASE_PROFILE)
        result = OwnerProfileIndex(profile).retrieve("月光花园项目")
        projection = success_audit_projection(result, duration_ms=4.25)
        encoded = json.dumps(projection, ensure_ascii=False, sort_keys=True)
        self.assertEqual(projection["event_namespace"], "owner_profile_read_v1")
        self.assertNotIn("owner_memory_read", encoded)
        self.assertEqual(projection["selected_category_counts"], {"ongoing_project": 1})
        self.assertFalse(projection["memory_write_performed"])
        self.assertFalse(projection["legacy_namespace_written"])
        for forbidden in (
            "月光花园项目",
            "测试角色持续维护",
            "garden-project",
            profile.sha256,
            profile.profile_id,
        ):
            self.assertNotIn(forbidden, encoded)

    def test_error_projection_contains_only_category_not_exception_text(self) -> None:
        error = OwnerProfileError("profile_unavailable", retryable=True)
        projection = error_audit_projection(
            error,
            query_characters=9,
            duration_ms=10,
        )
        encoded = json.dumps(projection, ensure_ascii=False, sort_keys=True)
        self.assertEqual(projection["outcome"], "degraded")
        self.assertEqual(projection["error_category"], "profile_unavailable")
        self.assertEqual(projection["query_length_bucket"], "1-32")
        self.assertNotIn("query_fingerprint", encoded)
        self.assertNotIn("这是一条原始查询", encoded)
        self.assertNotIn("identity", encoded)
        self.assertNotIn("message", encoded)
        self.assertNotIn("provider", encoded)

    def test_rejected_query_length_buckets_are_content_free(self) -> None:
        error = OwnerProfileError("query_out_of_contract")
        empty = error_audit_projection(error, query_characters=0, duration_ms=0)
        overlong = error_audit_projection(error, query_characters=257, duration_ms=0)
        self.assertEqual(empty["query_length_bucket"], "0")
        self.assertEqual(overlong["query_length_bucket"], "257+")

    def test_unknown_error_code_cannot_inject_text_into_audit(self) -> None:
        error = OwnerProfileError("synthetic raw profile text")
        projection = error_audit_projection(
            error,
            query_characters=1,
            duration_ms=0,
        )
        encoded = json.dumps(projection, sort_keys=True)
        self.assertEqual(projection["error_category"], "internal_error")
        self.assertNotIn(error.code, encoded)

    def test_v2_projection_exposes_current_only_and_uninitialized_is_absent(self) -> None:
        manifest = profile_v2_manifests()[0]
        current = initial_profile_current(manifest)
        projection = profile_v2_current_projection(manifest, current)
        self.assertEqual(projection["state"], "uninitialized")
        self.assertNotIn("scaled_value", projection)
        self.assertIsNone(render_profile_v2_current_context(manifest, current))
        encoded = json.dumps(projection, ensure_ascii=False, sort_keys=True)
        for forbidden in (
            "reason_category",
            "event_id",
            "raw_source_digest",
            "p08_source_digest",
            "trusted_time_digest",
        ):
            self.assertNotIn(forbidden, encoded)


if __name__ == "__main__":
    unittest.main()
