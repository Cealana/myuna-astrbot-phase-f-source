from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.audit import AuditLogger
from myuna_core.owner_profile.client import AuditedOwnerProfileReadRuntime
from myuna_core.owner_profile.contracts import OwnerProfileError, RetrievalResult


class FakeClient:
    def __init__(self, result: RetrievalResult | OwnerProfileError) -> None:
        self.result = result

    def retrieve(self, *args: object, **kwargs: object) -> RetrievalResult:
        if isinstance(self.result, OwnerProfileError):
            raise self.result
        return self.result


class OwnerProfileClientAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.audit = AuditLogger(Path(self.temporary.name), "dev")

    def records(self) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in self.audit.path.read_text("utf-8").splitlines()
        ]

    def test_empty_success_audit_contains_no_query_or_digest(self) -> None:
        result = RetrievalResult(
            state="empty",
            profile_revision=2,
            profile_sha256="a" * 64,
            query_characters=18,
            sections=(),
            context=None,
        )
        runtime = AuditedOwnerProfileReadRuntime(
            FakeClient(result),  # type: ignore[arg-type]
            self.audit,
            monotonic=iter((1.0, 1.005)).__next__,
        )
        runtime.retrieve(
            "private raw query",
            request_id="req-1",
            channel_kind="astrbot_telegram",
        )
        encoded = json.dumps(self.records(), sort_keys=True)
        self.assertIn("owner_profile_read_v1", encoded)
        self.assertNotIn("private raw query", encoded)
        self.assertNotIn("a" * 64, encoded)

    def test_error_audit_contains_only_fixed_category(self) -> None:
        unavailable = OwnerProfileError("profile_unavailable", retryable=True)
        runtime = AuditedOwnerProfileReadRuntime(
            FakeClient(unavailable),  # type: ignore[arg-type]
            self.audit,
            monotonic=iter((2.0, 2.010)).__next__,
        )
        with self.assertRaises(OwnerProfileError):
            runtime.retrieve(
                "another private query",
                request_id="req-2",
                channel_kind="astrbot_telegram",
            )
        encoded = json.dumps(self.records(), sort_keys=True)
        self.assertIn("profile_unavailable", encoded)
        self.assertNotIn("another private query", encoded)


if __name__ == "__main__":
    unittest.main()
