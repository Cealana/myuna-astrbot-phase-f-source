from __future__ import annotations

import json
from subprocess import CompletedProcess
import unittest

from owner_memory_retrieval_v2.postgres_source import (
    MAX_DATABASE_OUTPUT_BYTES,
    RecordSourceError,
    load_safe_records,
)


def safe_record() -> dict[str, object]:
    return {
        "candidate_id": "M001",
        "namespace_id": "ns-owner-cealana-private",
        "sensitivity": "normal",
        "confirmation_level": "user_confirmed",
    }


class PostgresSourceTests(unittest.TestCase):
    def test_wrong_runtime_identity_fails_before_runner(self) -> None:
        called = False

        def runner(*args: object, **kwargs: object) -> CompletedProcess[str]:
            nonlocal called
            called = True
            raise AssertionError("runner must not be called")

        with self.assertRaises(RecordSourceError) as captured:
            load_safe_records(user_name="myuna", runner=runner)
        self.assertEqual(captured.exception.code, "runtime_identity_mismatch")
        self.assertFalse(called)

    def test_query_uses_fixed_role_view_and_read_only_options(self) -> None:
        captured: dict[str, object] = {}

        def runner(command: list[str], **kwargs: object) -> CompletedProcess[str]:
            captured["command"] = command
            captured.update(kwargs)
            return CompletedProcess(command, 0, json.dumps(safe_record()) + "\n", "")

        records = load_safe_records(user_name="myuna_memory_runtime", runner=runner)
        self.assertEqual([item["candidate_id"] for item in records], ["M001"])
        command = captured["command"]
        assert isinstance(command, list)
        self.assertIn("--username=myuna_memory_runtime", command)
        self.assertIn("memory.owner_memory_runtime_nonrestricted_v1", command[-1])
        environment = captured["env"]
        assert isinstance(environment, dict)
        self.assertIn("default_transaction_read_only=on", environment["PGOPTIONS"])
        self.assertNotIn("HOME", environment)

    def test_boundary_violation_fails_closed(self) -> None:
        record = safe_record()
        record["sensitivity"] = "restricted"

        def runner(command: list[str], **kwargs: object) -> CompletedProcess[str]:
            return CompletedProcess(command, 0, json.dumps(record) + "\n", "")

        with self.assertRaises(RecordSourceError) as captured:
            load_safe_records(user_name="myuna_memory_runtime", runner=runner)
        self.assertEqual(captured.exception.code, "safe_view_boundary_violation")

    def test_output_budget_fails_closed(self) -> None:
        oversized = "x" * (MAX_DATABASE_OUTPUT_BYTES + 1)

        def runner(command: list[str], **kwargs: object) -> CompletedProcess[str]:
            return CompletedProcess(command, 0, oversized, "")

        with self.assertRaises(RecordSourceError) as captured:
            load_safe_records(user_name="myuna_memory_runtime", runner=runner)
        self.assertEqual(captured.exception.code, "safe_view_output_budget_exceeded")


if __name__ == "__main__":
    unittest.main()
