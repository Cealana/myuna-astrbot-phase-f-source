from __future__ import annotations

from pathlib import Path
import re
import stat
from tempfile import TemporaryDirectory
import json
import unittest

from myuna_core.audit import AuditLogger


class AuditTests(unittest.TestCase):
    def test_sensitive_values_are_redacted_recursively(self) -> None:
        with TemporaryDirectory() as temp:
            logger = AuditLogger(Path(temp), "dev")
            logger.emit(
                "test",
                details={
                    "api_key": "should-not-appear",
                    "nested": {
                        "Authorization": "Bearer secret",
                        "safe": "visible",
                        "input_tokens": 123,
                        "refresh_token": "also-secret",
                    },
                },
            )
            record = json.loads(logger.path.read_text(encoding="utf-8"))
            self.assertEqual(record["details"]["api_key"], "[REDACTED]")
            self.assertEqual(record["details"]["nested"]["Authorization"], "[REDACTED]")
            self.assertEqual(record["details"]["nested"]["safe"], "visible")
            self.assertEqual(record["details"]["nested"]["input_tokens"], 123)
            self.assertEqual(record["details"]["nested"]["refresh_token"], "[REDACTED]")
            self.assertNotIn("should-not-appear", logger.path.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(logger.path.stat().st_mode), 0o600)

    def test_content_free_trace_marker_has_exact_finite_shape(self) -> None:
        with TemporaryDirectory() as temp:
            logger = AuditLogger(Path(temp), "dev")
            trace_id = "trace-" + "a" * 32
            logger.emit_trace_marker(
                trace_id=trace_id,
                stage="provider_attempt_started",
                status="started",
                attempt_ordinal=2,
            )
            raw = logger.path.read_bytes()
            self.assertTrue(raw.endswith(b"\n"))
            self.assertEqual(raw.count(b"\n"), 1)
            self.assertNotIn(b"\r", raw)
            record = json.loads(raw.decode("utf-8"))
            self.assertEqual(
                set(record),
                {"marker", "timestamp"},
            )
            self.assertEqual(
                record["marker"],
                {
                    "attempt_ordinal": 2,
                    "round_ordinal": 0,
                    "stage": "provider_attempt_started",
                    "status": "started",
                    "trace_id": trace_id,
                    "version": 1,
                },
            )
            self.assertEqual(
                set(record["marker"]),
                {
                    "attempt_ordinal",
                    "round_ordinal",
                    "stage",
                    "status",
                    "trace_id",
                    "version",
                },
            )
            self.assertRegex(
                record["timestamp"],
                r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
            )
            self.assertIsNone(re.search(r"\.\d+", record["timestamp"]))
            forbidden = {
                "environment",
                "event",
                "outcome",
                "request_id",
                "exception",
                "url",
                "identity",
                "secret",
                "payload",
            }
            self.assertTrue(forbidden.isdisjoint(record))
            self.assertTrue(forbidden.isdisjoint(record["marker"]))
            self.assertNotIn("private-sentinel", raw.decode("utf-8"))
            for invalid in (
                {"trace_id": "private sentinel with spaces"},
                {"trace_id": 7},
                {"stage": "free-form-stage"},
                {"stage": 7},
                {"status": "exception-body"},
                {"status": 7},
                {"attempt_ordinal": True},
                {"attempt_ordinal": 1.0},
                {"round_ordinal": True},
                {"round_ordinal": 1.0},
            ):
                values = {
                    "trace_id": trace_id,
                    "stage": "core_request_started",
                    "status": "started",
                    "attempt_ordinal": 1,
                }
                values.update(invalid)
                with self.assertRaises(ValueError):
                    logger.emit_trace_marker(**values)

            with self.assertRaises(TypeError):
                logger.emit_trace_marker(
                    trace_id=trace_id,
                    stage="core_request_started",
                    status="started",
                    payload="private-sentinel",
                )

            logger.emit_trace_marker(
                trace_id="trace-b",
                stage="core_response_returned",
                status="succeeded",
                attempt_ordinal=1,
                round_ordinal=1,
            )
            lines = logger.path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertTrue(all(set(json.loads(line)) == {"marker", "timestamp"} for line in lines))


if __name__ == "__main__":
    unittest.main()
