from __future__ import annotations

from contextlib import redirect_stdout
from io import BytesIO, StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fault_diagnostics_v1 import (  # noqa: E402
    AUDIT_NAMESPACE,
    OUTPUT_SCHEMA,
    SNAPSHOT_SCHEMA,
    build_diagnostic_report,
    incident_ref_for_request,
)
import myuna_diagnose  # noqa: E402


def snapshot(*observations: dict[str, str]) -> dict[str, object]:
    return {
        "schema": SNAPSHOT_SCHEMA,
        "observed_at": "2026-08-02T08:00:00Z",
        "channel": "telegram",
        "incident_ref": incident_ref_for_request("gateway-synthetic-001"),
        "observations": list(observations),
    }


class FaultDiagnosticsV1Tests(unittest.TestCase):
    def test_mixed_snapshot_returns_fixed_content_free_report(self) -> None:
        report = build_diagnostic_report(
            snapshot(
                {
                    "target": "core",
                    "code": "active",
                    "evidence_class": "verified_live",
                },
                {
                    "target": "local_provider",
                    "code": "local_model_not_ready",
                    "evidence_class": "verified_live",
                },
                {
                    "target": "telegram_session",
                    "code": "secure",
                    "evidence_class": "verified_live",
                },
            )
        )
        self.assertEqual(report["schema"], OUTPUT_SCHEMA)
        self.assertEqual(report["overall"], "failed")
        self.assertEqual(report["audit_projection"]["event_namespace"], AUDIT_NAMESPACE)
        local = next(
            item for item in report["findings"] if item["target"] == "local_provider"
        )
        self.assertEqual(local["layer"], "local_provider")
        self.assertEqual(local["recovery_gate"], "T2")
        self.assertIs(local["owner_action_required"], True)
        encoded = json.dumps(report, ensure_ascii=False)
        for forbidden in (
            "message_text",
            "profile_content",
            "credential_value",
            "provider_payload",
            "raw_model_response",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_budget_accounting_and_session_repair_require_t3(self) -> None:
        report = build_diagnostic_report(
            snapshot(
                {
                    "target": "deepseek_budget",
                    "code": "budget_accounting_failed",
                    "evidence_class": "verified_live",
                },
                {
                    "target": "qq_session",
                    "code": "session_unavailable",
                    "evidence_class": "verified_live",
                },
            )
        )
        self.assertEqual(
            {item["recovery_gate"] for item in report["findings"]},
            {"T3"},
        )

    def test_session_capacity_checks_128_without_reading_rows(self) -> None:
        report = build_diagnostic_report(
            snapshot(
                {
                    "target": "telegram_session",
                    "code": "session_capacity_128",
                    "evidence_class": "verified_live",
                },
                {
                    "target": "qq_session",
                    "code": "session_capacity_mismatch",
                    "evidence_class": "source_only",
                },
            )
        )
        by_target = {item["target"]: item for item in report["findings"]}
        self.assertEqual(by_target["telegram_session"]["state"], "ok")
        self.assertEqual(by_target["qq_session"]["recovery_gate"], "T2")
        self.assertFalse(report["audit_projection"]["private_content_read"])

    def test_duplicate_unknown_and_extra_fields_fail_closed(self) -> None:
        item = {
            "target": "core",
            "code": "active",
            "evidence_class": "verified_live",
        }
        with self.assertRaises(ValueError):
            build_diagnostic_report(snapshot(item, dict(item)))
        unknown = snapshot(dict(item))
        unknown["observations"][0]["code"] = "free_form_failure"
        with self.assertRaises(ValueError):
            build_diagnostic_report(unknown)
        extra = snapshot(dict(item))
        extra["raw_log"] = "forbidden"
        with self.assertRaises(ValueError):
            build_diagnostic_report(extra)

    def test_target_and_code_mismatch_fails_closed(self) -> None:
        mismatched = snapshot(
            {
                "target": "profile_reader",
                "code": "provider_timeout",
                "evidence_class": "source_only",
            }
        )
        with self.assertRaises(ValueError):
            build_diagnostic_report(mismatched)

    def test_incident_reference_is_stable_and_rejects_unsafe_ids(self) -> None:
        first = incident_ref_for_request("gateway-synthetic-001")
        second = incident_ref_for_request("gateway-synthetic-001")
        self.assertEqual(first, second)
        self.assertRegex(first, r"^inc-[0-9a-f]{12}$")
        with self.assertRaises(ValueError):
            incident_ref_for_request("unsafe request id")

    def test_cli_reads_only_explicit_snapshot_and_returns_nonzero_for_fault(self) -> None:
        payload = json.dumps(
            snapshot(
                {
                    "target": "telegram_gateway",
                    "code": "core_unreachable",
                    "evidence_class": "verified_live",
                }
            )
        ).encode("utf-8")
        stdout = StringIO()
        stdin = type("Input", (), {"buffer": BytesIO(payload)})()
        with patch.object(sys, "stdin", stdin), redirect_stdout(stdout):
            exit_code = myuna_diagnose.main(["--snapshot", "-"])
        self.assertEqual(exit_code, 2)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["overall"], "failed")
        self.assertIs(result["audit_projection"]["state_changed"], False)

    def test_cli_invalid_input_does_not_echo_rejected_content(self) -> None:
        forbidden = "synthetic-private-marker"
        stdout = StringIO()
        stdin = type("Input", (), {"buffer": BytesIO(forbidden.encode())})()
        with patch.object(sys, "stdin", stdin), redirect_stdout(stdout):
            exit_code = myuna_diagnose.main(["--snapshot", "-"])
        self.assertEqual(exit_code, 3)
        self.assertNotIn(forbidden, stdout.getvalue())
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["error"], "invalid_snapshot")
        self.assertIs(result["private_content_read"], False)

    def test_cli_source_has_no_live_probe_or_mutation_imports(self) -> None:
        source = (ROOT / "scripts/myuna_diagnose.py").read_text(encoding="utf-8")
        for forbidden in (
            "import socket",
            "import subprocess",
            "requests",
            "urlopen",
            "systemctl",
            "journalctl",
            "docker",
            "/healthz",
            "/readyz",
        ):
            self.assertNotIn(forbidden, source)

    def test_cli_rejects_oversized_regular_file_before_json_parse(self) -> None:
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b"{" + b"x" * (128 * 1024))
            handle.flush()
            with self.assertRaisesRegex(ValueError, "snapshot size is invalid"):
                myuna_diagnose._load_snapshot(handle.name)


if __name__ == "__main__":
    unittest.main()
