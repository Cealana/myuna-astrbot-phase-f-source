from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import fault_diagnostics_collector_v1 as collector  # noqa: E402
from degradation_shadow_enqueue import (  # noqa: E402
    DegradationShadowJob,
    build_fault_incident_receipt,
)
from fault_diagnostics_v1 import build_diagnostic_report  # noqa: E402
from gateway_degradation_protocol import (  # noqa: E402
    deterministic_core_unreachable_projection,
)


NOW = datetime(2026, 8, 2, 9, 30, tzinfo=timezone.utc)
CORE_RELEASE = "/srv/myuna/releases/core/" + "a" * 64
QQ_EXEC = "/opt/myuna/context24-gateway/qq/releases/" + "b" * 64 + "/runtime/qq.py"
TELEGRAM_EXEC = (
    "/opt/myuna/context24-gateway/telegram/releases/"
    + "c" * 64
    + "/runtime/telegram.py"
)


def rooted(root: Path, path: Path) -> Path:
    return root / str(path).lstrip("/")


def write(root: Path, path: Path, payload: bytes, mode: int = 0o640) -> Path:
    target = rooted(root, path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    target.chmod(mode)
    return target


def build_tree(root: Path, *, with_receipt: bool = True) -> None:
    digests: dict[str, str] = {}
    for key, path in collector._SAFE_UNIT_FILES.items():
        payload = f"safe-unit:{key}\n".encode("ascii")
        write(root, path, payload, 0o644)
        digests[key] = sha256(payload).hexdigest()
    baseline = {
        "schema": collector.BASELINE_SCHEMA,
        "core_working_directory": CORE_RELEASE,
        "qq_exec_path": QQ_EXEC,
        "telegram_exec_path": TELEGRAM_EXEC,
        "session_capacity_messages": 128,
        "session_capacity_characters": 131072,
        "safe_unit_digests": digests,
    }
    write(
        root,
        collector.BASELINE_PATH,
        json.dumps(baseline, sort_keys=True).encode("ascii"),
    )
    for path in collector._SESSION_FILES.values():
        write(root, path, b"synthetic-db-never-read", 0o600)
    proc = (
        "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n"
        "   0: 0100007F:036F 00000000:0000 0A 00000000:00000000 00:00000000 0\n"
    )
    write(root, Path("/proc/net/tcp"), proc.encode("ascii"), 0o444)
    if with_receipt:
        job = DegradationShadowJob.from_projection(
            deterministic_core_unreachable_projection(),
            projection_source="gateway",
            channel="telegram",
            request_id="gateway-synthetic-collector-001",
        )
        write(
            root,
            collector._RECEIPT_FILES["telegram"],
            build_fault_incident_receipt(job, observed_at=NOW),
        )


def systemctl_state(unit: str, timeout: float) -> dict[str, str]:
    is_socket = unit.endswith(".socket")
    exec_start = ""
    working_directory = ""
    if unit == "myuna-core@qq.service":
        working_directory = CORE_RELEASE
    elif unit == "myuna-qq-owner-runtime-dev.service":
        exec_start = "python3 " + QQ_EXEC
    elif unit == "myuna-telegram-owner-runtime-dev.service":
        exec_start = "python3 " + TELEGRAM_EXEC
    return {
        "ActiveState": "active",
        "SubState": "listening" if is_socket else "running",
        "NRestarts": "0",
        "ExecStart": exec_start,
        "WorkingDirectory": working_directory,
    }


class FaultDiagnosticsCollectorV1Tests(unittest.TestCase):
    def test_collects_allowlisted_metadata_and_recent_incident(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build_tree(root)
            real_open = os.open

            def guarded_open(path, *args, **kwargs):
                if str(path).endswith("context.db"):
                    raise AssertionError("session database content must not be opened")
                return real_open(path, *args, **kwargs)

            with patch.object(collector.os, "open", side_effect=guarded_open):
                snapshot = collector.collect_diagnostic_snapshot(
                    "all",
                    now=NOW,
                    root=root,
                    systemctl_reader=systemctl_state,
                )
        report = build_diagnostic_report(snapshot)
        self.assertEqual(report["overall"], "failed")
        self.assertRegex(report["incident_ref"], r"^inc-[0-9a-f]{12}$")
        pairs = {(item["target"], item["code"]) for item in report["findings"]}
        self.assertIn(("telegram_gateway", "core_unreachable"), pairs)
        self.assertIn(("telegram_session", "session_capacity_128"), pairs)
        self.assertIn(("qq_session", "secure"), pairs)
        self.assertIn(("local_provider", "listening"), pairs)
        self.assertIn(("release", "match"), pairs)
        self.assertIs(report["audit_projection"]["private_content_read"], False)

    def test_release_drift_and_missing_baseline_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build_tree(root, with_receipt=False)
            rooted(root, collector._SAFE_UNIT_FILES["qq_unit"]).write_bytes(b"drift")
            drift = collector.collect_diagnostic_snapshot(
                "qq",
                now=NOW,
                root=root,
                systemctl_reader=systemctl_state,
            )
            rooted(root, collector.BASELINE_PATH).unlink()
            unknown = collector.collect_diagnostic_snapshot(
                "qq",
                now=NOW,
                root=root,
                systemctl_reader=systemctl_state,
            )
        drift_pairs = {(item["target"], item["code"]) for item in drift["observations"]}
        unknown_pairs = {
            (item["target"], item["code"]) for item in unknown["observations"]
        }
        self.assertIn(("release", "release_drift"), drift_pairs)
        self.assertIn(
            ("qq_session", "unknown_insufficient_safe_evidence"),
            unknown_pairs,
        )
        self.assertNotIn(("qq_session", "session_capacity_mismatch"), unknown_pairs)

    def test_systemctl_probe_is_exact_read_only_and_bounded(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": (
                    b"ActiveState=active\nSubState=running\nNRestarts=0\n"
                    b"ExecStart=/usr/bin/python3\nWorkingDirectory=/safe\n"
                ),
            },
        )()
        with patch.object(collector.subprocess, "run", return_value=completed) as run:
            state = collector._systemctl_show("myuna-core@qq.service", 0.1)
        self.assertEqual(state["ActiveState"], "active")
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["/usr/bin/systemctl", "show", "myuna-core@qq.service"])
        self.assertNotIn("start", command)
        self.assertNotIn("restart", command)
        self.assertNotIn("status", command)
        self.assertLessEqual(run.call_args.kwargs["timeout"], 0.1)
        with self.assertRaises(ValueError):
            collector._systemctl_show("unapproved.service", 0.1)

    def test_socket_probe_requests_only_socket_metadata(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": b"ActiveState=active\nSubState=running\n",
            },
        )()
        unit = "myuna-owner-profile-read-v1.socket"
        with patch.object(collector.subprocess, "run", return_value=completed) as run:
            state = collector._systemctl_show(unit, 0.1)
        self.assertEqual(state, {"ActiveState": "active", "SubState": "running"})
        command = run.call_args.args[0]
        self.assertNotIn("--property=NRestarts", command)
        self.assertNotIn("--property=ExecStart", command)
        self.assertNotIn("--property=WorkingDirectory", command)

    def test_collector_source_has_no_channel_model_health_or_private_probe(self) -> None:
        source = (ROOT / "scripts/fault_diagnostics_collector_v1.py").read_text()
        for forbidden in (
            "/healthz",
            "/readyz",
            "/v1/status",
            "/v1/chat",
            "journalctl",
            "SELECT ",
            "sqlite3",
            "provider_payload",
            "profile_content",
            "message_text",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
