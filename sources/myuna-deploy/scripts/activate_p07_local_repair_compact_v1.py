#!/usr/bin/env python3
"""Activate the P07 Core release with a compact single-echo repair contract."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess


_PREVIOUS_PATH = Path(__file__).with_name("activate_p07_local_repair_bounded_v1.py")
_PREVIOUS_SPEC = importlib.util.spec_from_file_location(
    "_p07_local_repair_compact_previous",
    _PREVIOUS_PATH,
)
if _PREVIOUS_SPEC is None or _PREVIOUS_SPEC.loader is None:
    raise RuntimeError("previous_activator_unavailable")
previous = importlib.util.module_from_spec(_PREVIOUS_SPEC)
_PREVIOUS_SPEC.loader.exec_module(previous)
base = previous.base


CURRENT_RELEASE = "78ce7d886ed14f240fc17ca5ad29ca38cb4c2d42774edd37ce7b25a274b1f203"
CURRENT_BINDING_SHA256 = (
    "f4f45827ee7cc133b49725311fd1f229b27fb20728ecd63998280301f6b6908a"
)
CURRENT_SELECTOR_SHA256 = (
    "29405d856cc4bd631b3868f220b696c3c69f4f04e26d7fbf14afb1190b572efc"
)
TARGET_RELEASE = "e71e808c4a1b9b8b95eac075e59efb7651461b4828ff0411a8f54378f4326866"
TARGET_COMMIT = "b79a10d90228b0229f2db6d185bbdbc50b48b3a2"
TARGET_FILE_COUNT = 273
TARGET_CORE_TESTS = 657
LOCAL_INPUT_CHARACTER_CEILING = 14_000
LOCAL_REPAIR_MINIMUM_HEADROOM = 2_000
BACKUP_ROOT = Path("/var/backups/myuna/p07-local-repair-compact-v1")
RECEIPT_ROOT = Path(
    "/var/lib/myuna/core-release-selector/p07-local-repair-compact-v1"
)
RECEIPT = RECEIPT_ROOT / f"{TARGET_RELEASE}.json"
SCHEMA = "myuna.p07-local-repair-compact-activation.v1"
ACTIVE_STATUS = "ACTIVE_WAITING_OWNER_ORGANIC_CONTINUITY_E2E_V4"


for module in (
    previous,
    previous.previous,
    previous.previous.previous,
    previous.previous.previous.previous,
    base,
):
    for name, value in (
        ("CURRENT_RELEASE", CURRENT_RELEASE),
        ("CURRENT_BINDING_SHA256", CURRENT_BINDING_SHA256),
        ("CURRENT_SELECTOR_SHA256", CURRENT_SELECTOR_SHA256),
        ("TARGET_RELEASE", TARGET_RELEASE),
        ("TARGET_COMMIT", TARGET_COMMIT),
        ("TARGET_FILE_COUNT", TARGET_FILE_COUNT),
        ("BACKUP_ROOT", BACKUP_ROOT),
        ("RECEIPT_ROOT", RECEIPT_ROOT),
        ("RECEIPT", RECEIPT),
        ("SCHEMA", SCHEMA),
    ):
        setattr(module, name, value)


ActivationRejected = base.ActivationRejected
canonical_json_bytes = base.canonical_json_bytes
digest_bytes = base.digest_bytes
digest_file = base.digest_file
_validate_bounded_candidate = previous.validate_candidate


def artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07-local-repair-compact-v1",
            "status": "offline_tested_not_installed",
            "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
            "tree_sha256": TARGET_RELEASE,
            "source_commit": TARGET_COMMIT,
            "file_count": TARGET_FILE_COUNT,
            "verification": {
                "core_tests": TARGET_CORE_TESTS,
                "private_content_present": False,
                "provider_calls": 0,
                "recent_assistant_echo_guard": "local-near-duplicate-repair-v1",
                "single_echo_compact_repair": "dialogue-only-v1",
                "local_repair_projection": "system-plus-current-exchange-v1",
                "local_repair_projected_message_count": 4,
                "local_input_character_ceiling": LOCAL_INPUT_CHARACTER_CEILING,
                "local_repair_minimum_headroom": LOCAL_REPAIR_MINIMUM_HEADROOM,
                "oversize_rejected_before_transport": True,
                "limits_increased": False,
                "gateway_timeout_changed": False,
                "profile_revision_mutated": False,
                "session_store_mutated": False,
            },
        }
    )


def plan_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": SCHEMA,
            "status": "standing_authority",
            "executor_sha256": digest_file(Path(__file__).resolve()),
            "prestate": {
                "core_release": CURRENT_RELEASE,
                "binding_sha256": CURRENT_BINDING_SHA256,
                "selector_sha256": CURRENT_SELECTOR_SHA256,
                "profile_service": "active",
                "local_provider": "active-qwen3-1.7b",
            },
            "target": {
                "core_release": TARGET_RELEASE,
                "core_source_commit": TARGET_COMMIT,
                "recent_assistant_echo_guard": "unchanged",
                "single_echo_repair": "compact-dialogue-only-v1",
                "local_repair_projection": "system-plus-current-exchange-v1",
                "local_repair_tail_messages": 3,
                "local_input_character_ceiling": LOCAL_INPUT_CHARACTER_CEILING,
                "local_repair_minimum_headroom": LOCAL_REPAIR_MINIMUM_HEADROOM,
                "direct_profile_projection": "unchanged-strict-current-turn-v1",
                "incidental_profile_enrichment": "unchanged-recent-complete-turns-v1",
                "session_store": "unchanged-128-message-window",
                "profile_revisions": "unchanged",
                "writer": "unchanged",
                "p08": "no-write-no-double-write",
            },
            "live_scope": {
                "core_restart_max": 1,
                "gateway_restarts": 0,
                "gateway_quiesce_restore": [
                    "qq-owner-private",
                    "telegram-owner-private",
                ],
                "local_provider_restart": 0,
                "profile_service_restart": 0,
                "limits_or_timeouts_changed": False,
                "health_endpoints_forbidden": True,
                "channel_calls_forbidden": True,
                "provider_calls_forbidden": True,
                "real_profile_probe_forbidden": True,
            },
            "rollback": {
                "restore_binding_and_selector_exact_bytes": True,
                "restore_core_release": CURRENT_RELEASE,
                "retain_installed_release": True,
                "preserve_profile_and_session_data": True,
            },
        }
    )


def _run_candidate_test(candidate: Path, pattern: str, test_name: str) -> None:
    resolved = candidate.resolve()
    completed = subprocess.run(
        [
            "/usr/bin/python3",
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            str(resolved / "tests"),
            "-p",
            pattern,
            "-k",
            test_name,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": f"{resolved}/src",
        },
    )
    base.require(completed.returncode == 0, "candidate_compact_repair_probe_rejected")


def validate_candidate(candidate: Path) -> None:
    _validate_bounded_candidate(candidate)
    resolved = candidate.resolve()
    source_path = resolved / "src/myuna_core/conversation.py"
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ActivationRejected("candidate_compact_repair_source_unavailable") from exc
    required = (
        "_local_recent_assistant_echo_repair_correction",
        'set(violations) != {"recent_assistant_echo_without_continuity"}',
        "Discard that ",
        "candidate. Answer the original final user message directly and naturally",
        "Do not introduce Myuna or ",
        "explain the repair",
    )
    base.require(
        all(item in source for item in required),
        "candidate_compact_repair_wiring_rejected",
    )
    _run_candidate_test(
        candidate,
        "test_conversation.py",
        "test_local_recent_assistant_echo_is_repaired_for_ordinary_chat",
    )
    _run_candidate_test(
        candidate,
        "test_provider_local_runtime.py",
        "test_local_repair_projection_honors_final_character_ceiling",
    )


def write_receipt(root: Path, plan: bytes) -> None:
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True)
    base.os.chmod(RECEIPT_ROOT, 0o700)
    if RECEIPT.exists():
        raise ActivationRejected("activation_receipt_conflict")
    payload = canonical_json_bytes(
        {
            "schema": SCHEMA,
            "status": ACTIVE_STATUS,
            "plan_sha256": digest_bytes(plan),
            "backup": root.name,
            "core_release": TARGET_RELEASE,
            "core_source_commit": TARGET_COMMIT,
            "core_tests": TARGET_CORE_TESTS,
            "single_echo_repair": "compact-dialogue-only-v1",
            "local_repair_projection": "system-plus-current-exchange-v1",
            "local_repair_projected_message_count": 4,
            "local_input_character_ceiling": LOCAL_INPUT_CHARACTER_CEILING,
            "local_repair_minimum_headroom": LOCAL_REPAIR_MINIMUM_HEADROOM,
            "oversize_rejected_before_transport": True,
            "limits_or_timeouts_changed": False,
            "direct_profile_projection_changed": False,
            "session_store_changed": False,
            "profile_revision_changed": False,
            "writer_called": False,
            "p08_written": False,
            "local_provider_restarted": False,
            "profile_service_restarted": False,
            "channel_called": False,
            "provider_called": False,
            "health_endpoint_called": False,
            "profile_content_recorded": False,
            "raw_identity_recorded": False,
            "raw_message_recorded": False,
            "secret_recorded": False,
        }
    )
    base._atomic_write(RECEIPT, payload, mode=0o600)
    base._atomic_write(root / "RECEIPT.json", payload, mode=0o600)


base.artifact_manifest_bytes = artifact_manifest_bytes
base.plan_bytes = plan_bytes
base.validate_candidate = validate_candidate
base.write_receipt = write_receipt

installation_receipt_bytes = base.installation_receipt_bytes
target_evidence = base.target_evidence
target_binding = base.target_binding


def activate(candidate: Path, *, preflight_only: bool) -> dict[str, object]:
    result = base.activate(candidate, preflight_only=preflight_only)
    if preflight_only:
        return result
    return {**result, "status": ACTIVE_STATUS}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    try:
        result = activate(arguments.candidate, preflight_only=arguments.preflight_only)
    except (ActivationRejected, OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
