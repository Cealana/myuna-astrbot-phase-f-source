#!/usr/bin/env python3
"""Activate the P07 Core release with bounded stale-assistant echo detection."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess


_PREVIOUS_PATH = Path(__file__).with_name("activate_p07_local_repair_compact_v1.py")
_PREVIOUS_SPEC = importlib.util.spec_from_file_location(
    "_p07_stale_assistant_echo_previous",
    _PREVIOUS_PATH,
)
if _PREVIOUS_SPEC is None or _PREVIOUS_SPEC.loader is None:
    raise RuntimeError("previous_activator_unavailable")
previous = importlib.util.module_from_spec(_PREVIOUS_SPEC)
_PREVIOUS_SPEC.loader.exec_module(previous)
base = previous.base


CURRENT_RELEASE = "e71e808c4a1b9b8b95eac075e59efb7651461b4828ff0411a8f54378f4326866"
CURRENT_BINDING_SHA256 = (
    "53ba3ce85f09dd837e4c160a04a02cf54114995945bd3865b0cd1123ddef9cb8"
)
CURRENT_SELECTOR_SHA256 = (
    "97a1b28be28aa1735857e65a24da3da41f8a00dd27f22fe8afa4a7392f8196bd"
)
TARGET_RELEASE = "9158f0d5efc4cebf1bab28416c1f2346211263e156b9dcdfdc53c27345de696b"
TARGET_COMMIT = "1643d32d873b7d3cd60f82005186d0ff254623c8"
TARGET_FILE_COUNT = 273
TARGET_CORE_TESTS = 659
ASSISTANT_ECHO_LOOKBACK = 3
LOCAL_INPUT_CHARACTER_CEILING = 14_000
LOCAL_REPAIR_MINIMUM_HEADROOM = 2_000
BACKUP_ROOT = Path("/var/backups/myuna/p07-stale-assistant-echo-v1")
RECEIPT_ROOT = Path("/var/lib/myuna/core-release-selector/p07-stale-assistant-echo-v1")
RECEIPT = RECEIPT_ROOT / f"{TARGET_RELEASE}.json"
SCHEMA = "myuna.p07-stale-assistant-echo-activation.v1"
ACTIVE_STATUS = "ACTIVE_WAITING_OWNER_ORGANIC_CONTINUITY_E2E_V5"


modules = []
module = previous
while module not in modules:
    modules.append(module)
    if not hasattr(module, "previous"):
        break
    module = module.previous
if base not in modules:
    modules.append(base)
for module in modules:
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
_validate_compact_candidate = previous.validate_candidate
_run_candidate_test = previous._run_candidate_test


def artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07-stale-assistant-echo-v1",
            "status": "offline_tested_not_installed",
            "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
            "tree_sha256": TARGET_RELEASE,
            "source_commit": TARGET_COMMIT,
            "file_count": TARGET_FILE_COUNT,
            "verification": {
                "core_tests": TARGET_CORE_TESTS,
                "private_content_present": False,
                "provider_calls": 0,
                "recent_assistant_echo_guard": "local-bounded-lookback-v2",
                "assistant_echo_lookback": ASSISTANT_ECHO_LOOKBACK,
                "exact_repeated_question_exempt": True,
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
                "recent_assistant_echo_guard": "bounded-last-3-assistant-v2",
                "exact_repeated_question_exempt": True,
                "single_echo_repair": "unchanged-compact-dialogue-only-v1",
                "local_repair_projection": "unchanged-system-plus-current-exchange-v1",
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


def validate_candidate(candidate: Path) -> None:
    _validate_compact_candidate(candidate)
    resolved = candidate.resolve()
    source_path = resolved / "src/myuna_core/conversation.py"
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ActivationRejected("candidate_stale_echo_source_unavailable") from exc
    required = (
        "_RECENT_ASSISTANT_ECHO_LOOKBACK = 3",
        "assistant_count > _RECENT_ASSISTANT_ECHO_LOOKBACK",
        "final_user_normalized == prior_user_normalized",
        "repeated or closely paraphrased a recent assistant reply",
    )
    base.require(
        all(item in source for item in required),
        "candidate_stale_echo_wiring_rejected",
    )
    _run_candidate_test(
        candidate,
        "test_conversation.py",
        "test_local_stale_assistant_echo_after_fallback_is_repaired",
    )
    _run_candidate_test(
        candidate,
        "test_conversation.py",
        "test_local_stale_assistant_echo_allows_exact_question_repeat",
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
            "recent_assistant_echo_guard": "local-bounded-lookback-v2",
            "assistant_echo_lookback": ASSISTANT_ECHO_LOOKBACK,
            "exact_repeated_question_exempt": True,
            "single_echo_repair": "unchanged-compact-dialogue-only-v1",
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
