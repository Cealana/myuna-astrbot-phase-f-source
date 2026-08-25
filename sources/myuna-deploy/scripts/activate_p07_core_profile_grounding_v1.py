#!/usr/bin/env python3
"""Select the exact P07 Core release with grounded Profile factual replies."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess


_PREVIOUS_PATH = Path(__file__).with_name(
    "activate_p07_core_local_output_cap_v1.py"
)
_PREVIOUS_SPEC = importlib.util.spec_from_file_location(
    "_p07_core_profile_grounding_previous",
    _PREVIOUS_PATH,
)
if _PREVIOUS_SPEC is None or _PREVIOUS_SPEC.loader is None:
    raise RuntimeError("previous_activator_unavailable")
previous = importlib.util.module_from_spec(_PREVIOUS_SPEC)
_PREVIOUS_SPEC.loader.exec_module(previous)
base = previous.base


CURRENT_RELEASE = "88ab37f31eabb3af4978b65acfb202abe33214d219beddd9f617087069907b82"
CURRENT_BINDING_SHA256 = "55fdf822e2d1e19e56e5c6d44237dfac84631c8e5be6f215cd16c6d9469bc2d8"
CURRENT_SELECTOR_SHA256 = "fb2338faff8ef9d31c06c4792e04c706f73cfeb532afc807675b3966ff749e4b"
TARGET_RELEASE = "4627f55ac6538deac23fe91f61650663e5063ec09521fc2eb11ac56e319fc2ba"
TARGET_COMMIT = "f93f2961aacc955fc16d2384a7e9f8779218d61e"
TARGET_FILE_COUNT = 238
TARGET_CORE_TESTS = 522
LOCAL_MAX_OUTPUT_TOKENS = 192
BACKUP_ROOT = Path("/var/backups/myuna/p07-core-profile-grounding-v1")
RECEIPT_ROOT = Path("/var/lib/myuna/core-release-selector/p07-profile-grounding")
RECEIPT = RECEIPT_ROOT / "LAST_ACTIVATION.json"
SCHEMA = "myuna.p07-core-profile-grounding-activation.v1"
ACTIVE_STATUS = "ACTIVE_WAITING_OWNER_PROFILE_GROUNDING_RETRY"


for module in (previous, base):
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
_validate_output_cap_candidate = previous.validate_candidate


def artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07-profile-grounding-v1",
            "status": "offline_tested_not_installed",
            "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
            "tree_sha256": TARGET_RELEASE,
            "source_commit": TARGET_COMMIT,
            "file_count": TARGET_FILE_COUNT,
            "verification": {
                "core_tests": TARGET_CORE_TESTS,
                "private_content_present": False,
                "provider_calls": 0,
                "local_input_projection": "recent-complete-turns-v1",
                "local_definition_projection": "exact-core-sections-v1",
                "local_max_output_tokens": LOCAL_MAX_OUTPUT_TOKENS,
                "owner_profile_factual_grounding": "high-priority-runtime-control-v1",
                "owner_channel_prompt": "authenticated-owner-private-generic-v1",
                "synthetic_model_probe": "passed-ascii-order-and-no-generic-fill",
                "deepseek_output_limits_changed": False,
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
                "local_input_limit_characters": 14_000,
                "local_definition_projection": "exact-approved-skill-sections-v1",
                "local_max_output_tokens": LOCAL_MAX_OUTPUT_TOKENS,
                "owner_profile_factual_grounding": "selected-profile-authoritative-v1",
                "owner_channel_prompt": "authenticated-owner-private-generic-v1",
                "deepseek_output_limits": "unchanged-768-4096",
                "definition_source_mutated": False,
                "session_store": "unchanged-128-message-window",
            },
            "live_scope": {
                "core_restart_max": 1,
                "gateway_restarts": 0,
                "gateway_quiesce_restore": [
                    "qq-owner-private",
                    "telegram-owner-private",
                ],
                "local_provider_restart": 0,
                "health_endpoints_forbidden": True,
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
    _validate_output_cap_candidate(candidate)
    conversation = candidate.resolve() / "src/myuna_core/conversation.py"
    try:
        source = conversation.read_text(encoding="utf-8")
    except OSError as exc:
        raise ActivationRejected("candidate_grounding_source_unavailable") from exc
    required = (
        "use the selected Profile and explicit Owner-authored text",
        "preserving every stated order, priority, and",
        "generic advice, ",
        "typical considerations, stereotypes",
        "authenticated Owner-private text channel",
    )
    base.require(
        all(source.count(item) == 1 for item in required),
        "candidate_grounding_rejected",
    )
    base.require(
        "authenticated private QQ text channel" not in source,
        "candidate_channel_prompt_rejected",
    )


def write_receipt(root: Path, plan: bytes) -> None:
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True)
    base.os.chmod(RECEIPT_ROOT, 0o700)
    payload = canonical_json_bytes(
        {
            "schema": SCHEMA,
            "status": ACTIVE_STATUS,
            "plan_sha256": digest_bytes(plan),
            "backup": root.name,
            "core_release": TARGET_RELEASE,
            "core_source_commit": TARGET_COMMIT,
            "core_tests": TARGET_CORE_TESTS,
            "local_max_output_tokens": LOCAL_MAX_OUTPUT_TOKENS,
            "owner_profile_factual_grounding": "high-priority-runtime-control-v1",
            "owner_channel_prompt": "authenticated-owner-private-generic-v1",
            "synthetic_model_probe": "passed-ascii-order-and-no-generic-fill",
            "deepseek_output_limits_changed": False,
            "definition_source_mutated": False,
            "session_store_changed": False,
            "local_provider_restarted": False,
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
