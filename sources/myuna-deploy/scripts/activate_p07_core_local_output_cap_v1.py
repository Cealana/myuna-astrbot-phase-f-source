#!/usr/bin/env python3
"""Select the exact P07 Core release with a local-only output cap."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess


_BASE_PATH = Path(__file__).with_name("activate_p07_core_local_sections_v1.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "_p07_core_local_output_cap_base",
    _BASE_PATH,
)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("base_activator_unavailable")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)


CURRENT_RELEASE = "75cfa2dbe9f476a110f52ee0d26a994bbb6548ab06122c4f0c4fe1343aaab5cf"
CURRENT_BINDING_SHA256 = "102d6ab7d4649dd0a494ee2754b5c2775c074b2d9e7a4e13937fb8e252e155b5"
CURRENT_SELECTOR_SHA256 = "055153b8513edb86935f5f8db8ace3fac70a9d6165c7792a4e40f7dc66ad1685"
TARGET_RELEASE = "88ab37f31eabb3af4978b65acfb202abe33214d219beddd9f617087069907b82"
TARGET_COMMIT = "1581fa683b299fefda38a0e1b65bb8630b1def2a"
TARGET_FILE_COUNT = 238
TARGET_CORE_TESTS = 522
LOCAL_MAX_OUTPUT_TOKENS = 192
BACKUP_ROOT = Path("/var/backups/myuna/p07-core-local-output-cap-v1")
RECEIPT_ROOT = Path("/var/lib/myuna/core-release-selector/p07-local-output-cap")
RECEIPT = RECEIPT_ROOT / "LAST_ACTIVATION.json"
SCHEMA = "myuna.p07-core-local-output-cap-activation.v1"


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
    setattr(base, name, value)


ActivationRejected = base.ActivationRejected
canonical_json_bytes = base.canonical_json_bytes
digest_bytes = base.digest_bytes
digest_file = base.digest_file
_validate_sections_candidate = base.validate_candidate


def artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07-local-output-cap-v1",
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
                "local_provider": "active",
            },
            "target": {
                "core_release": TARGET_RELEASE,
                "core_source_commit": TARGET_COMMIT,
                "local_input_limit_characters": 14_000,
                "local_definition_projection": "exact-approved-skill-sections-v1",
                "local_max_output_tokens": LOCAL_MAX_OUTPUT_TOKENS,
                "local_thinking": "disabled-fail-closed",
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
                "health_endpoints_forbidden": True,
                "provider_probe_forbidden": True,
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
    _validate_sections_candidate(candidate)
    resolved = candidate.resolve()
    probe = (
        "from myuna_core.conversation import ConversationError,_model_output_token_limit;"
        "assert _model_output_token_limit(provider='local',thinking='disabled')==192;"
        "assert _model_output_token_limit(provider='deepseek',thinking='disabled')==768;"
        "assert _model_output_token_limit(provider='deepseek',thinking='enabled')==4096;"
        "\ntry:\n _model_output_token_limit(provider='local',thinking='enabled')"
        "\nexcept ConversationError:\n pass"
        "\nelse:\n raise AssertionError('local thinking accepted')"
    )
    completed = subprocess.run(
        ["/usr/bin/python3", "-B", "-c", probe],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": f"{resolved}/src",
        },
    )
    base.require(completed.returncode == 0, "candidate_output_cap_probe_rejected")


def write_receipt(root: Path, plan: bytes) -> None:
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True)
    base.os.chmod(RECEIPT_ROOT, 0o700)
    payload = canonical_json_bytes(
        {
            "schema": SCHEMA,
            "status": "ACTIVE_WAITING_OWNER_TELEGRAM_E2E_RETRY",
            "plan_sha256": digest_bytes(plan),
            "backup": root.name,
            "core_release": TARGET_RELEASE,
            "core_source_commit": TARGET_COMMIT,
            "core_tests": TARGET_CORE_TESTS,
            "local_input_projection": "recent-complete-turns-v1",
            "local_definition_projection": "exact-core-sections-v1",
            "local_max_output_tokens": LOCAL_MAX_OUTPUT_TOKENS,
            "deepseek_output_limits_changed": False,
            "definition_source_mutated": False,
            "session_store_changed": False,
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
activate = base.activate


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
