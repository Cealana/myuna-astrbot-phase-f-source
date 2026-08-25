#!/usr/bin/env python3
"""Select the exact P07 Core release with isolated Profile factual context."""

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
    "_p07_core_profile_context_isolation_previous",
    _PREVIOUS_PATH,
)
if _PREVIOUS_SPEC is None or _PREVIOUS_SPEC.loader is None:
    raise RuntimeError("previous_activator_unavailable")
previous = importlib.util.module_from_spec(_PREVIOUS_SPEC)
_PREVIOUS_SPEC.loader.exec_module(previous)
base = previous.base


CURRENT_RELEASE = "4627f55ac6538deac23fe91f61650663e5063ec09521fc2eb11ac56e319fc2ba"
CURRENT_BINDING_SHA256 = "8e8610b23ab1b9669cfedbe3eaad55c17faecd55178ad9caea729f3748128e13"
CURRENT_SELECTOR_SHA256 = "bfec123f06e5afc69bc9c5774c1a7a585c9459c4f8f9ebd3803a78e264ca18cd"
TARGET_RELEASE = "678e07db0eb491b39650eca987ee58c02fb284ba03211a209b43ba9e50269800"
TARGET_COMMIT = "3d02317682d9e76aa91cfc29de571726d8faccfe"
TARGET_FILE_COUNT = 238
TARGET_CORE_TESTS = 526
LOCAL_MAX_OUTPUT_TOKENS = 192
BACKUP_ROOT = Path("/var/backups/myuna/p07-core-profile-context-isolation-v1")
RECEIPT_ROOT = Path(
    "/var/lib/myuna/core-release-selector/p07-profile-context-isolation"
)
RECEIPT = RECEIPT_ROOT / "LAST_ACTIVATION.json"
SCHEMA = "myuna.p07-core-profile-context-isolation-activation.v1"
ACTIVE_STATUS = "ACTIVE_WAITING_OWNER_PROFILE_ISOLATION_RETRY"


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
            "schema": "myuna.core-source-artifact.p07-profile-context-isolation-v1",
            "status": "offline_tested_not_installed",
            "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
            "tree_sha256": TARGET_RELEASE,
            "source_commit": TARGET_COMMIT,
            "file_count": TARGET_FILE_COUNT,
            "verification": {
                "core_tests": TARGET_CORE_TESTS,
                "private_content_present": False,
                "provider_calls": 0,
                "local_input_projection": "owner-profile-bounded-current-turn-v1",
                "local_definition_projection": "exact-core-sections-v1",
                "local_max_output_tokens": LOCAL_MAX_OUTPUT_TOKENS,
                "owner_profile_factual_grounding": "high-priority-runtime-control-v1",
                "owner_profile_context_isolation": "selected-profile-bounded-v1",
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
                "owner_profile_context_isolation": (
                    "system-current-turn-and-bounded-repair-v1"
                ),
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
    resolved = candidate.resolve()
    conversation = resolved / "src/myuna_core/conversation.py"
    local_provider = resolved / "src/myuna_core/providers/local.py"
    request_contract = resolved / "src/myuna_core/providers/base.py"
    try:
        source = conversation.read_text(encoding="utf-8")
        local_source = local_provider.read_text(encoding="utf-8")
        contract_source = request_contract.read_text(encoding="utf-8")
    except OSError as exc:
        raise ActivationRejected("candidate_isolation_source_unavailable") from exc
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
    base.require(
        source.count('"owner_profile_bounded_v1"') == 3,
        "candidate_isolation_wiring_rejected",
    )
    base.require(
        local_source.count('name="owner_profile_bounded_v1"') == 1
        and contract_source.count(
            'InputProjection = Literal["default", "owner_profile_bounded_v1"]'
        )
        == 1,
        "candidate_isolation_contract_rejected",
    )
    probe = (
        "from myuna_core.providers import ModelRequest;"
        "from myuna_core.providers.local import project_local_request;"
        "m=({'role':'system','content':'profile'},"
        "{'role':'user','content':'old'},"
        "{'role':'assistant','content':'WRONG'},"
        "{'role':'user','content':'current'});"
        "p=project_local_request(ModelRequest(request_id='profile-probe',"
        "messages=m,max_output_tokens=192,input_projection="
        "'owner_profile_bounded_v1',input_projection_tail_messages=1));"
        "assert p.name=='owner_profile_bounded_v1';"
        "assert tuple(x['content'] for x in p.request.messages)==('profile','current');"
        "assert p.omitted_message_count==2;"
        "assert 'WRONG' not in repr(p.request.messages)"
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
    base.require(
        completed.returncode == 0,
        "candidate_isolation_probe_rejected",
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
            "owner_profile_context_isolation": "selected-profile-bounded-v1",
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
