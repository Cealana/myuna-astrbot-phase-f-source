#!/usr/bin/env python3
"""Activate the P07 Core release with an explicit bounded local repair projection."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess


_PREVIOUS_PATH = Path(__file__).with_name("activate_p07_profile_anti_echo_v1.py")
_PREVIOUS_SPEC = importlib.util.spec_from_file_location(
    "_p07_local_repair_bounded_previous",
    _PREVIOUS_PATH,
)
if _PREVIOUS_SPEC is None or _PREVIOUS_SPEC.loader is None:
    raise RuntimeError("previous_activator_unavailable")
previous = importlib.util.module_from_spec(_PREVIOUS_SPEC)
_PREVIOUS_SPEC.loader.exec_module(previous)
base = previous.base


CURRENT_RELEASE = "5398d648877b32a4061b584f48814b6d1b2f8d8039c2748c006fb43ab2285d0c"
CURRENT_BINDING_SHA256 = (
    "8a6b6d457e88de60a9dd1f627ca44effd11a7b3ba9d5fff60b6aced1845fb639"
)
CURRENT_SELECTOR_SHA256 = (
    "1f187605ccac02f02653579e9245e09e61fe705f37b89281a2d3bb717cfd1a75"
)
TARGET_RELEASE = "78ce7d886ed14f240fc17ca5ad29ca38cb4c2d42774edd37ce7b25a274b1f203"
TARGET_COMMIT = "9fedc3a6deda8cbf558f4bbf4940bf9fb85741dd"
TARGET_FILE_COUNT = 273
TARGET_CORE_TESTS = 656
BACKUP_ROOT = Path("/var/backups/myuna/p07-local-repair-bounded-v1")
RECEIPT_ROOT = Path(
    "/var/lib/myuna/core-release-selector/p07-local-repair-bounded-v1"
)
RECEIPT = RECEIPT_ROOT / f"{TARGET_RELEASE}.json"
SCHEMA = "myuna.p07-local-repair-bounded-activation.v1"
ACTIVE_STATUS = "ACTIVE_WAITING_OWNER_ORGANIC_CONTINUITY_E2E_V3"


for module in (previous, previous.previous, previous.previous.previous, base):
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
_validate_anti_echo_candidate = previous.validate_candidate


def _validate_context_isolation_candidate_v2(candidate: Path) -> None:
    """Preserve the isolation checks after extending InputProjection."""
    context = previous.previous.previous.previous
    context._validate_output_cap_candidate(candidate)
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
        local_source.count('"owner_profile_bounded_v1"') == 1
        and local_source.count('"local_repair_bounded_v1"') == 1
        and '"owner_profile_bounded_v1"' in contract_source
        and '"local_repair_bounded_v1"' in contract_source,
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
        "assert tuple(x['content'] for x in p.request.messages)=="
        "('profile','current');"
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


def _validate_exact_recall_candidate_v2(candidate: Path) -> None:
    _validate_context_isolation_candidate_v2(candidate)
    resolved = candidate.resolve()
    conversation = resolved / "src/myuna_core/conversation.py"
    try:
        source = conversation.read_text(encoding="utf-8")
    except OSError as exc:
        raise ActivationRejected("candidate_exact_recall_source_unavailable") from exc
    exact_required = (
        "owner_profile_exact_recall_v1",
        "provider_call_performed",
        "raw_query_recorded",
        "raw_reply_recorded",
        "_render_owner_profile_exact_recall",
    )
    base.require(
        all(item in source for item in exact_required),
        "candidate_exact_recall_wiring_rejected",
    )
    exact_probe = (
        "from myuna_core.conversation import "
        "_owner_profile_exact_recall_requested as q,"
        "_render_owner_profile_exact_recall as r;"
        "from myuna_core.owner_profile.contracts import "
        "RetrievalResult,RetrievedProfileSection;"
        "s=lambda rank,body:RetrievedProfileSection(rank=rank,"
        "category='long_term_preference',title='synthetic',body=body,"
        "source_ref='owner-profile:synthetic:r1:s@sha256:'+'a'*64);"
        "x=RetrievalResult(state='selected',profile_revision=1,"
        "profile_sha256='a'*64,query_characters=8,"
        "sections=(s(1,'FIRST'),s(2,'UNRELATED')),context='synthetic');"
        "assert q('\\u8bf7\\u6309\\u539f\\u987a\\u5e8f\\u590d\\u8ff0"
        "\\u6211\\u7684\\u4f18\\u5148\\u7ea7');"
        "o=r(x);assert 'FIRST' in o and 'UNRELATED' not in o"
    )
    completed = subprocess.run(
        ["/usr/bin/python3", "-B", "-c", exact_probe],
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
        "candidate_exact_recall_probe_rejected",
    )


def artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07-local-repair-bounded-v1",
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
                "local_repair_projection": "system-plus-current-exchange-v1",
                "local_repair_projected_message_count": 4,
                "local_input_character_ceiling": 14_000,
                "telegram_core_timeout_seconds_unchanged": 165,
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
                "local_repair_projection": "system-plus-current-exchange-v1",
                "local_repair_tail_messages": 3,
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
                "gateway_timeout_change": False,
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
    incidental = previous.previous
    inherited_validator = incidental._validate_exact_recall_candidate
    incidental._validate_exact_recall_candidate = _validate_exact_recall_candidate_v2
    try:
        _validate_anti_echo_candidate(candidate)
    finally:
        incidental._validate_exact_recall_candidate = inherited_validator
    resolved = candidate.resolve()
    paths = (
        resolved / "src/myuna_core/conversation.py",
        resolved / "src/myuna_core/providers/base.py",
        resolved / "src/myuna_core/providers/local.py",
    )
    try:
        sources = tuple(path.read_text(encoding="utf-8") for path in paths)
    except OSError as exc:
        raise ActivationRejected("candidate_local_repair_source_unavailable") from exc
    base.require(
        all("local_repair_bounded_v1" in source for source in sources),
        "candidate_local_repair_wiring_rejected",
    )
    probe = r'''
from myuna_core.providers import ModelRequest
from myuna_core.providers.local import (
    LOCAL_MAX_INPUT_CHARACTERS,
    project_local_request,
)

messages = [{"role": "system", "content": "s" * 5_000}]
messages.extend(
    item
    for index in range(63)
    for item in (
        {"role": "user", "content": f"old-user-{index}-" + "u" * 80},
        {"role": "assistant", "content": f"old-assistant-{index}-" + "a" * 80},
    )
)
messages.extend((
    {"role": "user", "content": "current ordinary question"},
    {"role": "assistant", "content": "rejected echo candidate"},
    {"role": "user", "content": "bounded repair instruction"},
))
assert sum(len(item["content"]) for item in messages) > LOCAL_MAX_INPUT_CHARACTERS
request = ModelRequest(
    request_id="local-repair-bounded-probe",
    messages=tuple(messages),
    max_output_tokens=192,
    model="myuna-local-owner-v1",
    input_projection="local_repair_bounded_v1",
    input_projection_tail_messages=3,
    route_reason="normal_chat_repair",
)
projection = project_local_request(request)
assert projection.name == "local_repair_bounded_v1"
assert len(projection.request.messages) == 4
assert projection.request.messages == (messages[0], *messages[-3:])
assert sum(
    len(item["content"]) for item in projection.request.messages
) <= LOCAL_MAX_INPUT_CHARACTERS
assert projection.omitted_message_count == len(messages) - 4
'''
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
        "candidate_local_repair_probe_rejected",
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
            "local_repair_projection": "system-plus-current-exchange-v1",
            "local_repair_projected_message_count": 4,
            "gateway_timeout_changed": False,
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
