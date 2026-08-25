#!/usr/bin/env python3
"""Activate the P07 Core release that preserves incidental chat continuity."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess


_PREVIOUS_PATH = Path(__file__).with_name(
    "activate_p07_core_profile_exact_recall_v1.py"
)
_PREVIOUS_SPEC = importlib.util.spec_from_file_location(
    "_p07_profile_incidental_continuity_previous",
    _PREVIOUS_PATH,
)
if _PREVIOUS_SPEC is None or _PREVIOUS_SPEC.loader is None:
    raise RuntimeError("previous_activator_unavailable")
previous = importlib.util.module_from_spec(_PREVIOUS_SPEC)
_PREVIOUS_SPEC.loader.exec_module(previous)
base = previous.base


CURRENT_RELEASE = "91735394aea8c705c26b001475a0f97b9dd7286e69ef65e3dbeb5f3f0609989d"
CURRENT_BINDING_SHA256 = (
    "a43d7a4f42a27b73cc2c05197df55159d5a2a0d6f69d49e8bbb219dcc084c680"
)
CURRENT_SELECTOR_SHA256 = (
    "6f7597032161c7c6e7bc99f4395fc787fc592505f54387df8895136cca1d4ec2"
)
TARGET_RELEASE = "6650de29d86123d2f43191e54af67781f7b4b5c8b4f8e1cfded639b050a3885f"
TARGET_COMMIT = "559d8b07703eb61fe2a95514fc36e5089d9ac618"
TARGET_FILE_COUNT = 273
TARGET_CORE_TESTS = 647
BACKUP_ROOT = Path("/var/backups/myuna/p07-profile-incidental-continuity-v1")
RECEIPT_ROOT = Path(
    "/var/lib/myuna/core-release-selector/p07-profile-incidental-continuity-v1"
)
RECEIPT = RECEIPT_ROOT / f"{TARGET_RELEASE}.json"
SCHEMA = "myuna.p07-profile-incidental-continuity-activation.v1"
ACTIVE_STATUS = "ACTIVE_WAITING_OWNER_ORGANIC_CONTINUITY_E2E"


for module in (previous, previous.previous, base):
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
_validate_exact_recall_candidate = previous.validate_candidate


def artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07-incidental-continuity-v1",
            "status": "offline_tested_not_installed",
            "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
            "tree_sha256": TARGET_RELEASE,
            "source_commit": TARGET_COMMIT,
            "file_count": TARGET_FILE_COUNT,
            "verification": {
                "core_tests": TARGET_CORE_TESTS,
                "private_content_present": False,
                "provider_calls": 0,
                "direct_profile_query_projection": "strict-current-turn-v1",
                "incidental_profile_enrichment": "recent-complete-turns-v1",
                "identity_example_scope": "explicit-identity-query-only-v1",
                "unrequested_identity_reply_guard": "repair-then-fallback-v1",
                "owner_profile_exact_recall": "top-ranked-section-deterministic-v1",
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
                "direct_profile_query_projection": "strict-current-turn-v1",
                "incidental_profile_enrichment": "recent-complete-turns-v1",
                "identity_example_scope": "explicit-identity-query-only-v1",
                "unrequested_identity_reply_guard": "repair-then-fallback-v1",
                "owner_profile_exact_recall": (
                    "ordered-recall-top-ranked-section-deterministic-v1"
                ),
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
    _validate_exact_recall_candidate(candidate)
    resolved = candidate.resolve()
    source_path = resolved / "src/myuna_core/conversation.py"
    local_source_path = resolved / "src/myuna_core/providers/local.py"
    try:
        source = source_path.read_text(encoding="utf-8")
        local_source = local_source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ActivationRejected("candidate_continuity_source_unavailable") from exc
    required = (
        "strict_owner_profile_projection",
        "_owner_profile_direct_factual_query_requested",
        "include_identity_answers",
        "unrequested_identity_reply",
    )
    base.require(
        all(item in source for item in required),
        "candidate_continuity_wiring_rejected",
    )
    base.require(
        "local_recent_complete_turns_v1" in local_source,
        "candidate_recent_projection_rejected",
    )
    probe = r'''
from myuna_core.conversation import (
    ConversationInput,
    _identity_answer_requested,
    _owner_profile_direct_factual_query_requested,
    _project_local_definition_entrypoint,
    _unrequested_identity_reply_violations,
)
from myuna_core.persona_routing import PersonaRoute
from myuna_core.providers import ModelRequest
from myuna_core.providers.local import project_local_request

incident = (
    "\u6211\u548c\u670b\u53cb\u5728\u5916\u9762\u73a9\uff0c"
    "\u521a\u770b\u5b8c\u6d3b\u52a8\uff0c\u73b0\u5728\u4f11\u606f\u3002"
)
direct = "\u6211\u505a\u9879\u76ee\u51b3\u7b56\u65f6\u4f18\u5148\u8003\u8651\u4ec0\u4e48\uff1f"
assert not _owner_profile_direct_factual_query_requested(incident)
assert _owner_profile_direct_factual_query_requested(direct)

messages = [{"role": "system", "content": "s" * 9_000}]
messages.extend(
    item
    for index in range(55)
    for item in (
        {"role": "user", "content": f"old-user-{index}-" + "u" * 60},
        {"role": "assistant", "content": f"old-assistant-{index}-" + "a" * 60},
    )
)
messages.extend((
    {"role": "user", "content": "recent-user"},
    {"role": "assistant", "content": "recent-assistant"},
    {"role": "user", "content": incident},
))
ordinary = project_local_request(ModelRequest(
    request_id="incidental",
    messages=tuple(messages),
    max_output_tokens=192,
    model="myuna-local-owner-v1",
))
assert ordinary.name == "local_recent_complete_turns_v1"
assert tuple(item["content"] for item in ordinary.request.messages[-3:]) == (
    "recent-user", "recent-assistant", incident,
)

strict_messages = (
    {"role": "system", "content": "profile"},
    {"role": "user", "content": "old"},
    {"role": "assistant", "content": "WRONG"},
    {"role": "user", "content": direct},
)
strict = project_local_request(ModelRequest(
    request_id="direct",
    messages=strict_messages,
    max_output_tokens=192,
    model="myuna-local-owner-v1",
    input_projection="owner_profile_bounded_v1",
    input_projection_tail_messages=1,
))
assert "WRONG" not in repr(strict.request.messages)

document = (
    "# Myuna Skill\nVersion: synthetic\n\n"
    "## 3. Core identity\ncore\n\n"
    "## 4. Non-negotiable hard rules\nhard\n\n"
    "## 5. Default Myuna voice and style parameters\nvoice\n\n"
    "## 6. First meeting and identity answers\nFIRST_EXAMPLE\n"
)
ordinary_definition = _project_local_definition_entrypoint(
    document,
    persona_route=PersonaRoute.MYUNA,
    command_name=None,
    include_identity_answers=False,
)
identity_definition = _project_local_definition_entrypoint(
    document,
    persona_route=PersonaRoute.MYUNA,
    command_name=None,
    include_identity_answers=True,
)
assert "FIRST_EXAMPLE" not in ordinary_definition
assert "FIRST_EXAMPLE" in identity_definition
assert _identity_answer_requested("Who are you?")

request = ConversationInput(
    messages=(
        {"role": "user", "content": "earlier"},
        {"role": "assistant", "content": "earlier answer"},
        {"role": "user", "content": incident},
    ),
    mode="myuna",
    task_class="chat",
    risk_level="low",
    high_quality=False,
    synthetic_memory=False,
)
assert _unrequested_identity_reply_violations(
    "Hi\uff0c\u6211\u662f Myuna", request
) == ["unrequested_identity_reply"]
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
        "candidate_continuity_probe_rejected",
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
            "direct_profile_query_projection": "strict-current-turn-v1",
            "incidental_profile_enrichment": "recent-complete-turns-v1",
            "identity_example_scope": "explicit-identity-query-only-v1",
            "unrequested_identity_reply_guard": "repair-then-fallback-v1",
            "owner_profile_exact_recall": "top-ranked-section-deterministic-v1",
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
