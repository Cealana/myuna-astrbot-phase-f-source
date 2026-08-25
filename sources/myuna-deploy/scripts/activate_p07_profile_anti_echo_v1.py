#!/usr/bin/env python3
"""Activate the P07 Core release with a bounded local recent-turn echo guard."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess


_PREVIOUS_PATH = Path(__file__).with_name(
    "activate_p07_profile_incidental_continuity_v1.py"
)
_PREVIOUS_SPEC = importlib.util.spec_from_file_location(
    "_p07_profile_anti_echo_previous",
    _PREVIOUS_PATH,
)
if _PREVIOUS_SPEC is None or _PREVIOUS_SPEC.loader is None:
    raise RuntimeError("previous_activator_unavailable")
previous = importlib.util.module_from_spec(_PREVIOUS_SPEC)
_PREVIOUS_SPEC.loader.exec_module(previous)
base = previous.base


CURRENT_RELEASE = "6650de29d86123d2f43191e54af67781f7b4b5c8b4f8e1cfded639b050a3885f"
CURRENT_BINDING_SHA256 = (
    "6e54bde664538e1d4aa8a1940bafee02ac0f2e62cc697d0a4a3a9558f08284f0"
)
CURRENT_SELECTOR_SHA256 = (
    "e03eb64dadfb9fe3758c8ee4bb20bd6da054de829aacf2cd6dd80b8bf6c15f1b"
)
TARGET_RELEASE = "5398d648877b32a4061b584f48814b6d1b2f8d8039c2748c006fb43ab2285d0c"
TARGET_COMMIT = "11043c904332568e2dfee04c49376dcdbcac90c9"
TARGET_FILE_COUNT = 273
TARGET_CORE_TESTS = 654
BACKUP_ROOT = Path("/var/backups/myuna/p07-profile-anti-echo-v1")
RECEIPT_ROOT = Path("/var/lib/myuna/core-release-selector/p07-profile-anti-echo-v1")
RECEIPT = RECEIPT_ROOT / f"{TARGET_RELEASE}.json"
SCHEMA = "myuna.p07-profile-anti-echo-activation.v1"
ACTIVE_STATUS = "ACTIVE_WAITING_OWNER_ORGANIC_CONTINUITY_E2E_V2"


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
_validate_continuity_candidate = previous.validate_candidate


def artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07-profile-anti-echo-v1",
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
                "minimum_normalized_characters": 32,
                "similarity_threshold": "0.90",
                "explicit_repeat_or_quote_exempt": True,
                "short_reply_exempt": True,
                "direct_profile_projection_exempt": True,
                "incidental_profile_enrichment": "recent-complete-turns-v1",
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
                "recent_assistant_echo_guard": "local-near-duplicate-repair-v1",
                "explicit_repeat_or_quote": "exempt",
                "short_reply": "exempt",
                "direct_profile_projection": "strict-current-turn-v1-exempt",
                "incidental_profile_enrichment": "recent-complete-turns-v1",
                "identity_guard": "unchanged",
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
    _validate_continuity_candidate(candidate)
    resolved = candidate.resolve()
    source_path = resolved / "src/myuna_core/conversation.py"
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ActivationRejected("candidate_anti_echo_source_unavailable") from exc
    required = (
        "_recent_assistant_echo_violations",
        "recent_assistant_echo_without_continuity",
        "_RECENT_ASSISTANT_ECHO_MIN_NORMALIZED_CHARACTERS",
        "_RECENT_ASSISTANT_ECHO_SIMILARITY_THRESHOLD",
    )
    base.require(
        all(item in source for item in required),
        "candidate_anti_echo_wiring_rejected",
    )
    probe = r'''
from myuna_core.conversation import (
    ConversationInput,
    _recent_assistant_echo_violations,
)

prior = (
    "\u6211\u4f1a\u5148\u8ba4\u771f\u601d\u8003\u4f60\u7684\u60f3\u6cd5\uff0c"
    "\u518d\u6162\u6162\u5206\u4eab\u5206\u6790\uff0c"
    "\u4e5f\u613f\u610f\u503e\u542c\u4f60\u63a5\u4e0b\u6765\u60f3\u8bf4\u7684\u5185\u5bb9"
)
ordinary = ConversationInput(
    messages=(
        {"role": "user", "content": "earlier"},
        {"role": "assistant", "content": prior},
        {"role": "user", "content": "\u55e8\uff0c\u4f60\u73b0\u5728\u600e\u4e48\u6837\uff1f"},
    ),
    mode="myuna",
    task_class="chat",
    risk_level="low",
    high_quality=False,
    synthetic_memory=False,
)
echoed = "\u55ef\u2026\u2026" + prior
assert _recent_assistant_echo_violations(echoed, ordinary, enabled=True) == [
    "recent_assistant_echo_without_continuity"
]
assert _recent_assistant_echo_violations(echoed, ordinary, enabled=False) == []

repeat = ConversationInput(
    messages=(
        ordinary.messages[0],
        ordinary.messages[1],
        {"role": "user", "content": "\u8bf7\u539f\u6837\u91cd\u590d\u4e00\u904d"},
    ),
    mode="myuna",
    task_class="chat",
    risk_level="low",
    high_quality=False,
    synthetic_memory=False,
)
assert _recent_assistant_echo_violations(prior, repeat, enabled=True) == []
assert _recent_assistant_echo_violations("\u5728\u5462", ordinary, enabled=True) == []
assert _recent_assistant_echo_violations(
    "\u6211\u60f3\u5148\u68b3\u7406\u9650\u5236\uff0c"
    "\u518d\u7ed9\u4f60\u53ef\u6bd4\u8f83\u7684\u8def\u5f84",
    ordinary,
    enabled=True,
) == []
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
    base.require(completed.returncode == 0, "candidate_anti_echo_probe_rejected")


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
            "recent_assistant_echo_guard": "local-near-duplicate-repair-v1",
            "direct_profile_projection_changed": False,
            "incidental_profile_enrichment": "recent-complete-turns-v1",
            "identity_guard_changed": False,
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
