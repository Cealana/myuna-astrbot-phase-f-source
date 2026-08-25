#!/usr/bin/env python3
"""Select the P07-C Core release that preserves the authenticated writer ID."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess


_PREVIOUS_PATH = Path(__file__).with_name(
    "activate_p07c_core_write_source_v1.py"
)
_PREVIOUS_SPEC = importlib.util.spec_from_file_location(
    "_p07c_core_diary_request_id_previous",
    _PREVIOUS_PATH,
)
if _PREVIOUS_SPEC is None or _PREVIOUS_SPEC.loader is None:
    raise RuntimeError("previous_activator_unavailable")
previous = importlib.util.module_from_spec(_PREVIOUS_SPEC)
_PREVIOUS_SPEC.loader.exec_module(previous)
base = previous.base


CURRENT_RELEASE = "8b634196e48cf8eb64b196d8b021ee34f5e95481c8441767833773efd2d3abce"
CURRENT_BINDING_SHA256 = "32d8afbe66f870cc5ff8bbc3d784cc90349cf0dfb3bb23e4c5655634a2224763"
CURRENT_SELECTOR_SHA256 = "5b66af5c3edf2f72a121a759046e2c1b43d8e40125bed74e3e8c5b5362e7efa7"
TARGET_RELEASE = "afd32010f989c6964c836248a1ff6c4dc046713e92afa0a10cc98af782284a9a"
TARGET_COMMIT = "a18903a669c5d8771f5bde0857c0c8864509b628"
TARGET_FILE_COUNT = 261
TARGET_CORE_TESTS = 609
BACKUP_ROOT = Path("/var/backups/myuna/p07c-core-diary-request-id-repair-v1")
RECEIPT_ROOT = Path(
    "/var/lib/myuna/core-release-selector/"
    "p07c-core-diary-request-id-repair-v1/receipts"
)
SCHEMA = "myuna.p07c-core-diary-request-id-repair-activation.v1"
ACTIVE_STATUS = "P07C_CORE_REQUEST_ID_REPAIR_ACTIVE_WAITING_OWNER_E2E"


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
        ("SCHEMA", SCHEMA),
    ):
        setattr(module, name, value)


ActivationRejected = base.ActivationRejected
canonical_json_bytes = base.canonical_json_bytes
digest_bytes = base.digest_bytes
digest_file = base.digest_file


def artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07c-diary-request-id-repair-v1",
            "status": "offline_tested_not_installed",
            "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
            "tree_sha256": TARGET_RELEASE,
            "source_commit": TARGET_COMMIT,
            "file_count": TARGET_FILE_COUNT,
            "verification": {
                "core_tests": TARGET_CORE_TESTS,
                "focused_tests": 124,
                "private_content_present": False,
                "provider_calls": 0,
                "authenticated_request_id_preserved": True,
                "writer_request_id_equality_relaxed": False,
                "profile_content_changed": False,
                "candidate_store_changed": False,
                "legacy_namespace_written": False,
                "session_temporal_capability_double_write": False,
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
                "profile_revision": 2,
                "profile_writer": "installed-active",
            },
            "target": {
                "core_release": TARGET_RELEASE,
                "core_source_commit": TARGET_COMMIT,
                "writer_request_id": "authenticated-gateway-context-v1",
                "core_http_request_id": "retained-for-core-response-and-audit-v1",
                "writer_protocol_equality": "strict-fail-closed-v1",
                "profile_and_candidate_data": "unchanged",
                "legacy_session_p08_p10_write": "disabled",
            },
            "live_scope": {
                "core_restart_max": 1,
                "gateway_restarts": 0,
                "gateway_quiesce_restore": [
                    "qq-owner-private",
                    "telegram-owner-private",
                ],
                "profile_writer_restart": 0,
                "local_provider_restart": 0,
                "profile_reader_restart": 0,
                "model_calls_forbidden": True,
                "channel_messages_forbidden": True,
                "health_endpoints_forbidden": True,
            },
            "rollback": {
                "restore_binding_and_selector_exact_bytes": True,
                "restore_core_release": CURRENT_RELEASE,
                "retain_installed_release": True,
                "preserve_profile_candidate_session_data": True,
            },
        }
    )


def validate_candidate(candidate: Path) -> None:
    previous.validate_candidate(candidate)
    resolved = candidate.resolve()
    try:
        conversation = (resolved / "src/myuna_core/conversation.py").read_text(
            encoding="utf-8"
        )
        protocol = (
            resolved / "src/myuna_core/owner_profile/write_protocol.py"
        ).read_text(encoding="utf-8")
    except OSError as exc:
        raise ActivationRejected("candidate_request_id_source_unavailable") from exc
    base.require(
        all(
            symbol in conversation
            for symbol in (
                "write_request_id = (",
                "authenticated_context.request_id",
                "request_id=write_request_id",
            )
        ),
        "candidate_authenticated_request_id_rejected",
    )
    base.require(
        "if context.request_id != request_id:" in protocol,
        "candidate_writer_request_id_equality_rejected",
    )


def write_receipt(root: Path, plan: bytes) -> None:
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True)
    base.os.chmod(RECEIPT_ROOT.parent, 0o700)
    base.os.chmod(RECEIPT_ROOT, 0o700)
    plan_sha256 = digest_bytes(plan)
    receipt = RECEIPT_ROOT / f"{plan_sha256}.json"
    base.require(not receipt.exists(), "activation_receipt_conflict")
    payload = canonical_json_bytes(
        {
            "schema": SCHEMA,
            "status": ACTIVE_STATUS,
            "plan_sha256": plan_sha256,
            "backup": root.name,
            "core_release": TARGET_RELEASE,
            "core_source_commit": TARGET_COMMIT,
            "core_tests": TARGET_CORE_TESTS,
            "focused_tests": 124,
            "profile_writer_restarted": False,
            "profile_revision_changed": False,
            "candidate_store_changed": False,
            "provider_called": False,
            "channel_message_sent": False,
            "private_content_recorded": False,
            "raw_identity_recorded": False,
            "raw_message_recorded": False,
            "secret_recorded": False,
        }
    )
    base._atomic_write(receipt, payload, mode=0o600)
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
        result = activate(
            arguments.candidate,
            preflight_only=arguments.preflight_only,
        )
    except (ActivationRejected, OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
