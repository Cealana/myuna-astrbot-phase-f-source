#!/usr/bin/env python3
"""Select the exact P07-C Core release before enabling the Profile writer."""

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
    "_p07c_core_write_source_previous",
    _PREVIOUS_PATH,
)
if _PREVIOUS_SPEC is None or _PREVIOUS_SPEC.loader is None:
    raise RuntimeError("previous_activator_unavailable")
previous = importlib.util.module_from_spec(_PREVIOUS_SPEC)
_PREVIOUS_SPEC.loader.exec_module(previous)
base = previous.base


CURRENT_RELEASE = "e4b626ba09433e34c22f84f479abb73c9fe17337670cf4f4ff88d3b000424d60"
CURRENT_BINDING_SHA256 = "095836071d9830c8ca218abcd0b4e04ca7c1b28532ec6d0d23789115445e7c8b"
CURRENT_SELECTOR_SHA256 = "6e37634e91642e30f9eb24bd75a7d96a8e1dde2871c60d5415bb68b81d6b7cbb"
TARGET_RELEASE = "8b634196e48cf8eb64b196d8b021ee34f5e95481c8441767833773efd2d3abce"
TARGET_COMMIT = "8a1e5dd93738ae8705f5548cd6188acde0142c21"
TARGET_FILE_COUNT = 261
TARGET_CORE_TESTS = 609
BACKUP_ROOT = Path("/var/backups/myuna/p07c-core-write-source-v1")
RECEIPT_ROOT = Path(
    "/var/lib/myuna/core-release-selector/p07c-core-write-source-v1/receipts"
)
SCHEMA = "myuna.p07c-core-write-source-activation.v1"
ACTIVE_STATUS = "P07C_CORE_SOURCE_ACTIVE_WRITER_NOT_YET_ENABLED"


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
_validate_previous_candidate = previous.validate_candidate


def artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.p07c-profile-write-v1",
            "status": "offline_tested_not_installed",
            "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
            "tree_sha256": TARGET_RELEASE,
            "source_commit": TARGET_COMMIT,
            "file_count": TARGET_FILE_COUNT,
            "verification": {
                "core_tests": TARGET_CORE_TESTS,
                "private_content_present": False,
                "provider_calls": 0,
                "owner_profile_write_entrypoint": "explicit-diary-only-v1",
                "candidate_analysis_provider": "fixed-local-loopback-v1",
                "candidate_max_changes": 3,
                "candidate_source_retained": False,
                "owner_confirmation_required": True,
                "immutable_profile_publication": True,
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
                "profile_writer": "not-installed",
            },
            "target": {
                "core_release": TARGET_RELEASE,
                "core_source_commit": TARGET_COMMIT,
                "profile_writer_source": "present-but-disabled-until-separate-activation",
                "owner_profile_write_entrypoint": "authenticated-telegram-diary-only-v1",
                "candidate_analysis": "bounded-local-provider-strict-json-v1",
                "candidate_persistence": "exact-owner-confirmation-required-v1",
                "read_retrieval": "existing-qq-and-telegram-policy-preserved",
                "legacy_session_p08_p10_write": "disabled",
            },
            "live_scope": {
                "core_restart_max": 1,
                "gateway_restarts": 0,
                "gateway_quiesce_restore": [
                    "qq-owner-private",
                    "telegram-owner-private",
                ],
                "local_provider_restart": 0,
                "profile_reader_restart": 0,
                "profile_writer_install": False,
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
    _validate_previous_candidate(candidate)
    resolved = candidate.resolve()
    required_files = {
        "conversation": resolved / "src/myuna_core/conversation.py",
        "intent": resolved / "src/myuna_core/owner_profile/write_intent.py",
        "candidate": resolved / "src/myuna_core/owner_profile/write_candidate.py",
        "runtime": resolved / "src/myuna_core/owner_profile/write_runtime.py",
        "publisher": resolved / "src/myuna_core/owner_profile/write_publish.py",
        "worker": resolved / "src/myuna_core/owner_profile/write_socket_worker.py",
    }
    try:
        sources = {
            name: path.read_text(encoding="utf-8")
            for name, path in required_files.items()
        }
    except OSError as exc:
        raise ActivationRejected("candidate_write_source_unavailable") from exc
    required_symbols = {
        "conversation": (
            "owner_profile_write_runtime",
            "conversation.owner_profile_write",
        ),
        "intent": (
            "parse_benchmark_write_intent",
            "benchmark_intent_grants_profile_consent",
        ),
        "candidate": (
            "MAX_CHANGES = 3",
            "MAX_SOURCE_CHARACTERS",
            "analyze_candidate_with_local_provider",
        ),
        "runtime": (
            "OwnerProfileWriteAccessPolicy",
            "consent_memory_candidate",
            "telegram-owner-private",
        ),
        "publisher": (
            "publish_stored_profile_candidate",
            "install_active_profile_target",
        ),
        "worker": (
            "build_runtime_from_environment",
            "serve_write_connection",
        ),
    }
    base.require(
        all(
            all(symbol in sources[name] for symbol in symbols)
            for name, symbols in required_symbols.items()
        ),
        "candidate_write_wiring_rejected",
    )
    probe = (
        "from myuna_core.owner_profile.write_intent import "
        "parse_benchmark_write_intent,benchmark_intent_grants_profile_consent;"
        "assert parse_benchmark_write_intent('ordinary chat') is None;"
        "assert parse_benchmark_write_intent('/Diary archive') is None;"
        "x=parse_benchmark_write_intent('/Benchmark stable synthetic preference');"
        "assert x and x.action=='propose';"
        "assert benchmark_intent_grants_profile_consent('/Benchmark stable synthetic preference');"
        "assert not benchmark_intent_grants_profile_consent('/Diary archive');"
        "assert not benchmark_intent_grants_profile_consent('ordinary chat')"
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
    base.require(completed.returncode == 0, "candidate_write_probe_rejected")


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
            "profile_writer_installed": False,
            "profile_revision_changed": False,
            "local_provider_restarted": False,
            "profile_reader_restarted": False,
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
