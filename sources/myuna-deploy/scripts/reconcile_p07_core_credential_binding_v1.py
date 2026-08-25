#!/usr/bin/env python3
"""One-attempt, byte-exact P07 credential declaration reconciliation."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess

from activate_p07_hybrid_external_generation_v1 import (
    atomic_write,
    canonical,
    digest_bytes,
    digest_file,
    systemctl,
)
from p07_credential_binding import (
    CredentialBindingRejected,
    canonical_hybrid_gate,
    verify_effective_credential,
    verify_reconcilable_duplicate,
    verify_strict_binding,
)


SCHEMA = "myuna.p07-core-credential-binding-reconciliation.v1"
CORE_SERVICE = "myuna-core@qq.service"
DROPIN_ROOT = Path("/etc/systemd/system/myuna-core@qq.service.d")
CANONICAL_DROPIN = "credentials.conf"
REDUNDANT_DROPIN = "zzzzzzzzz-p07-hybrid-external-v1.conf"
REDUNDANT_PATH = DROPIN_ROOT / REDUNDANT_DROPIN
EXPECTED_SOURCE = Path("/etc/myuna/secrets/deepseek-api-key")
EFFECTIVE_CREDENTIAL = Path(f"/run/credentials/{CORE_SERVICE}/deepseek_api_key")
BACKUP_ROOT = Path("/var/backups/myuna/p07-core-credential-binding-v1")
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07-core-credential-binding-v1")


class ReconciliationRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ReconciliationRejected(code)


def inspect_prestate() -> dict[str, object]:
    duplicate = verify_reconcilable_duplicate(
        DROPIN_ROOT,
        canonical_dropin=CANONICAL_DROPIN,
        redundant_dropin=REDUNDANT_DROPIN,
        expected_source=EXPECTED_SOURCE,
    )
    effective = verify_effective_credential(EFFECTIVE_CREDENTIAL)
    metadata = REDUNDANT_PATH.lstat()
    require(
        metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o644,
        "credential_redundant_permission_rejected",
    )
    return {
        "binding": duplicate,
        "effective_credential": effective,
        "redundant_dropin_uid": metadata.st_uid,
    }


def build_plan(prestate: dict[str, object]) -> bytes:
    return canonical(
        {
            "boundaries": {
                "credential_category_changed": False,
                "credential_source_changed": False,
                "credential_value_read_or_written": False,
                "model_provider_or_channel_called": False,
                "service_restart": False,
            },
            "executor_sha256": digest_file(Path(__file__).resolve()),
            "prestate": prestate,
            "rollback": {
                "daemon_reload": True,
                "exact_redundant_dropin_bytes": True,
            },
            "schema": SCHEMA,
            "status": "owner_authority_required_before_apply",
            "target": {
                "canonical_declaration_count": 1,
                "canonical_dropin": CANONICAL_DROPIN,
                "redundant_dropin_sha256": digest_bytes(canonical_hybrid_gate()),
            },
        }
    )


def backup(plan: bytes, original: bytes) -> Path:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    root = BACKUP_ROOT / digest_bytes(plan)
    require(not root.exists(), "reconciliation_attempt_already_exists")
    root.mkdir(mode=0o700)
    atomic_write(root / "PLAN.json", plan, mode=0o600)
    atomic_write(root / "REDUNDANT_DROPIN", original, mode=0o600)
    return root


def verify_target() -> dict[str, object]:
    strict = verify_strict_binding(
        DROPIN_ROOT,
        canonical_dropin=CANONICAL_DROPIN,
        expected_source=EXPECTED_SOURCE,
    )
    require(
        REDUNDANT_PATH.read_bytes() == canonical_hybrid_gate(),
        "credential_target_dropin_rejected",
    )
    effective = verify_effective_credential(EFFECTIVE_CREDENTIAL)
    return {
        "declaration_count": strict["declaration_count"],
        "effective_credential_metadata": effective,
        "redundant_dropin_sha256": digest_file(REDUNDANT_PATH),
    }


def restore(original: bytes, prestate: dict[str, object]) -> None:
    binding = prestate["binding"]
    require(isinstance(binding, dict), "credential_prestate_rejected")
    mode = binding.get("redundant_dropin_mode")
    gid = binding.get("redundant_dropin_gid")
    require(isinstance(mode, int) and isinstance(gid, int), "credential_prestate_rejected")
    atomic_write(REDUNDANT_PATH, original, mode=mode, gid=gid)
    systemctl("daemon-reload")
    restored = inspect_prestate()
    restored_binding = restored["binding"]
    require(
        isinstance(restored_binding, dict)
        and restored_binding.get("redundant_dropin_sha256")
        == binding.get("redundant_dropin_sha256"),
        "credential_rollback_rejected",
    )


def reconcile(
    *,
    expected_plan_sha256: str | None,
    preflight_only: bool,
) -> dict[str, object]:
    require(os.geteuid() == 0, "root_identity_required")
    prestate = inspect_prestate()
    plan = build_plan(prestate)
    plan_sha256 = digest_bytes(plan)
    if expected_plan_sha256 is not None:
        require(plan_sha256 == expected_plan_sha256, "plan_digest_drifted")
    if preflight_only:
        return {"plan_sha256": plan_sha256, "status": "ready"}
    require(expected_plan_sha256 is not None, "expected_plan_required")
    original = REDUNDANT_PATH.read_bytes()
    backup_root = backup(plan, original)
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    journal = STATE_ROOT / f"JOURNAL-{stamp}-{plan_sha256[:12]}.json"
    atomic_write(
        journal,
        canonical({"plan_sha256": plan_sha256, "schema": SCHEMA, "status": "reconciling"}),
        mode=0o600,
    )
    mutated = False
    try:
        binding = prestate["binding"]
        require(isinstance(binding, dict), "credential_prestate_rejected")
        gid = binding.get("redundant_dropin_gid")
        require(isinstance(gid, int), "credential_prestate_rejected")
        atomic_write(REDUNDANT_PATH, canonical_hybrid_gate(), mode=0o644, gid=gid)
        mutated = True
        systemctl("daemon-reload")
        target = verify_target()
        receipt = {
            "backup": backup_root.name,
            "credential_category_changed": False,
            "credential_source_changed": False,
            "credential_value_read_or_written": False,
            "model_called": False,
            "plan_sha256": plan_sha256,
            "provider_or_channel_called": False,
            "schema": SCHEMA,
            "service_restarted": False,
            "status": "CREDENTIAL_BINDING_RECONCILED_B_PREFLIGHT_REQUIRED",
            **target,
        }
        atomic_write(journal, canonical(receipt), mode=0o600)
        atomic_write(
            STATE_ROOT / f"RECEIPT-{stamp}-{plan_sha256[:12]}.json",
            canonical(receipt),
            mode=0o600,
        )
        return receipt
    except Exception:
        rollback = "not_needed"
        rollback_error: Exception | None = None
        if mutated:
            try:
                restore(original, prestate)
                rollback = "verified"
            except Exception as exc:
                rollback = "failed"
                rollback_error = exc
        atomic_write(
            journal,
            canonical(
                {
                    "model_called": False,
                    "plan_sha256": plan_sha256,
                    "provider_or_channel_called": False,
                    "rollback": rollback,
                    "schema": SCHEMA,
                    "status": (
                        "rollback_failed"
                        if rollback_error is not None
                        else "rolled_back"
                        if mutated
                        else "failed_before_mutation"
                    ),
                }
            ),
            mode=0o600,
        )
        if rollback_error is not None:
            raise ReconciliationRejected("credential_rollback_rejected") from rollback_error
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    try:
        result = reconcile(
            expected_plan_sha256=arguments.expected_plan_sha256,
            preflight_only=arguments.preflight_only,
        )
    except (
        CredentialBindingRejected,
        ReconciliationRejected,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        code = getattr(exc, "code", "credential_reconciliation_rejected")
        print(
            json.dumps(
                {"failure_gate": code, "status": "rejected"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
