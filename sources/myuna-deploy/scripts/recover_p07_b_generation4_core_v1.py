#!/usr/bin/env python3
"""Recover the exact accepted P07 B generation-4 Core/runtime selection."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from activate_owner_profile_local_provider_v1 import CORE_DROPIN_BYTES
from activate_p07_hybrid_external_generation_v1 import (
    CORE_BINDING,
    CORE_GATE,
    CORE_SELECTOR,
    TELEGRAM_DROPIN,
    TELEGRAM_SERVICE,
    TELEGRAM_SOCKET,
    active,
    atomic_write,
    canonical,
    digest_bytes,
    digest_file,
    show,
    systemctl,
)
from core_release_selector import compute_tree_digest
from p07_credential_binding import (
    CredentialBindingRejected,
    credential_declarations,
    effective_credential_declarations,
    verify_effective_credential,
    verify_source_metadata,
    verify_strict_binding,
)


SCHEMA = "myuna.p07-b-generation4-core-incident-recovery.v1"
CORE_SERVICE = "myuna-core@qq.service"
DROPIN_ROOT = Path("/etc/systemd/system/myuna-core@qq.service.d")
LOCAL_PROFILE_DROPIN = DROPIN_ROOT / "zzzzzzz-p07-local-profile-v1.conf"
CANONICAL_CREDENTIAL_DROPIN = "credentials.conf"
EXPECTED_SOURCE = Path("/etc/myuna/secrets/deepseek-api-key")
EFFECTIVE_CREDENTIAL = Path(
    f"/run/credentials/{CORE_SERVICE}/deepseek_api_key"
)
CORE_RELEASE = "f96b1da88e2fa0221544dcf6ce04b70108bf282c47cec182e9438768a933f4f7"
CORE_RELEASE_PATH = Path("/srv/myuna/releases/core") / CORE_RELEASE
CORE_FILE_COUNT = 292
RUNTIME_RELEASE = "7374038455d57bdeec2b7ce64de9d4274c16f64f50f95ac993e0e970571c92df"
SELECTOR = Path("/etc/myuna-telegram-gateway/external-epoch-selector-v2.json")
EXPECTED_CORE_BINDING_SHA256 = "5074782136274fd89c6a351ed8f7692a14800ed96c5dc810807fed69b4b011ff"
EXPECTED_CORE_SELECTOR_SHA256 = "78e5ee4357e59128746941a0b07acbc3dcddb150f1e18d59667d500202802e7c"
EXPECTED_CORE_GATE_SHA256 = "6d43dd65898f844821582dba4c15031e5d62f2fe7b0bf7bf8c33768b58d697a7"
EXPECTED_TELEGRAM_DROPIN_SHA256 = "78eab22fbd8593a826c58feee356d3e41507ad2ad6db0c523f39deccf12d806a"
EXPECTED_SELECTOR_SHA256 = "21e9bddb3df33783bc8769c3176d2d2ba16da48ab665763edb09abad91a3614b"
TARGET_CREDENTIAL_LINE = (
    b"LoadCredential=deepseek_api_key:/etc/myuna/secrets/deepseek-api-key\n"
)
BROKEN_LOCAL_PROFILE_DROPIN = CORE_DROPIN_BYTES.replace(
    TARGET_CREDENTIAL_LINE,
    b"",
    1,
)
BACKUP_ROOT = Path("/var/backups/myuna/p07-b-generation4-core-incident-recovery-v1")
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07-b-generation4-core-incident-recovery-v1")


class RecoveryRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RecoveryRejected(code)


def _regular_file(path: Path, *, mode: int | None = None) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RecoveryRejected("recovery_file_unavailable") from exc
    require(
        not path.is_symlink() and stat.S_ISREG(metadata.st_mode),
        "recovery_file_type_rejected",
    )
    require(metadata.st_uid == 0, "recovery_file_owner_rejected")
    if mode is not None:
        require(stat.S_IMODE(metadata.st_mode) == mode, "recovery_file_mode_rejected")
    return metadata


def _restart_count(unit: str) -> int:
    try:
        value = int(show(unit, "NRestarts"))
    except (TypeError, ValueError) as exc:
        raise RecoveryRejected("service_restart_metadata_rejected") from exc
    require(value >= 0, "service_restart_metadata_rejected")
    return value


def _verify_exact_b_selection() -> None:
    require(digest_file(CORE_BINDING) == EXPECTED_CORE_BINDING_SHA256, "core_binding_drifted")
    require(digest_file(CORE_SELECTOR) == EXPECTED_CORE_SELECTOR_SHA256, "core_selector_drifted")
    require(digest_file(CORE_GATE) == EXPECTED_CORE_GATE_SHA256, "core_gate_drifted")
    require(
        digest_file(TELEGRAM_DROPIN) == EXPECTED_TELEGRAM_DROPIN_SHA256,
        "telegram_dropin_drifted",
    )
    require(digest_file(SELECTOR) == EXPECTED_SELECTOR_SHA256, "generation4_selector_drifted")
    require(
        show(CORE_SERVICE, "WorkingDirectory") == CORE_RELEASE_PATH.as_posix(),
        "core_release_selection_drifted",
    )
    require(
        f"/{RUNTIME_RELEASE}/runtime/telegram_owner_runtime_gateway.py"
        in show(TELEGRAM_SERVICE, "ExecStart"),
        "telegram_runtime_selection_drifted",
    )
    require(
        compute_tree_digest(CORE_RELEASE_PATH) == (CORE_RELEASE, CORE_FILE_COUNT),
        "core_release_tree_drifted",
    )


def inspect_prestate() -> dict[str, object]:
    require(os.geteuid() == 0, "root_identity_required")
    _verify_exact_b_selection()
    metadata = _regular_file(LOCAL_PROFILE_DROPIN, mode=0o644)
    require(
        LOCAL_PROFILE_DROPIN.read_bytes() == BROKEN_LOCAL_PROFILE_DROPIN,
        "local_profile_dropin_prestate_drifted",
    )
    verify_source_metadata(EXPECTED_SOURCE)
    raw = credential_declarations(DROPIN_ROOT)
    require(
        raw.count((CANONICAL_CREDENTIAL_DROPIN, EXPECTED_SOURCE)) == 1,
        "canonical_credential_declaration_rejected",
    )
    require(
        effective_credential_declarations(DROPIN_ROOT) == (),
        "broken_effective_credential_shape_drifted",
    )
    require(not active(CORE_SERVICE), "core_prestate_must_be_inactive")
    return {
        "core_active": False,
        "core_restarts": _restart_count(CORE_SERVICE),
        "core_release": CORE_RELEASE,
        "local_profile_dropin_gid": metadata.st_gid,
        "local_profile_dropin_mode": stat.S_IMODE(metadata.st_mode),
        "local_profile_dropin_sha256": digest_file(LOCAL_PROFILE_DROPIN),
        "selector_sha256": digest_file(SELECTOR),
        "telegram_service_active": active(TELEGRAM_SERVICE),
        "telegram_socket_active": active(TELEGRAM_SOCKET),
    }


def build_plan(prestate: dict[str, object]) -> bytes:
    return canonical(
        {
            "boundaries": {
                "channel_model_provider_health_called": False,
                "credential_source_or_value_changed": False,
                "d_activation_replayed": False,
                "old_epoch_session_profile_writer_qq_changed": False,
            },
            "executor_sha256": digest_file(Path(__file__).resolve()),
            "prestate": prestate,
            "rollback": {
                "exact_local_profile_dropin": True,
                "restore_service_states": True,
            },
            "schema": SCHEMA,
            "status": "incident-recovery-ready",
            "target": {
                "core_release": CORE_RELEASE,
                "effective_credential_count": 1,
                "generation": 4,
                "local_profile_dropin_sha256": digest_bytes(CORE_DROPIN_BYTES),
                "runtime_release": RUNTIME_RELEASE,
                "selector_sha256": EXPECTED_SELECTOR_SHA256,
            },
        }
    )


def backup(plan: bytes, prestate: dict[str, object]) -> tuple[Path, bytes]:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    root = BACKUP_ROOT / digest_bytes(plan)
    require(not root.exists(), "recovery_attempt_already_exists")
    root.mkdir(mode=0o700)
    original = LOCAL_PROFILE_DROPIN.read_bytes()
    atomic_write(root / "PLAN.json", plan, mode=0o600)
    atomic_write(root / "PRESTATE.json", canonical(prestate), mode=0o600)
    atomic_write(root / "LOCAL_PROFILE_DROPIN", original, mode=0o600)
    return root, original


def wait_stable(unit: str, *, seconds: float = 15.0, timeout: float = 45.0) -> int:
    deadline = time.monotonic() + timeout
    stable_since: float | None = None
    observed_restarts: int | None = None
    while time.monotonic() < deadline:
        restarts = _restart_count(unit)
        if active(unit):
            if observed_restarts == restarts:
                stable_since = stable_since or time.monotonic()
                if time.monotonic() - stable_since >= seconds:
                    return restarts
            else:
                observed_restarts = restarts
                stable_since = time.monotonic()
        else:
            observed_restarts = restarts
            stable_since = None
        time.sleep(0.5)
    raise RecoveryRejected("service_stability_rejected")


def verify_target() -> dict[str, object]:
    _verify_exact_b_selection()
    strict = verify_strict_binding(
        DROPIN_ROOT,
        canonical_dropin=CANONICAL_CREDENTIAL_DROPIN,
        expected_source=EXPECTED_SOURCE,
    )
    require(strict["effective_declaration_count"] == 1, "effective_binding_rejected")
    require(
        strict["effective_dropin"] == LOCAL_PROFILE_DROPIN.name,
        "effective_binding_owner_rejected",
    )
    verify_effective_credential(EFFECTIVE_CREDENTIAL)
    require(active(CORE_SERVICE), "core_target_inactive")
    require(active(TELEGRAM_SERVICE), "telegram_service_target_inactive")
    require(active(TELEGRAM_SOCKET), "telegram_socket_target_inactive")
    return {
        "core_restarts": _restart_count(CORE_SERVICE),
        "effective_credential_count": 1,
        "generation": 4,
        "telegram_restarts": _restart_count(TELEGRAM_SERVICE),
    }


def restore(original: bytes, prestate: dict[str, object]) -> None:
    systemctl("stop", TELEGRAM_SERVICE, check=False)
    systemctl("stop", CORE_SERVICE, check=False)
    mode = prestate.get("local_profile_dropin_mode")
    gid = prestate.get("local_profile_dropin_gid")
    require(isinstance(mode, int) and isinstance(gid, int), "recovery_prestate_rejected")
    atomic_write(LOCAL_PROFILE_DROPIN, original, mode=mode, gid=gid)
    systemctl("daemon-reload")
    if bool(prestate.get("telegram_socket_active")):
        systemctl("start", TELEGRAM_SOCKET)
    else:
        systemctl("stop", TELEGRAM_SOCKET, check=False)
    if bool(prestate.get("telegram_service_active")):
        systemctl("start", TELEGRAM_SERVICE)
    require(
        digest_file(LOCAL_PROFILE_DROPIN)
        == str(prestate.get("local_profile_dropin_sha256")),
        "recovery_rollback_dropin_rejected",
    )
    require(not active(CORE_SERVICE), "recovery_rollback_core_state_rejected")


def recover(*, expected_plan_sha256: str | None, preflight_only: bool) -> dict[str, object]:
    prestate = inspect_prestate()
    plan = build_plan(prestate)
    plan_sha256 = digest_bytes(plan)
    if expected_plan_sha256 is not None:
        require(plan_sha256 == expected_plan_sha256, "plan_digest_drifted")
    if preflight_only:
        return {"plan_sha256": plan_sha256, "status": "ready"}
    require(expected_plan_sha256 is not None, "expected_plan_required")
    backup_root, original = backup(plan, prestate)
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    journal = STATE_ROOT / f"JOURNAL-{stamp}-{plan_sha256[:12]}.json"
    atomic_write(
        journal,
        canonical({"plan_sha256": plan_sha256, "schema": SCHEMA, "status": "recovering"}),
        mode=0o600,
    )
    mutated = False
    try:
        gid = prestate["local_profile_dropin_gid"]
        require(isinstance(gid, int), "recovery_prestate_rejected")
        atomic_write(LOCAL_PROFILE_DROPIN, CORE_DROPIN_BYTES, mode=0o644, gid=gid)
        mutated = True
        systemctl("daemon-reload")
        verify_strict_binding(
            DROPIN_ROOT,
            canonical_dropin=CANONICAL_CREDENTIAL_DROPIN,
            expected_source=EXPECTED_SOURCE,
        )
        systemctl("start", CORE_SERVICE)
        wait_stable(CORE_SERVICE)
        systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)
        wait_stable(TELEGRAM_SERVICE, seconds=5.0, timeout=30.0)
        target = verify_target()
        receipt = {
            "backup": backup_root.name,
            "channel_model_provider_health_called": False,
            "credential_source_or_value_changed": False,
            "d_activation_replayed": False,
            "plan_sha256": plan_sha256,
            "rollback": "not_needed",
            "schema": SCHEMA,
            "status": "P07_B_GENERATION4_FUNCTIONAL_PRESTATE_RESTORED",
            **target,
        }
        atomic_write(journal, canonical(receipt), mode=0o600)
        atomic_write(STATE_ROOT / f"RECEIPT-{stamp}-{plan_sha256[:12]}.json", canonical(receipt), mode=0o600)
        return receipt
    except Exception as original_error:
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
                    "plan_sha256": plan_sha256,
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
            raise RecoveryRejected("recovery_rollback_rejected") from rollback_error
        raise original_error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    try:
        result = recover(
            expected_plan_sha256=arguments.expected_plan_sha256,
            preflight_only=arguments.preflight_only,
        )
    except (
        CredentialBindingRejected,
        RecoveryRejected,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        print(
            json.dumps(
                {
                    "failure_gate": getattr(exc, "code", "incident_recovery_rejected"),
                    "status": "rejected",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
