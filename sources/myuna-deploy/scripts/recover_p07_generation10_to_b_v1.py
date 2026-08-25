#!/usr/bin/env python3
"""Restore the accepted B generation-4 functional prestate before P07 recovery."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess

from activate_p07_d_generation10_v1 import (
    B_V4_EPOCH_DATABASE,
    CORE_BINDING,
    CORE_GATE,
    CORE_SELECTOR,
    CORE_SERVICE,
    RELEASE_SET_PATH,
    SELECTOR_PATH,
    TELEGRAM_DROPIN,
    TELEGRAM_RUNTIME_USER,
    TELEGRAM_SERVICE,
    TELEGRAM_SOCKET,
    _expected_b_metadata,
    _load_b_selector,
    active,
    atomic_write,
    canonical,
    digest_bytes,
    digest_file,
    load_protected_release_set_snapshot,
    optional_bytes,
    show,
    systemctl,
)
from external_epoch_bundle import (
    inspect_epoch_bundle,
    restore_epoch_bundle_permissions,
    seal_epoch_bundle,
)
from recover_p07_b_generation4_core_v1 import (
    EXPECTED_CORE_BINDING_SHA256,
    EXPECTED_CORE_GATE_SHA256,
    EXPECTED_CORE_SELECTOR_SHA256,
    EXPECTED_SELECTOR_SHA256,
    EXPECTED_TELEGRAM_DROPIN_SHA256,
    RecoveryRejected,
    _verify_exact_b_selection,
    verify_target,
    wait_stable,
)


SCHEMA = "myuna.p07-generation10-to-b-recovery.v1"
BACKUP_ROOT = Path("/var/backups/myuna/p07-generation10-to-b-recovery-v1")
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07-generation10-to-b-recovery-v1")
REQUIRED_B_FILES = {
    "CORE_BINDING": EXPECTED_CORE_BINDING_SHA256,
    "CORE_GATE": EXPECTED_CORE_GATE_SHA256,
    "CORE_SELECTOR": EXPECTED_CORE_SELECTOR_SHA256,
    "SELECTOR": EXPECTED_SELECTOR_SHA256,
    "TELEGRAM_DROPIN": EXPECTED_TELEGRAM_DROPIN_SHA256,
}


class Generation10ToBRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Generation10ToBRejected(code)


def _root_regular(path: Path, *, mode: int = 0o600) -> bytes:
    metadata = path.lstat()
    require(
        not path.is_symlink()
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and stat.S_IMODE(metadata.st_mode) == mode,
        "recovery_source_metadata_rejected",
    )
    return path.read_bytes()


def _load_source_backup(path: Path) -> tuple[dict[str, bytes], dict[str, object]]:
    metadata = path.lstat()
    require(
        not path.is_symlink()
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        "recovery_source_directory_rejected",
    )
    files = {name: _root_regular(path / name) for name in REQUIRED_B_FILES}
    for name, expected in REQUIRED_B_FILES.items():
        require(digest_bytes(files[name]) == expected, "recovery_source_digest_rejected")
    stopped_bundle = json.loads(_root_regular(path / "STOPPED_BUNDLE_PRESTATE.json"))
    require(
        isinstance(stopped_bundle, dict)
        and isinstance(stopped_bundle.get("bundle_digest"), str),
        "recovery_bundle_prestate_rejected",
    )
    return files, stopped_bundle


def _service_projection() -> dict[str, object]:
    return {
        unit: {
            "active": active(unit),
            "nrestarts": int(show(unit, "NRestarts") or "0"),
            "result": show(unit, "Result"),
            "substate": show(unit, "SubState"),
        }
        for unit in (CORE_SERVICE, TELEGRAM_SERVICE, TELEGRAM_SOCKET)
    }


def inspect_prestate(
    source_backup: Path,
    *,
    expected_revision: int,
    expected_turns: int,
    expected_summaries: int,
) -> dict[str, object]:
    require(os.geteuid() == 0, "root_identity_required")
    source_files, bundle_prestate = _load_source_backup(source_backup)
    snapshot = load_protected_release_set_snapshot(
        RELEASE_SET_PATH, expected_uid=0, expected_gid=0
    )
    require(snapshot.release_set.generation == 10, "generation10_not_selected")
    selector_metadata = SELECTOR_PATH.lstat()
    require(
        not SELECTOR_PATH.is_symlink()
        and stat.S_ISREG(selector_metadata.st_mode)
        and json.loads(SELECTOR_PATH.read_bytes()).get("generation") == 10,
        "generation10_selector_rejected",
    )
    telegram = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    sealed = inspect_epoch_bundle(
        B_V4_EPOCH_DATABASE,
        expected_file_mode=0o440,
        expected_parent_mode=0o550,
        expected_uid=0,
        expected_gid=telegram.pw_gid,
    )
    require(
        sealed["bundle_digest"] == bundle_prestate["bundle_digest"],
        "b_bundle_digest_drifted",
    )
    require(active(CORE_SERVICE), "generation10_core_state_rejected")
    return {
        "b_bundle_digest": sealed["bundle_digest"],
        "b_metadata": _expected_b_metadata(
            revision=expected_revision,
            turns=expected_turns,
            summaries=expected_summaries,
            pending=0,
        ),
        "current_release_set_id": snapshot.release_set.release_set_id,
        "current_services": _service_projection(),
        "source_backup_name": source_backup.name,
        "source_control_digest": digest_bytes(
            canonical({name: digest_bytes(payload) for name, payload in source_files.items()})
        ),
    }


def build_plan(prestate: dict[str, object]) -> bytes:
    return canonical(
        {
            "boundaries": {
                "channel_model_provider_health_called": False,
                "failed_epoch_reused": False,
                "old_epoch_content_read_or_mutated": False,
            },
            "executor_sha256": digest_file(Path(__file__).resolve()),
            "prestate": prestate,
            "rollback": "restore exact generation10 control files and reseal B bundle",
            "schema": SCHEMA,
            "status": "ready",
            "target": "accepted-b-generation4-functional-prestate",
        }
    )


def _write_b_controls(source: dict[str, bytes]) -> None:
    core_gid = grp.getgrnam("myuna").gr_gid
    telegram_gid = pwd.getpwnam(TELEGRAM_RUNTIME_USER).pw_gid
    atomic_write(CORE_BINDING, source["CORE_BINDING"], mode=0o640, gid=core_gid)
    atomic_write(CORE_GATE, source["CORE_GATE"], mode=0o644)
    atomic_write(CORE_SELECTOR, source["CORE_SELECTOR"], mode=0o644)
    atomic_write(TELEGRAM_DROPIN, source["TELEGRAM_DROPIN"], mode=0o644)
    atomic_write(SELECTOR_PATH, source["SELECTOR"], mode=0o640, gid=telegram_gid)


def _restore_controls(
    current: dict[str, bytes | None],
    preserved_release_set: Path,
    *,
    release_moved: bool,
) -> None:
    core_gid = grp.getgrnam("myuna").gr_gid
    telegram_gid = pwd.getpwnam(TELEGRAM_RUNTIME_USER).pw_gid
    atomic_write(CORE_BINDING, current["CORE_BINDING"], mode=0o640, gid=core_gid)  # type: ignore[arg-type]
    atomic_write(CORE_GATE, current["CORE_GATE"], mode=0o644)  # type: ignore[arg-type]
    atomic_write(CORE_SELECTOR, current["CORE_SELECTOR"], mode=0o644)  # type: ignore[arg-type]
    atomic_write(TELEGRAM_DROPIN, current["TELEGRAM_DROPIN"], mode=0o644)  # type: ignore[arg-type]
    atomic_write(SELECTOR_PATH, current["SELECTOR"], mode=0o640, gid=telegram_gid)  # type: ignore[arg-type]
    if release_moved:
        require(preserved_release_set.is_file() and not preserved_release_set.is_symlink(), "generation10_release_set_evidence_rejected")
        os.replace(preserved_release_set, RELEASE_SET_PATH)


def _restore_service_states(prestate: dict[str, object]) -> None:
    projection = prestate.get("current_services")
    require(isinstance(projection, dict), "generation10_service_prestate_rejected")
    for unit in (CORE_SERVICE, TELEGRAM_SOCKET, TELEGRAM_SERVICE):
        observed = projection.get(unit)
        require(
            isinstance(observed, dict) and type(observed.get("active")) is bool,
            "generation10_service_prestate_rejected",
        )
        if observed["active"]:
            systemctl("start", unit)
        else:
            systemctl("stop", unit, check=False)
    for unit in (CORE_SERVICE, TELEGRAM_SOCKET, TELEGRAM_SERVICE):
        observed = projection[unit]
        require(active(unit) == observed["active"], "generation10_service_rollback_rejected")
        if observed["active"] and unit.endswith(".service"):
            wait_stable(unit, seconds=5.0, timeout=30.0)


def recover(
    source_backup: Path,
    *,
    expected_revision: int,
    expected_turns: int,
    expected_summaries: int,
    expected_plan_sha256: str | None,
    preflight_only: bool,
) -> dict[str, object]:
    prestate = inspect_prestate(
        source_backup,
        expected_revision=expected_revision,
        expected_turns=expected_turns,
        expected_summaries=expected_summaries,
    )
    source, bundle_prestate = _load_source_backup(source_backup)
    plan = build_plan(prestate)
    plan_sha256 = digest_bytes(plan)
    if expected_plan_sha256 is not None:
        require(plan_sha256 == expected_plan_sha256, "plan_digest_drifted")
    if preflight_only:
        return {"plan_sha256": plan_sha256, "status": "ready"}
    require(expected_plan_sha256 is not None, "expected_plan_required")
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    backup = BACKUP_ROOT / plan_sha256
    require(not backup.exists(), "recovery_attempt_already_exists")
    backup.mkdir(mode=0o700)
    current = {
        "CORE_BINDING": CORE_BINDING.read_bytes(),
        "CORE_GATE": CORE_GATE.read_bytes(),
        "CORE_SELECTOR": CORE_SELECTOR.read_bytes(),
        "TELEGRAM_DROPIN": TELEGRAM_DROPIN.read_bytes(),
        "SELECTOR": SELECTOR_PATH.read_bytes(),
    }
    for name, payload in current.items():
        atomic_write(backup / name, payload, mode=0o600)
    atomic_write(backup / "PLAN.json", plan, mode=0o600)
    preserved_release_set = backup / "GENERATION10_RELEASE_SET.json"
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    journal = STATE_ROOT / f"JOURNAL-{stamp}-{plan_sha256[:12]}.json"
    atomic_write(journal, canonical({"plan_sha256": plan_sha256, "schema": SCHEMA, "status": "recovering"}), mode=0o600)
    mutation_started = False
    release_moved = False
    bundle_restored = False
    try:
        systemctl("stop", TELEGRAM_SOCKET, TELEGRAM_SERVICE, CORE_SERVICE)
        mutation_started = True
        _write_b_controls(source)
        os.replace(RELEASE_SET_PATH, preserved_release_set)
        release_moved = True
        restore_epoch_bundle_permissions(
            B_V4_EPOCH_DATABASE,
            prestate=bundle_prestate,
            expected_bundle_digest=str(bundle_prestate["bundle_digest"]),
        )
        bundle_restored = True
        systemctl("daemon-reload")
        systemctl("start", CORE_SERVICE, TELEGRAM_SOCKET, TELEGRAM_SERVICE)
        wait_stable(CORE_SERVICE)
        wait_stable(TELEGRAM_SERVICE, seconds=5.0, timeout=30.0)
        target = verify_target()
        _expected_b_metadata(
            revision=expected_revision,
            turns=expected_turns,
            summaries=expected_summaries,
            pending=0,
        )
        receipt = {
            "generation10_release_set_preserved": True,
            "plan_sha256": plan_sha256,
            "schema": SCHEMA,
            "status": "P07_ACCEPTED_B_FUNCTIONAL_PRESTATE_RESTORED",
            **target,
        }
        atomic_write(journal, canonical(receipt), mode=0o600)
        atomic_write(STATE_ROOT / f"RECEIPT-{stamp}-{plan_sha256[:12]}.json", canonical(receipt), mode=0o600)
        return receipt
    except Exception as original_error:
        if mutation_started:
            systemctl("stop", TELEGRAM_SOCKET, TELEGRAM_SERVICE, CORE_SERVICE, check=False)
            _restore_controls(
                current,
                preserved_release_set,
                release_moved=release_moved,
            )
            if bundle_restored:
                telegram = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
                seal_epoch_bundle(
                    B_V4_EPOCH_DATABASE,
                    expected_bundle_digest=str(bundle_prestate["bundle_digest"]),
                    source_uid=telegram.pw_uid,
                    source_gid=telegram.pw_gid,
                    sealed_gid=telegram.pw_gid,
                )
            systemctl("daemon-reload")
            _restore_service_states(prestate)
            restored_snapshot = load_protected_release_set_snapshot(
                RELEASE_SET_PATH, expected_uid=0, expected_gid=0
            )
            require(restored_snapshot.release_set.generation == 10, "generation10_rollback_selection_rejected")
        atomic_write(journal, canonical({"plan_sha256": plan_sha256, "rollback": "verified" if mutation_started else "not_needed", "schema": SCHEMA, "status": "rejected"}), mode=0o600)
        raise original_error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-backup", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--expected-turns", required=True, type=int)
    parser.add_argument("--expected-summaries", required=True, type=int)
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    try:
        result = recover(
            arguments.source_backup.resolve(),
            expected_revision=arguments.expected_revision,
            expected_turns=arguments.expected_turns,
            expected_summaries=arguments.expected_summaries,
            expected_plan_sha256=arguments.expected_plan_sha256,
            preflight_only=arguments.preflight_only,
        )
    except (Generation10ToBRejected, RecoveryRejected, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(json.dumps({"failure_gate": getattr(exc, "code", "generation10_to_b_recovery_rejected"), "status": "rejected"}, separators=(",", ":"), sort_keys=True))
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
