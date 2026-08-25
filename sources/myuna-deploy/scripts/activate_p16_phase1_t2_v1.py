#!/usr/bin/env python3
"""Rollback-bound P16 Phase 1 incident-history activation controller.

The controller observes and mutates only fixed, content-free release/service
metadata.  It never calls a channel, model, provider, health endpoint, Profile,
session store, database, or log reader.  The generation-13 P07 release-set and
P08 state remain immutable compatibility inputs; P16 is installed as a
diagnostic overlay and is enabled only when both its selector and marker exist.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Callable, Mapping

import activate_p08_active_temporal_context_v1 as p08_activation
import activate_p16_diagnostics_v1 as legacy_p16
from activate_p07_d_generation13_v1 import (
    EFFECTIVE_V6_ENV,
    OWNER_RUNTIME_CONFIG,
    RELEASE_SET_EPOCH_PATH,
    RELEASE_SET_PATH,
    TELEGRAM_RUNTIME_USER,
    _load_v6_release,
)
from activate_p07_external_epoch_rollover_v1 import SELECTOR_PATH as P07_SELECTOR
from activate_p07_hybrid_external_generation_v1 import (
    CORE_BINDING,
    CORE_GATE as P07_CORE_GATE,
    CORE_RELEASE_ROOT,
    CORE_SELECTOR,
    CORE_SERVICE,
    PLUGIN_ROOT,
    RUNTIME_ROOT,
    TELEGRAM_CONFIG,
    TELEGRAM_DROPIN as GENERATION13_TELEGRAM_DROPIN,
    TELEGRAM_SERVICE,
    TELEGRAM_SOCKET,
)
from incident_history_runtime_adapter_v1 import (
    INCIDENT_HISTORY_MARKER,
    INCIDENT_HISTORY_ROOT,
    INCIDENT_HISTORY_SELECTOR,
    load_approved_incident_history_selector,
)
from p07_d_release_set import load_protected_release_set_snapshot
from p07_d_runtime_readiness import (
    RuntimeReadinessRejected,
    inspect_runtime_readiness,
    readiness_path,
)
from p16_phase1_t2_contract_v1 import (
    ATTEMPT_LINEAGE_SCHEMA_V1,
    ATTEMPT_TRANSITION_RECEIPT_SCHEMA,
    ATTEMPT_TRANSITION_RECEIPT_SCHEMA_V1,
    BUNDLE_SCHEMA,
    build_selector,
    canonical,
    digest,
    validate_attempt_lineage,
    validate_bundle,
)


LIVE_PLAN_SCHEMA = "myuna.p16-phase1-t2-live-plan.v1"
ACTIVATION_RECEIPT_SCHEMA = "myuna.p16-phase1-t2-activation-receipt.v1"
ROLLBACK_RECEIPT_SCHEMA = "myuna.p16-phase1-t2-rollback-receipt.v1"
ATTEMPT_LEDGER_SCHEMA = "myuna.p16-phase1-t2-attempt-ledger.v1"
MARKER_SCHEMA = "myuna.p16-incident-history-enabled.v1"
SERVICE_BINDING_PROJECTION = "systemd-exec-static-v2"

P16_TELEGRAM_DROPIN = Path(
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
    "zzzzzzzzzzzz-p16-phase1-t2-v1.conf"
)
ADAPTER_RELEASE_ROOT = Path("/opt/myuna/p16-incident-history-v1/releases")
STATE_ROOT = Path("/var/lib/myuna-fault-diagnostics/p16-phase1-t2-state")
ATTEMPT_LEDGER = STATE_ROOT / "ATTEMPT_LEDGER.json"
ATTEMPT_LOCK = STATE_ROOT / "ATTEMPT_LEDGER.lock"
ATTEMPT_TRANSITION_ROOT = STATE_ROOT / "attempt-lineage-v1"
# Immutable state for the currently active v1 successor series.
SUCCESSOR_STATE_ROOT = Path(
    "/var/lib/myuna-fault-diagnostics/p16-successor-attempt-series-v1"
)
# Independent state for the projection-budget strategy. It never aliases or
# rewrites the predecessor series above.
PROJECTION_BUDGET_SUCCESSOR_STATE_ROOT = Path(
    "/var/lib/myuna-fault-diagnostics/p16-projection-budget-attempt-series-v1"
)
RECEIPT_ROOT = Path("/var/lib/myuna-fault-diagnostics/p16-phase1-t2-receipts")
SUCCESSOR_RECEIPT_ROOT = RECEIPT_ROOT
BACKUP_ROOT = Path("/var/backups/myuna/p16-phase1-t2-v1")
ACTIVE_PREDECESSOR_BUNDLE_ROOT = Path(
    "/srv/myuna/builds/p16-successor-series-v1-repair/run-a-root"
)

MAX_ATTEMPTS = 2
P08_SERVICE = p08_activation.SERVICE
P08_SOCKET = p08_activation.SOCKET

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_INVOCATION = re.compile(r"^[0-9a-f]{32}$")
_SAFE_GATE = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
_SYSTEMD_EXEC_RUNTIME_BRACKET_FIELD = re.compile(
    r"\s*;\s*(?:start_time|stop_time)=\[[^\]]*\]"
)
_SYSTEMD_EXEC_RUNTIME_SCALAR_FIELD = re.compile(
    r"\s*;\s*(?:pid|code|status)=[^;}]*"
)
_MAX_JSON = 1_000_000


class P16Phase1T2Rejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise P16Phase1T2Rejected(code)


def _failure_gate(exc: BaseException) -> str:
    code = getattr(exc, "code", "")
    if not isinstance(code, str) or _SAFE_GATE.fullmatch(code) is None:
        return "p16_phase1_t2_rejected"
    return code


def _sha(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_regular(path: Path, *, maximum: int = _MAX_JSON) -> bytes:
    metadata = path.lstat()
    require(
        not path.is_symlink()
        and stat.S_ISREG(metadata.st_mode)
        and 0 < metadata.st_size <= maximum,
        "protected_file_rejected",
    )
    return path.read_bytes()


def _read_canonical(path: Path, *, maximum: int = _MAX_JSON) -> dict[str, object]:
    raw = _read_regular(path, maximum=maximum)
    require(raw.endswith(b"\n"), "canonical_json_framing_rejected")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise P16Phase1T2Rejected("canonical_json_rejected") from exc
    require(isinstance(value, dict) and raw == canonical(value) + b"\n", "canonical_json_rejected")
    return value


def _read_canonical_legacy(path: Path, *, maximum: int = _MAX_JSON) -> dict[str, object]:
    """Read a protected canonical object that historically omitted framing."""

    raw = _read_regular(path, maximum=maximum)
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise P16Phase1T2Rejected("canonical_json_rejected") from exc
    require(
        isinstance(value, dict) and raw in {canonical(value), canonical(value) + b"\n"},
        "canonical_json_rejected",
    )
    return value


def _atomic_write(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    uid: int = 0,
    gid: int = 0,
    exclusive: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        if exclusive:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        else:
            os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _run(command: list[str], *, timeout: float = 20.0, cwd: Path | None = None) -> bytes:
    try:
        completed = subprocess.run(
            command,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            cwd=cwd,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise P16Phase1T2Rejected("fixed_command_failed") from exc
    return completed.stdout


def _systemctl(*arguments: str, timeout: float = 60.0) -> None:
    _run(["/usr/bin/systemctl", *arguments], timeout=timeout)


def _show(unit: str, fields: tuple[str, ...]) -> dict[str, str]:
    command = ["/usr/bin/systemctl", "show", unit]
    command.extend(f"--property={field}" for field in fields)
    command.append("--no-pager")
    raw = _run(command, timeout=3.0).decode("ascii")
    result: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        require(bool(separator) and key not in result, "service_projection_rejected")
        result[key] = value
    require(set(result) == set(fields), "service_projection_rejected")
    return result


def _stable_exec_start_projection(value: str) -> str:
    """Remove systemd's per-invocation fields from an ExecStart projection."""

    if not value:
        return ""
    normalized = _SYSTEMD_EXEC_RUNTIME_BRACKET_FIELD.sub("", value)
    normalized = _SYSTEMD_EXEC_RUNTIME_SCALAR_FIELD.sub("", normalized).strip()
    require(
        all(
            marker not in normalized
            for marker in ("start_time=", "stop_time=", "pid=", "code=", "status=")
        ),
        "service_exec_start_projection_rejected",
    )
    return normalized


def _service_projection(unit: str, *, socket: bool = False) -> dict[str, object]:
    fields = (
        ("ActiveState", "SubState", "Result", "InvocationID", "WorkingDirectory")
        if socket
        else (
            "ActiveState",
            "SubState",
            "Result",
            "NRestarts",
            "MainPID",
            "InvocationID",
            "ExecStart",
            "WorkingDirectory",
        )
    )
    observed = _show(unit, fields)
    raw_restarts = "0" if socket else observed["NRestarts"]
    raw_pid = "0" if socket else observed["MainPID"]
    require(raw_restarts.isdigit(), "service_restart_projection_rejected")
    require(raw_pid.isdigit(), "service_pid_projection_rejected")
    invocation = observed["InvocationID"]
    if int(raw_pid) > 0:
        require(_INVOCATION.fullmatch(invocation) is not None, "service_invocation_projection_rejected")
    exec_start = observed.get("ExecStart", "")
    return {
        "active_state": observed["ActiveState"],
        "sub_state": observed["SubState"],
        "result": observed["Result"],
        "nrestarts": int(raw_restarts or "0"),
        "pid": int(raw_pid),
        "invocation_id": invocation,
        "binding_digest": digest(
            "myuna-p16-phase1-t2-service-binding-v2",
            {
                "exec_start": _stable_exec_start_projection(exec_start),
                "unit": unit,
                "working_directory": observed["WorkingDirectory"],
            },
        ),
        "exec_start": exec_start,
        "working_directory": observed["WorkingDirectory"],
    }


def _require_active(projection: Mapping[str, object], *, socket: bool = False) -> None:
    require(projection["active_state"] == "active", "target_service_inactive")
    allowed_substates = {"running"} if not socket else {"running", "listening"}
    require(projection["sub_state"] in allowed_substates, "target_service_inactive")
    require(projection["result"] in {"", "success"}, "target_service_failed")
    require(projection["nrestarts"] == 0, "target_service_restart_drifted")


def _verify_targets_stopped() -> None:
    for unit, is_socket in (
        (CORE_SERVICE, False),
        (TELEGRAM_SERVICE, False),
        (TELEGRAM_SOCKET, True),
    ):
        projection = _service_projection(unit, socket=is_socket)
        require(
            projection["active_state"] == "inactive"
            and projection["pid"] == 0,
            "target_services_not_stopped",
        )


def _git_identity(root: Path, expected: str) -> dict[str, object]:
    require(_HEX40.fullmatch(expected) is not None, "source_commit_rejected")
    prefix = ["/usr/sbin/runuser", "-u", "myuna", "--", "/usr/bin/git", "-C", str(root)]
    head = _run([*prefix, "rev-parse", "HEAD"]).decode("ascii").strip()
    status = _run(
        [*prefix, "status", "--porcelain", "--untracked-files=no"]
    )
    require(head == expected and status == b"", "source_head_drifted")
    return {"commit": head, "clean_tracked": True}


def _inventory_document(bundle_root: Path, name: str) -> dict[str, object]:
    value = _read_canonical(bundle_root / "inventories" / f"{name}.json", maximum=8_000_000)
    require(set(value) == {"schema", "files"}, "artifact_inventory_rejected")
    require(value["schema"] == "myuna.p16-artifact-inventory.v1", "artifact_inventory_rejected")
    require(isinstance(value["files"], list) and value["files"], "artifact_inventory_rejected")
    return value


def _validate_artifact(
    root: Path,
    inventory: Mapping[str, object],
    expected_digest: str,
    expected_count: int,
) -> None:
    require(
        root.name == expected_digest
        and not root.is_symlink()
        and root.is_dir()
        and _HEX64.fullmatch(root.name) is not None,
        "artifact_root_rejected",
    )
    rows = inventory["files"]
    require(isinstance(rows, list) and len(rows) == expected_count, "artifact_inventory_rejected")
    expected_paths: set[str] = set()
    for row in rows:
        require(
            isinstance(row, dict)
            and set(row) == {"path", "sha256", "size", "mode"},
            "artifact_inventory_rejected",
        )
        relative = row["path"]
        require(
            isinstance(relative, str)
            and relative
            and not relative.startswith("/")
            and "\\" not in relative
            and ".." not in Path(relative).parts
            and relative not in expected_paths,
            "artifact_inventory_rejected",
        )
        expected_paths.add(relative)
        target = root / relative
        metadata = target.lstat()
        require(
            not target.is_symlink()
            and stat.S_ISREG(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == int(str(row["mode"]), 8)
            and metadata.st_size == row["size"]
            and _sha(target.read_bytes()) == row["sha256"],
            "artifact_file_drifted",
        )
    actual_paths: set[str] = set()
    for path in [root, *root.rglob("*")]:
        require(not path.is_symlink(), "artifact_symlink_rejected")
        if path.is_dir():
            require(stat.S_IMODE(path.stat().st_mode) == 0o550, "artifact_mode_drifted")
        else:
            require(path.is_file(), "artifact_type_rejected")
            actual_paths.add(path.relative_to(root).as_posix())
    require(actual_paths == expected_paths, "artifact_inventory_drifted")


def _load_bundle_context(bundle_root: Path) -> dict[str, object]:
    bundle = validate_bundle(_read_canonical(bundle_root / "P16_PHASE1_T2_BUNDLE.json"))
    require(bundle["schema"] == BUNDLE_SCHEMA, "bundle_rejected")
    artifacts: dict[str, Path] = {}
    inventories: dict[str, dict[str, object]] = {}
    for name, record_value in bundle["artifacts"].items():
        require(isinstance(record_value, dict), "bundle_artifact_rejected")
        record = record_value
        inventory = _inventory_document(bundle_root, name)
        require(
            digest("myuna-p16-artifact-inventory-v1", inventory)
            == record["inventory_digest"],
            "artifact_inventory_digest_drifted",
        )
        root = bundle_root / name / str(record["release_digest"])
        _validate_artifact(root, inventory, str(record["release_digest"]), int(record["file_count"]))
        artifacts[name] = root
        inventories[name] = inventory
    return {"bundle": bundle, "artifacts": artifacts, "inventories": inventories}


def _file_projection(path: Path) -> dict[str, object]:
    raw = _read_regular(path, maximum=8_000_000)
    metadata = path.lstat()
    return {
        "sha256": _sha(raw),
        "size": len(raw),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "type": "regular_no_symlink",
    }


def _absent(path: Path) -> bool:
    return not path.exists() and not path.is_symlink()


def _basic_acl(path: Path) -> tuple[str, ...]:
    raw = _run(["/usr/bin/getfacl", "-cp", str(path)], timeout=3.0).decode("ascii")
    rows = tuple(line for line in raw.splitlines() if line and not line.startswith("#"))
    require(
        len(rows) == 3
        and rows[0].startswith("user::")
        and rows[1].startswith("group::")
        and rows[2].startswith("other::"),
        "acl_projection_rejected",
    )
    return rows


def _directory_projection(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    allow_absent: bool,
) -> dict[str, object]:
    if _absent(path):
        require(allow_absent, "protected_directory_absent")
        return {"state": "absent"}
    metadata = path.lstat()
    require(
        not path.is_symlink()
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == uid
        and metadata.st_gid == gid
        and stat.S_IMODE(metadata.st_mode) == mode,
        "protected_directory_rejected",
    )
    rows = _basic_acl(path)
    return {
        "state": "present_exact",
        "uid": uid,
        "gid": gid,
        "mode": f"{mode:04o}",
        "acl_digest": digest("myuna-p16-phase1-t2-basic-acl-v1", list(rows)),
    }


def _require_root_directory(path: Path, *, mode: int, code: str) -> None:
    require(not _absent(path), code)
    metadata = path.lstat()
    require(
        not path.is_symlink()
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == mode,
        code,
    )
    require(
        _basic_acl(path) == ("user::rwx", "group::---", "other::---"),
        code,
    )


def _require_root_file(path: Path, *, mode: int, code: str) -> bytes:
    require(not _absent(path), code)
    raw = _read_regular(path, maximum=8_000_000)
    metadata = path.lstat()
    require(
        metadata.st_uid == 0
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == mode,
        code,
    )
    return raw


def _require_protected_file(
    path: Path, *, uid: int, gid: int, mode: int, code: str
) -> bytes:
    require(not _absent(path), code)
    raw = _read_regular(path, maximum=8_000_000)
    metadata = path.lstat()
    require(
        metadata.st_uid == uid
        and metadata.st_gid == gid
        and stat.S_IMODE(metadata.st_mode) == mode,
        code,
    )
    return raw


def _validate_predecessor_receipt(predecessor: Mapping[str, object]) -> None:
    _require_root_directory(RECEIPT_ROOT, mode=0o700, code="attempt_lineage_receipt_rejected")
    matches = tuple(
        sorted(RECEIPT_ROOT.glob(f"*-{str(predecessor['receipt_digest'])[:16]}.json"))
    )
    require(len(matches) == 1, "attempt_lineage_receipt_rejected")
    path = matches[0]
    raw = _require_root_file(path, mode=0o600, code="attempt_lineage_receipt_rejected")
    require(_sha(raw) == predecessor["receipt_file_sha256"], "attempt_lineage_receipt_rejected")
    receipt = _read_canonical(path, maximum=4096)
    supplied = receipt.get("receipt_digest")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    require(
        set(receipt)
        == {
            "schema",
            "status",
            "attempt",
            "bundle_digest",
            "live_plan_digest",
            "activation_failure_gate",
            "rollback_failure_gate",
            "failure_stage",
            "history_preserved",
            "content_free",
            "private_content_read",
            "channel_called",
            "model_called",
            "provider_called",
            "health_called",
            "recorded_at",
            "receipt_digest",
        }
        and receipt["schema"] == predecessor["receipt_schema"]
        and receipt["status"] == predecessor["receipt_status"]
        and receipt["attempt"] == predecessor["receipt_attempt"]
        and receipt["bundle_digest"] == predecessor["bundle_digest"]
        and receipt["live_plan_digest"] == predecessor["live_plan_digest"]
        and receipt["activation_failure_gate"] == predecessor["activation_failure_gate"]
        and receipt["rollback_failure_gate"] == predecessor["rollback_failure_gate"]
        and receipt["failure_stage"] == "verify_default_off_target"
        and isinstance(receipt["recorded_at"], str)
        and receipt["history_preserved"] is True
        and receipt["content_free"] is True
        and all(
            receipt[field] is False
            for field in (
                "private_content_read",
                "channel_called",
                "model_called",
                "provider_called",
                "health_called",
            )
        )
        and supplied == predecessor["receipt_digest"]
        and supplied == digest("myuna-p16-phase1-t2-receipt-v1", unsigned),
        "attempt_lineage_receipt_rejected",
    )


def _validate_predecessor_backup(predecessor: Mapping[str, object]) -> None:
    plan_digest = str(predecessor["live_plan_digest"])
    root = BACKUP_ROOT / plan_digest
    _require_root_directory(root, mode=0o700, code="attempt_lineage_backup_rejected")
    manifest_raw = _require_root_file(
        root / "BACKUP.json", mode=0o600, code="attempt_lineage_backup_rejected"
    )
    require(
        _sha(manifest_raw) == predecessor["backup_manifest_sha256"],
        "attempt_lineage_backup_rejected",
    )
    backup = _load_backup(root, plan_digest)
    require(
        backup["schema"] == predecessor["backup_schema"]
        and backup["backup_digest"] == predecessor["backup_digest"]
        and backup["target_prestate"]
        == {
            "incident_selector": "absent",
            "incident_marker": "absent",
            "p16_telegram_dropin": "absent",
        }
        and backup["history_action"] == "preserve",
        "attempt_lineage_backup_rejected",
    )
    live_plan_raw = _require_root_file(
        root / "LIVE_PLAN.json", mode=0o600, code="attempt_lineage_backup_rejected"
    )
    live_plan = _read_canonical(root / "LIVE_PLAN.json")
    live_plan_unsigned = {
        key: value for key, value in live_plan.items() if key != "live_plan_digest"
    }
    require(
        live_plan_raw == canonical(live_plan) + b"\n"
        and live_plan.get("bundle_digest") == predecessor["bundle_digest"]
        and live_plan.get("live_plan_digest") == plan_digest
        and digest("myuna-p16-phase1-t2-live-plan-v1", live_plan_unsigned)
        == plan_digest,
        "attempt_lineage_backup_rejected",
    )
    expected_names = {"BACKUP.json", "LIVE_PLAN.json"}
    require(isinstance(backup["files"], dict), "attempt_lineage_backup_rejected")
    for record in backup["files"].values():
        require(
            isinstance(record, dict)
            and set(record) == {"backup_name", "source"}
            and isinstance(record["backup_name"], str),
            "attempt_lineage_backup_rejected",
        )
        name = str(record["backup_name"])
        expected_names.add(name)
        saved = root / name
        raw = _require_root_file(saved, mode=0o600, code="attempt_lineage_backup_rejected")
        require(
            _sha(raw) == record["source"]["sha256"],
            "attempt_lineage_backup_rejected",
        )
    require(
        {path.name for path in root.iterdir()} == expected_names,
        "attempt_lineage_backup_rejected",
    )


def _validate_attempt_predecessor(bundle: Mapping[str, object]) -> dict[str, object]:
    try:
        lineage = validate_attempt_lineage(
            bundle["attempt_lineage"],
            {
                key: bundle[key]
                for key in (
                    "schema",
                    "status",
                    "core_source_commit",
                    "deploy_source_commit",
                    "controller_source_sha256",
                    "generation13_base",
                    "artifacts",
                    "compatibility",
                    "content_free",
                )
            },
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise P16Phase1T2Rejected("attempt_lineage_contract_rejected") from exc
    predecessor = lineage["predecessor"]
    _require_root_directory(STATE_ROOT, mode=0o700, code="attempt_lineage_ledger_rejected")
    raw = _require_root_file(
        ATTEMPT_LEDGER, mode=0o600, code="attempt_lineage_ledger_rejected"
    )
    payload = _read_canonical(ATTEMPT_LEDGER, maximum=4096)
    require(
        _sha(raw) == predecessor["ledger_sha256"]
        and set(payload)
        == {"schema", "bundle_digest", "attempts", "last_live_plan_digest"}
        and payload["schema"] == predecessor["ledger_schema"] == ATTEMPT_LEDGER_SCHEMA
        and payload["bundle_digest"] == predecessor["bundle_digest"]
        and payload["attempts"] == predecessor["attempts"] == 1
        and payload["last_live_plan_digest"] == predecessor["live_plan_digest"],
        "attempt_lineage_ledger_rejected",
    )
    _validate_predecessor_receipt(predecessor)
    _validate_predecessor_backup(predecessor)
    return lineage


def _transition_payload(
    bundle: Mapping[str, object],
    lineage: Mapping[str, object],
    live_plan_digest: str,
) -> dict[str, object]:
    predecessor = lineage["predecessor"]
    unsigned = {
        "schema": ATTEMPT_TRANSITION_RECEIPT_SCHEMA,
        "status": "attempt_consumed",
        "attempt_series_id": lineage["attempt_series_id"],
        "from_bundle_digest": predecessor["bundle_digest"],
        "to_bundle_digest": bundle["bundle_digest"],
        "reviewed_repair_bundle_digest": lineage["reviewed_repair_bundle_digest"],
        "from_attempt": 1,
        "to_attempt": 2,
        "previous_live_plan_digest": predecessor["live_plan_digest"],
        "live_plan_digest": live_plan_digest,
        "predecessor_ledger_sha256": predecessor["ledger_sha256"],
        "predecessor_receipt_digest": predecessor["receipt_digest"],
        "predecessor_backup_digest": predecessor["backup_digest"],
        "content_free": True,
        "private_content_read": False,
        "channel_called": False,
        "model_called": False,
        "provider_called": False,
        "health_called": False,
    }
    return {
        **unsigned,
        "transition_digest": digest(
            "myuna-p16-attempt-series-transition-receipt-v1", unsigned
        ),
    }


def _read_transition(
    bundle: Mapping[str, object],
    lineage: Mapping[str, object],
) -> dict[str, object] | None:
    if _absent(ATTEMPT_TRANSITION_ROOT):
        return None
    _require_root_directory(
        ATTEMPT_TRANSITION_ROOT,
        mode=0o700,
        code="attempt_lineage_transition_rejected",
    )
    path = ATTEMPT_TRANSITION_ROOT / "attempt-0002.json"
    require(
        {item.name for item in ATTEMPT_TRANSITION_ROOT.iterdir()}
        == {path.name},
        "attempt_lineage_partial_transition",
    )
    _require_root_file(path, mode=0o600, code="attempt_lineage_transition_rejected")
    receipt = _read_canonical(path, maximum=4096)
    live_plan_digest = receipt.get("live_plan_digest")
    require(
        isinstance(live_plan_digest, str)
        and _HEX64.fullmatch(live_plan_digest) is not None
        and receipt == _transition_payload(bundle, lineage, live_plan_digest),
        "attempt_lineage_transition_rejected",
    )
    return receipt


def _successor_identity(bundle: Mapping[str, object]) -> dict[str, object]:
    return {
        key: bundle[key]
        for key in (
            "schema",
            "status",
            "core_source_commit",
            "deploy_source_commit",
            "controller_source_sha256",
            "generation13_base",
            "artifacts",
            "compatibility",
            "content_free",
        )
    }


def _validate_terminal_predecessor_v1(
    bundle: Mapping[str, object], lineage: Mapping[str, object]
) -> None:
    predecessor = lineage["terminal_predecessor"]
    raw_ledger = _require_root_file(
        ATTEMPT_LEDGER, mode=0o600, code="successor_terminal_ledger_rejected"
    )
    ledger = _read_canonical(ATTEMPT_LEDGER, maximum=4096)
    require(
        _sha(raw_ledger) == predecessor["ledger_sha256"]
        and ledger.get("schema") == predecessor["ledger_schema"]
        and ledger.get("attempts") == 1,
        "successor_terminal_ledger_rejected",
    )

    _require_root_directory(
        ATTEMPT_TRANSITION_ROOT,
        mode=0o700,
        code="successor_terminal_transition_rejected",
    )
    transition_path = ATTEMPT_TRANSITION_ROOT / "attempt-0002.json"
    require(
        {path.name for path in ATTEMPT_TRANSITION_ROOT.iterdir()}
        == {transition_path.name},
        "successor_terminal_transition_rejected",
    )
    transition_raw = _require_root_file(
        transition_path,
        mode=0o600,
        code="successor_terminal_transition_rejected",
    )
    transition = _read_canonical(transition_path, maximum=4096)
    supplied_transition = transition.get("transition_digest")
    transition_unsigned = {
        key: value for key, value in transition.items() if key != "transition_digest"
    }
    require(
        _sha(transition_raw) == predecessor["transition_file_sha256"]
        and transition.get("schema") == predecessor["transition_schema"]
        and transition.get("attempt_series_id") == predecessor["attempt_series_id"]
        and transition.get("to_bundle_digest") == predecessor["bundle_digest"]
        and transition.get("live_plan_digest") == predecessor["live_plan_digest"]
        and transition.get("from_attempt") == 1
        and transition.get("to_attempt") == predecessor["attempts"] == 2
        and supplied_transition == predecessor["transition_digest"]
        and supplied_transition
        == digest("myuna-p16-attempt-series-transition-receipt-v1", transition_unsigned),
        "successor_terminal_transition_rejected",
    )

    _require_root_directory(
        RECEIPT_ROOT, mode=0o700, code="successor_terminal_receipt_rejected"
    )
    receipt_matches = tuple(
        sorted(
            RECEIPT_ROOT.glob(
                f"*-{str(predecessor['activation_receipt_digest'])[:16]}.json"
            )
        )
    )
    require(len(receipt_matches) == 1, "successor_terminal_receipt_rejected")
    receipt_path = receipt_matches[0]
    receipt_raw = _require_root_file(
        receipt_path, mode=0o600, code="successor_terminal_receipt_rejected"
    )
    receipt = _read_canonical(receipt_path, maximum=8192)
    receipt_unsigned = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    require(
        _sha(receipt_raw) == predecessor["activation_receipt_file_sha256"]
        and receipt.get("schema") == predecessor["activation_receipt_schema"]
        and receipt.get("status") == "active_waiting_owner_organic_canary"
        and receipt.get("attempt") == 2
        and receipt.get("bundle_digest") == predecessor["bundle_digest"]
        and receipt.get("live_plan_digest") == predecessor["live_plan_digest"]
        and receipt.get("receipt_digest") == predecessor["activation_receipt_digest"]
        and receipt.get("receipt_digest")
        == digest("myuna-p16-phase1-t2-receipt-v1", receipt_unsigned),
        "successor_terminal_receipt_rejected",
    )

    backup_root = BACKUP_ROOT / str(predecessor["live_plan_digest"])
    backup_raw = _require_root_file(
        backup_root / "BACKUP.json",
        mode=0o600,
        code="successor_terminal_backup_rejected",
    )
    backup = _load_backup(backup_root, str(predecessor["live_plan_digest"]))
    require(
        _sha(backup_raw) == predecessor["activation_backup_manifest_sha256"]
        and backup.get("backup_digest") == predecessor["activation_backup_digest"],
        "successor_terminal_backup_rejected",
    )

    marker_raw = _require_root_file(
        INCIDENT_HISTORY_MARKER,
        mode=0o440,
        code="successor_terminal_marker_rejected",
    )
    telegram_gid = pwd.getpwnam(TELEGRAM_RUNTIME_USER).pw_gid
    selector_raw = _require_protected_file(
        INCIDENT_HISTORY_SELECTOR,
        uid=0,
        gid=telegram_gid,
        mode=0o440,
        code="successor_terminal_selector_rejected",
    )
    dropin_raw = _require_root_file(
        P16_TELEGRAM_DROPIN,
        mode=0o644,
        code="successor_terminal_dropin_rejected",
    )
    marker = _read_canonical(INCIDENT_HISTORY_MARKER, maximum=4096)
    selector = _read_canonical(INCIDENT_HISTORY_SELECTOR, maximum=64_000)
    require(
        _sha(marker_raw) == predecessor["marker_sha256"]
        and marker.get("schema") == predecessor["marker_schema"]
        and marker.get("bundle_digest") == predecessor["bundle_digest"]
        and marker.get("selector_digest") == predecessor["selector_digest"]
        and _sha(selector_raw) == predecessor["selector_sha256"]
        and selector.get("schema") == predecessor["selector_schema"]
        and selector.get("bundle_digest") == predecessor["bundle_digest"]
        and digest("myuna-p16-incident-history-selector-v1", selector)
        == predecessor["selector_digest"]
        and _sha(dropin_raw) == predecessor["dropin_sha256"],
        "successor_terminal_active_binding_rejected",
    )


def _validate_terminal_predecessor_v2(
    bundle: Mapping[str, object], lineage: Mapping[str, object]
) -> None:
    """Validate the exact active successor without mutating its series."""

    predecessor = lineage["terminal_predecessor"]
    context = _load_bundle_context(ACTIVE_PREDECESSOR_BUNDLE_ROOT)
    active_bundle = context["bundle"]
    try:
        active_lineage = validate_attempt_lineage(
            active_bundle["attempt_lineage"], _successor_identity(active_bundle)
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise P16Phase1T2Rejected("successor_predecessor_bundle_rejected") from exc
    manifest_raw = _read_regular(
        ACTIVE_PREDECESSOR_BUNDLE_ROOT / "P16_PHASE1_T2_BUNDLE.json",
        maximum=1_000_000,
    )
    require(
        active_bundle["bundle_digest"] == predecessor["bundle_digest"]
        and _sha(manifest_raw) == predecessor["bundle_manifest_sha256"]
        and active_lineage["schema"] == predecessor["lineage_schema"]
        and active_lineage["lineage_digest"] == predecessor["lineage_digest"]
        and active_lineage["attempt_series_id"] == predecessor["attempt_series_id"]
        and active_lineage["strategy_id"] == predecessor["strategy_id"]
        and active_bundle["core_source_commit"] == predecessor["active_core_source_commit"]
        and active_bundle["deploy_source_commit"] == predecessor["active_deploy_source_commit"],
        "successor_predecessor_bundle_rejected",
    )

    predecessor_attempts = _read_successor_attempts(active_bundle, active_lineage)
    require(
        len(predecessor_attempts) == predecessor["attempts"] == 1
        and predecessor["maximum_attempts"] == 2
        and predecessor_attempts[0]["attempt_digest"] == predecessor["attempt_digest"],
        "successor_predecessor_attempt_rejected",
    )
    attempt_path = SUCCESSOR_STATE_ROOT / "attempt-0001.json"
    attempt_raw = _require_root_file(
        attempt_path, mode=0o600, code="successor_predecessor_attempt_rejected"
    )
    require(
        _sha(attempt_raw) == predecessor["attempt_file_sha256"],
        "successor_predecessor_attempt_rejected",
    )

    _require_root_directory(
        RECEIPT_ROOT, mode=0o700, code="successor_predecessor_receipt_rejected"
    )
    receipt_matches = tuple(
        sorted(
            RECEIPT_ROOT.glob(
                f"*-{str(predecessor['activation_receipt_digest'])[:16]}.json"
            )
        )
    )
    require(len(receipt_matches) == 1, "successor_predecessor_receipt_rejected")
    receipt_path = receipt_matches[0]
    receipt_raw = _require_root_file(
        receipt_path, mode=0o600, code="successor_predecessor_receipt_rejected"
    )
    receipt = _read_canonical(receipt_path, maximum=64_000)
    receipt_unsigned = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    require(
        _sha(receipt_raw) == predecessor["activation_receipt_file_sha256"]
        and receipt.get("schema") == predecessor["activation_receipt_schema"]
        and receipt.get("status") == "active_waiting_owner_organic_canary"
        and receipt.get("attempt") == 1
        and receipt.get("attempt_series_id") == predecessor["attempt_series_id"]
        and receipt.get("bundle_digest") == predecessor["bundle_digest"]
        and receipt.get("live_plan_digest") == predecessor["live_plan_digest"]
        and receipt.get("receipt_digest") == predecessor["activation_receipt_digest"]
        and receipt.get("receipt_digest")
        == digest("myuna-p16-phase1-t2-receipt-v1", receipt_unsigned),
        "successor_predecessor_receipt_rejected",
    )

    backup_root = BACKUP_ROOT / str(predecessor["live_plan_digest"])
    _require_root_directory(
        backup_root, mode=0o700, code="successor_predecessor_backup_rejected"
    )
    backup_raw = _require_root_file(
        backup_root / "BACKUP.json",
        mode=0o600,
        code="successor_predecessor_backup_rejected",
    )
    backup = _load_backup(backup_root, str(predecessor["live_plan_digest"]))
    expected_backup_names = {"BACKUP.json", "LIVE_PLAN.json"}
    for record in backup["files"].values():
        backup_name = str(record["backup_name"])
        expected_backup_names.add(backup_name)
        saved_raw = _require_root_file(
            backup_root / backup_name,
            mode=0o600,
            code="successor_predecessor_backup_rejected",
        )
        require(
            _sha(saved_raw) == record["source"]["sha256"],
            "successor_predecessor_backup_rejected",
        )
    require(
        _sha(backup_raw) == predecessor["activation_backup_manifest_sha256"]
        and backup.get("schema") == predecessor["activation_backup_schema"]
        and backup.get("backup_digest") == predecessor["activation_backup_digest"]
        and {path.name for path in backup_root.iterdir()} == expected_backup_names,
        "successor_predecessor_backup_rejected",
    )

    telegram_identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    marker = _file_projection(INCIDENT_HISTORY_MARKER)
    selector = _file_projection(INCIDENT_HISTORY_SELECTOR)
    dropin = _file_projection(P16_TELEGRAM_DROPIN)
    marker_doc = _read_canonical(INCIDENT_HISTORY_MARKER, maximum=4096)
    selector_doc = _read_canonical(INCIDENT_HISTORY_SELECTOR, maximum=64_000)
    selector_digest = digest("myuna-p16-incident-history-selector-v1", selector_doc)
    require(
        marker["uid"] == marker["gid"] == 0
        and marker["mode"] == "0440"
        and marker["sha256"] == predecessor["marker_sha256"]
        and selector["uid"] == 0
        and selector["gid"] == telegram_identity.pw_gid
        and selector["mode"] == "0440"
        and selector["sha256"] == predecessor["selector_sha256"]
        and selector_digest == predecessor["selector_digest"]
        and dropin["uid"] == dropin["gid"] == 0
        and dropin["mode"] == "0644"
        and dropin["sha256"] == predecessor["dropin_sha256"]
        and marker_doc.get("bundle_digest") == predecessor["bundle_digest"]
        and marker_doc.get("selector_digest") == predecessor["selector_digest"]
        and selector_doc.get("bundle_digest") == predecessor["bundle_digest"],
        "successor_predecessor_active_binding_rejected",
    )

    services = {
        "core": _service_projection(CORE_SERVICE),
        "telegram": _service_projection(TELEGRAM_SERVICE),
        "telegram_socket": _service_projection(TELEGRAM_SOCKET, socket=True),
        "p08": _service_projection(P08_SERVICE),
        "p08_socket": _service_projection(P08_SOCKET, socket=True),
    }
    service_digest_fields = {
        "core": "core_service_binding_digest",
        "telegram": "telegram_service_binding_digest",
        "telegram_socket": "telegram_socket_binding_digest",
        "p08": "p08_service_binding_digest",
        "p08_socket": "p08_socket_binding_digest",
    }
    for name, projection in services.items():
        _require_active(projection, socket=name.endswith("socket"))
        require(
            projection["binding_digest"] == predecessor[service_digest_fields[name]],
            "successor_predecessor_service_binding_rejected",
        )
    selected_core = legacy_p16._selected_core_release(
        str(services["core"]["working_directory"])
    ).name
    selected_runtime = legacy_p16._selected_gateway_release(
        str(services["telegram"]["exec_start"]), channel="telegram"
    ).name
    require(
        selected_core == predecessor["active_core_release_digest"]
        and selected_runtime == predecessor["active_runtime_release_digest"]
        and _selected_plugin_digest() == predecessor["active_plugin_release_digest"]
        and active_bundle["artifacts"]["p16_adapter"]["release_digest"]
        == predecessor["active_adapter_release_digest"],
        "successor_predecessor_release_selection_rejected",
    )
    history = _history_projection(telegram_identity.pw_uid, telegram_identity.pw_gid)
    history_files = history["channel"].get("files", {})
    require(
        set(history_files) == {"history-v1.json"}
        and history_files["history-v1.json"]["sha256"]
        == predecessor["history_file_sha256"]
        and history_files["history-v1.json"]["size"]
        == predecessor["history_file_size"],
        "successor_predecessor_history_rejected",
    )


def _validate_terminal_predecessor(
    bundle: Mapping[str, object], lineage: Mapping[str, object]
) -> None:
    if lineage.get("schema") == ATTEMPT_LINEAGE_SCHEMA_V1:
        _validate_terminal_predecessor_v1(bundle, lineage)
        return
    _validate_terminal_predecessor_v2(bundle, lineage)


def _successor_attempt_payload(
    bundle: Mapping[str, object],
    lineage: Mapping[str, object],
    *,
    attempt: int,
    live_plan_digest: str,
    previous_attempt_digest: str | None,
    recorded_at: str,
) -> dict[str, object]:
    is_legacy = lineage["schema"] == ATTEMPT_LINEAGE_SCHEMA_V1
    predecessor = lineage["terminal_predecessor"]
    unsigned = {
        "schema": (
            ATTEMPT_TRANSITION_RECEIPT_SCHEMA_V1
            if is_legacy
            else ATTEMPT_TRANSITION_RECEIPT_SCHEMA
        ),
        "status": "attempt_consumed",
        "recorded_at": recorded_at,
        "attempt_series_id": lineage["attempt_series_id"],
        "strategy_id": lineage["strategy_id"],
        "bundle_digest": bundle["bundle_digest"],
        "attempt": attempt,
        "maximum_attempts": lineage["maximum_attempts"],
        "live_plan_digest": live_plan_digest,
        "previous_attempt_digest": previous_attempt_digest,
        "terminal_lineage_digest": lineage["lineage_digest"],
        "content_free": True,
        "private_content_read": False,
        "channel_called": False,
        "model_called": False,
        "provider_called": False,
        "health_called": False,
    }
    if not is_legacy:
        unsigned.update(
            {
                "predecessor_snapshot_digest": lineage["predecessor_snapshot_digest"],
                "predecessor_attempt_series_id": predecessor["attempt_series_id"],
                "predecessor_attempt_digest": predecessor["attempt_digest"],
                "predecessor_remaining_attempts_retired": lineage[
                    "predecessor_remaining_attempts_retired"
                ],
                "strategy_relation": lineage["strategy_relation"],
                "strategy_change_digest": lineage["strategy_change_digest"],
            }
        )
    domain = (
        "myuna-p16-successor-attempt-consumption-receipt-v1"
        if is_legacy
        else "myuna-p16-successor-attempt-consumption-receipt-v2"
    )
    return {
        **unsigned,
        "attempt_digest": digest(domain, unsigned),
    }


def _successor_state_root(lineage: Mapping[str, object]) -> Path:
    if (
        lineage.get("schema") == ATTEMPT_LINEAGE_SCHEMA_V1
        and lineage.get("state_namespace") == "p16-successor-attempt-series-v1"
    ):
        return SUCCESSOR_STATE_ROOT
    if (
        lineage.get("schema") != ATTEMPT_LINEAGE_SCHEMA_V1
        and lineage.get("state_namespace")
        == "p16-projection-budget-attempt-series-v1"
    ):
        return PROJECTION_BUDGET_SUCCESSOR_STATE_ROOT
    raise P16Phase1T2Rejected("successor_attempt_namespace_rejected")


def _read_successor_attempts(
    bundle: Mapping[str, object], lineage: Mapping[str, object]
) -> list[dict[str, object]]:
    state_root = _successor_state_root(lineage)
    if _absent(state_root):
        return []
    _require_root_directory(
        state_root,
        mode=0o700,
        code="successor_attempt_series_rejected",
    )
    names = {path.name for path in state_root.iterdir()}
    expected_names = {
        f"attempt-{number:04d}.json" for number in range(1, len(names) + 1)
    }
    require(
        names == expected_names and 1 <= len(names) <= MAX_ATTEMPTS,
        "successor_attempt_series_partial",
    )
    result: list[dict[str, object]] = []
    previous: str | None = None
    for number in range(1, len(names) + 1):
        path = state_root / f"attempt-{number:04d}.json"
        _require_root_file(path, mode=0o600, code="successor_attempt_series_rejected")
        receipt = _read_canonical(path, maximum=4096)
        supplied = receipt.get("attempt_digest")
        recorded_at = receipt.get("recorded_at")
        live_plan_digest = receipt.get("live_plan_digest")
        expected = None
        if isinstance(recorded_at, str) and isinstance(live_plan_digest, str):
            expected = _successor_attempt_payload(
                bundle,
                lineage,
                attempt=number,
                live_plan_digest=live_plan_digest,
                previous_attempt_digest=previous,
                recorded_at=recorded_at,
            )
        require(
            receipt == expected
            and receipt.get("attempt_series_id") == lineage["attempt_series_id"]
            and receipt.get("strategy_id") == lineage["strategy_id"]
            and receipt.get("bundle_digest") == bundle["bundle_digest"]
            and receipt.get("attempt") == number
            and receipt.get("maximum_attempts") == MAX_ATTEMPTS
            and receipt.get("previous_attempt_digest") == previous
            and receipt.get("terminal_lineage_digest") == lineage["lineage_digest"]
            and isinstance(recorded_at, str)
            and isinstance(live_plan_digest, str)
            and _HEX64.fullmatch(str(receipt["live_plan_digest"])) is not None
            and supplied == expected["attempt_digest"],
            "successor_attempt_series_rejected",
        )
        previous = str(supplied)
        result.append(receipt)
    return result


def _successor_activation_receipt_attempts(
    bundle: Mapping[str, object], lineage: Mapping[str, object]
) -> set[int]:
    if _absent(SUCCESSOR_RECEIPT_ROOT):
        return set()
    _require_root_directory(
        SUCCESSOR_RECEIPT_ROOT,
        mode=0o700,
        code="successor_attempt_receipt_rejected",
    )
    attempts: list[int] = []
    for path in sorted(SUCCESSOR_RECEIPT_ROOT.glob("*.json")):
        receipt = _read_canonical(path, maximum=64_000)
        if receipt.get("attempt_series_id") != lineage["attempt_series_id"]:
            continue
        supplied = receipt.get("receipt_digest")
        unsigned = {
            key: value for key, value in receipt.items() if key != "receipt_digest"
        }
        attempt = receipt.get("attempt")
        require(
            receipt.get("schema") == ACTIVATION_RECEIPT_SCHEMA
            and receipt.get("bundle_digest") == bundle["bundle_digest"]
            and receipt.get("strategy_id") == lineage["strategy_id"]
            and type(attempt) is int
            and 1 <= attempt <= MAX_ATTEMPTS
            and supplied == digest("myuna-p16-phase1-t2-receipt-v1", unsigned),
            "successor_attempt_receipt_rejected",
        )
        attempts.append(attempt)
    require(len(attempts) == len(set(attempts)), "successor_attempt_receipt_rejected")
    return set(attempts)


def _attempt_projection(bundle: Mapping[str, object]) -> dict[str, object]:
    try:
        lineage = validate_attempt_lineage(bundle["attempt_lineage"], _successor_identity(bundle))
    except (KeyError, TypeError, ValueError) as exc:
        raise P16Phase1T2Rejected("successor_attempt_lineage_rejected") from exc
    _validate_terminal_predecessor(bundle, lineage)
    attempts = _read_successor_attempts(bundle, lineage)
    activation_attempts = _successor_activation_receipt_attempts(bundle, lineage)
    require(
        not activation_attempts
        or max(activation_attempts) <= len(attempts),
        "successor_attempt_series_reset_rejected",
    )
    return {
        "attempt_series_id": lineage["attempt_series_id"],
        "attempts": len(attempts),
        "maximum_attempts": MAX_ATTEMPTS,
        "series_state": "absent" if not attempts else "present_exact",
        "terminal_attempt_digest": None if not attempts else attempts[-1]["attempt_digest"],
        "activation_receipts": len(activation_attempts),
    }


def _attempt_count(bundle: Mapping[str, object]) -> int:
    return int(_attempt_projection(bundle)["attempts"])


def _consume_attempt(bundle: Mapping[str, object], live_plan_digest: str) -> int:
    require(
        isinstance(live_plan_digest, str)
        and _HEX64.fullmatch(live_plan_digest) is not None,
        "attempt_lineage_plan_rejected",
    )
    try:
        descriptor = os.open(
            ATTEMPT_LOCK,
            os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise P16Phase1T2Rejected("attempt_lineage_lock_rejected") from exc
    locked = False
    try:
        lock_metadata = os.fstat(descriptor)
        require(
            stat.S_ISREG(lock_metadata.st_mode)
            and lock_metadata.st_uid == 0
            and lock_metadata.st_gid == 0
            and stat.S_IMODE(lock_metadata.st_mode) == 0o600,
            "attempt_lineage_lock_rejected",
        )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        projection = _attempt_projection(bundle)
        require(
            projection["attempts"] < MAX_ATTEMPTS,
            "live_attempt_budget_exhausted",
        )
        attempt = int(projection["attempts"]) + 1
        state_root = _successor_state_root(bundle["attempt_lineage"])
        if attempt == 1:
            require(_absent(state_root), "successor_attempt_series_rejected")
            state_root.mkdir(mode=0o700, exist_ok=False)
            os.chown(state_root, 0, 0)
            os.chmod(state_root, 0o700)
            _fsync_directory(state_root.parent)
        lineage = bundle["attempt_lineage"]
        previous = projection["terminal_attempt_digest"]
        payload = _successor_attempt_payload(
            bundle,
            lineage,
            attempt=attempt,
            live_plan_digest=live_plan_digest,
            previous_attempt_digest=None if previous is None else str(previous),
            recorded_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        _atomic_write(
            state_root / f"attempt-{attempt:04d}.json",
            canonical(payload) + b"\n",
            mode=0o600,
            exclusive=True,
        )
        require(
            _attempt_projection(bundle)["attempts"] == attempt,
            "successor_attempt_series_rejected",
        )
        return attempt
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _selected_plugin_digest() -> str:
    payload = _read_canonical_legacy(TELEGRAM_CONFIG, maximum=64_000)
    value = payload.get("gateway_release")
    require(isinstance(value, str) and _HEX64.fullmatch(value) is not None, "plugin_selection_rejected")
    return value


def _p08_selection(expected_release: str, expected_plan: str) -> dict[str, object]:
    selector = _read_canonical(p08_activation.SELECTOR_JSON, maximum=64_000)
    expected_fields = {
        "schema",
        "plan_digest",
        "release_digest",
        "release_path",
        "core_commit",
        "deploy_commit",
        "gateway_manifest_digest",
        "gateway_client_sha256",
        "plugin_digest",
    }
    release_path = Path(str(selector.get("release_path", "")))
    require(
        set(selector) == expected_fields
        and selector["schema"] == p08_activation.SELECTOR_SCHEMA
        and selector["plan_digest"] == expected_plan
        and selector["release_digest"] == expected_release
        and release_path.is_absolute()
        and release_path.name == expected_release,
        "generation13_p08_selection_drifted",
    )
    return {
        "release_digest": expected_release,
        "selector": _file_projection(p08_activation.SELECTOR_JSON),
    }


def _p07_snapshot(expected_release_set_id: str) -> object:
    snapshot = load_protected_release_set_snapshot(RELEASE_SET_PATH, expected_uid=0, expected_gid=0)
    selected = snapshot.release_set
    require(
        selected.release_set_id == expected_release_set_id
        and selected.generation == 13
        and selected.epoch["database_path"] == RELEASE_SET_EPOCH_PATH,
        "generation13_release_set_drifted",
    )
    return selected


def _readiness_projection(
    release_set: object,
    telegram: Mapping[str, object],
    *,
    wait_for_process: bool = False,
    timeout_seconds: float = 30.0,
    poll_seconds: float = 0.25,
    stable_seconds: float = 5.0,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    require(
        0 < poll_seconds <= 1
        and 0 <= stable_seconds <= 60
        and timeout_seconds >= stable_seconds,
        "runtime_readiness_window_rejected",
    )
    telegram_identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    deadline = monotonic() + timeout_seconds
    while True:
        if wait_for_process and monotonic() > deadline:
            raise P16Phase1T2Rejected("runtime_readiness_process_timeout")
        current = _service_projection(TELEGRAM_SERVICE) if wait_for_process else telegram
        if wait_for_process:
            _require_active(current)
            require(
                current["pid"] == telegram["pid"]
                and current["invocation_id"] == telegram["invocation_id"]
                and current["nrestarts"] == telegram["nrestarts"]
                and current["binding_digest"] == telegram["binding_digest"],
                "runtime_startup_identity_drifted",
            )
        try:
            receipt = inspect_runtime_readiness(
                readiness_path(RELEASE_SET_EPOCH_PATH),
                expected_uid=telegram_identity.pw_uid,
                expected_gid=telegram_identity.pw_gid,
                expected_generation=13,
                expected_release_set_id=release_set.release_set_id,
                expected_epoch_id=release_set.epoch["epoch_id"],
                expected_database_path=RELEASE_SET_EPOCH_PATH,
                expected_selector_digest=release_set.selector["digest"],
                expected_runtime_config_digest=release_set.runtime_config["digest"],
            )
        except RuntimeReadinessRejected as exc:
            if not wait_for_process or exc.code != "runtime_readiness_absent":
                raise
            receipt = None
        if receipt is not None and (
            receipt.pid == telegram["pid"]
            and receipt.invocation_id == telegram["invocation_id"]
        ):
            break
        if not wait_for_process:
            raise P16Phase1T2Rejected("runtime_readiness_process_mismatch")
        if monotonic() >= deadline:
            raise P16Phase1T2Rejected("runtime_readiness_process_timeout")
        sleep(poll_seconds)
    if wait_for_process:
        sleep(stable_seconds)
        final = _service_projection(TELEGRAM_SERVICE)
        _require_active(final)
        require(
            final["pid"] == telegram["pid"]
            and final["invocation_id"] == telegram["invocation_id"]
            and final["nrestarts"] == telegram["nrestarts"]
            and final["binding_digest"] == telegram["binding_digest"],
            "runtime_readiness_not_stable",
        )
    return {
        "schema": "myuna.p07-d-runtime-readiness.v1",
        "generation": receipt.generation,
        "release_set_id": receipt.release_set_id,
        "selector_digest": receipt.selector_digest,
        "runtime_config_digest": receipt.runtime_config_digest,
        "epoch_metadata_digest": receipt.epoch_metadata_digest,
        "process_binding_digest": digest(
            "myuna-p16-phase1-t2-readiness-process-v1",
            {"invocation_id": receipt.invocation_id, "pid": receipt.pid},
        ),
    }


def _history_projection(telegram_uid: int, telegram_gid: int) -> dict[str, object]:
    root = _directory_projection(
        INCIDENT_HISTORY_ROOT,
        uid=0,
        gid=0,
        mode=0o751,
        allow_absent=True,
    )
    channel = _directory_projection(
        INCIDENT_HISTORY_ROOT / "telegram",
        uid=telegram_uid,
        gid=telegram_gid,
        mode=0o700,
        allow_absent=True,
    ) if root["state"] != "absent" else {"state": "absent"}
    if channel["state"] == "present_exact":
        entries = tuple(sorted(path.name for path in (INCIDENT_HISTORY_ROOT / "telegram").iterdir()))
        require(set(entries).issubset({"history-v1.json"}), "history_inventory_rejected")
        files: dict[str, object] = {}
        for name in entries:
            path = INCIDENT_HISTORY_ROOT / "telegram" / name
            projection = _file_projection(path)
            expected_mode = "0640"
            require(
                projection["uid"] == telegram_uid
                and projection["gid"] == telegram_gid
                and projection["mode"] == expected_mode
                and projection["size"] <= 8_000_000,
                "history_file_rejected",
            )
            files[name] = projection
        channel = {**channel, "files": files}
    return {"root": root, "channel": channel}


def _live_context(bundle_context: Mapping[str, object], core_source_root: Path, deploy_source_root: Path) -> dict[str, object]:
    require(os.geteuid() == 0, "root_identity_required")
    bundle = bundle_context["bundle"]
    base = bundle["generation13_base"]
    compatibility = bundle["compatibility"]
    terminal = bundle["attempt_lineage"]["terminal_predecessor"]
    telegram_identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    core_identity = pwd.getpwnam("myuna")
    require(grp.getgrnam(TELEGRAM_RUNTIME_USER).gr_gid == telegram_identity.pw_gid, "telegram_identity_rejected")

    source = {
        "core": _git_identity(core_source_root, str(bundle["core_source_commit"])),
        "deploy": _git_identity(deploy_source_root, str(bundle["deploy_source_commit"])),
    }
    controller_source = deploy_source_root / "scripts/activate_p16_phase1_t2_v1.py"
    require(
        _sha(_read_regular(controller_source, maximum=2_000_000))
        == bundle["controller_source_sha256"],
        "controller_source_drifted",
    )
    source["controller_source_sha256"] = bundle["controller_source_sha256"]
    services = {
        "core": _service_projection(CORE_SERVICE),
        "telegram": _service_projection(TELEGRAM_SERVICE),
        "telegram_socket": _service_projection(TELEGRAM_SOCKET, socket=True),
        "p08": _service_projection(P08_SERVICE),
        "p08_socket": _service_projection(P08_SOCKET, socket=True),
    }
    for name, projection in services.items():
        _require_active(projection, socket=name.endswith("socket"))

    selected_core = legacy_p16._selected_core_release(str(services["core"]["working_directory"]))
    selected_runtime = legacy_p16._selected_gateway_release(
        str(services["telegram"]["exec_start"]), channel="telegram"
    )
    require(
        selected_core.name == terminal["active_core_release_digest"],
        "successor_prestate_core_selection_drifted",
    )
    require(
        selected_runtime.name == terminal["active_runtime_release_digest"],
        "successor_prestate_runtime_selection_drifted",
    )
    require(
        _selected_plugin_digest() == terminal["active_plugin_release_digest"],
        "successor_prestate_plugin_selection_drifted",
    )
    p08_selection = _p08_selection(
        str(base["p08_release_digest"]), str(compatibility["p08_plan_digest"])
    )

    release_set = _p07_snapshot(str(compatibility["p07_release_set_id"]))
    require(
        release_set.core["release_digest"] == base["core_release_digest"]
        and release_set.telegram_runtime["release_digest"] == base["runtime_release_digest"]
        and _load_v6_release() == compatibility["effective_definition_id"],
        "generation13_compatibility_drifted",
    )
    require(_sha(_read_regular(P07_SELECTOR, maximum=64_000)) == release_set.selector["digest"], "generation13_selector_drifted")
    require(_sha(_read_regular(OWNER_RUNTIME_CONFIG, maximum=64_000)) == release_set.runtime_config["digest"], "generation13_runtime_config_drifted")

    binding_bytes = _read_regular(CORE_BINDING, maximum=64_000)
    try:
        binding = legacy_p16.load_runtime_binding(legacy_p16.parse_json_document(binding_bytes))
    except Exception as exc:
        raise P16Phase1T2Rejected("core_binding_rejected") from exc
    require(
        binding.selected_release.tree_sha256 == selected_core.name,
        "core_binding_selection_drifted",
    )
    core_selector_bytes = _read_regular(CORE_SELECTOR, maximum=64_000)
    core_guard_bytes = _read_regular(legacy_p16.CORE_GUARD, maximum=64_000)
    require(
        binding.selector_dropin_sha256 == _sha(core_selector_bytes)
        and binding.guard_dropin_sha256 == _sha(core_guard_bytes),
        "core_binding_digest_drifted",
    )

    _validate_terminal_predecessor(bundle, bundle["attempt_lineage"])
    plugin_release = PLUGIN_ROOT / str(base["plugin_release_digest"])
    require(plugin_release.is_dir() and not plugin_release.is_symlink(), "generation13_plugin_artifact_rejected")
    _validate_artifact(
        plugin_release,
        bundle_context["inventories"]["telegram_plugin"],
        str(base["plugin_release_digest"]),
        int(bundle["artifacts"]["telegram_plugin"]["file_count"]),
    )
    artifact_targets: dict[str, object] = {}
    for name, parent in (
        ("core", CORE_RELEASE_ROOT),
        ("telegram_runtime", RUNTIME_ROOT),
        ("p16_adapter", ADAPTER_RELEASE_ROOT),
    ):
        target = parent / str(bundle["artifacts"][name]["release_digest"])
        if _absent(target):
            artifact_targets[name] = {"state": "absent"}
        else:
            _validate_artifact(
                target,
                bundle_context["inventories"][name],
                str(bundle["artifacts"][name]["release_digest"]),
                int(bundle["artifacts"][name]["file_count"]),
            )
            artifact_targets[name] = {"state": "present_exact"}
    readiness = _readiness_projection(release_set, services["telegram"])
    history = _history_projection(telegram_identity.pw_uid, telegram_identity.pw_gid)
    attempts = _attempt_count(bundle)
    require(attempts < MAX_ATTEMPTS, "live_attempt_budget_exhausted")

    files = {
        "core_binding": _file_projection(CORE_BINDING),
        "core_selector": _file_projection(CORE_SELECTOR),
        "core_guard": _file_projection(legacy_p16.CORE_GUARD),
        "p07_core_gate": _file_projection(P07_CORE_GATE),
        "generation13_telegram_dropin": _file_projection(GENERATION13_TELEGRAM_DROPIN),
        "p07_selector": _file_projection(P07_SELECTOR),
        "p07_release_set": _file_projection(RELEASE_SET_PATH),
        "runtime_config": _file_projection(OWNER_RUNTIME_CONFIG),
        "plugin_config": _file_projection(TELEGRAM_CONFIG),
        "effective_v6": _file_projection(EFFECTIVE_V6_ENV),
        "p08_selector": p08_selection["selector"],
        "incident_selector": _file_projection(INCIDENT_HISTORY_SELECTOR),
        "incident_marker": _file_projection(INCIDENT_HISTORY_MARKER),
        "p16_telegram_dropin": _file_projection(P16_TELEGRAM_DROPIN),
    }
    return {
        "source": source,
        "services": services,
        "selected": {
            "core": selected_core.name,
            "telegram_runtime": selected_runtime.name,
            "telegram_plugin": base["plugin_release_digest"],
            "p08": p08_selection["release_digest"],
        },
        "compatibility": {
            "combined_release_set_id": compatibility["combined_release_set_id"],
            "p07_release_set_id": release_set.release_set_id,
            "effective_definition_id": compatibility["effective_definition_id"],
            "generation": 13,
            "epoch_schema": compatibility["epoch_schema"],
        },
        "readiness": readiness,
        "files": files,
        "history": history,
        "artifact_targets": artifact_targets,
        "attempts": attempts,
        "identities": {
            "core_uid": core_identity.pw_uid,
            "core_gid": core_identity.pw_gid,
            "telegram_uid": telegram_identity.pw_uid,
            "telegram_gid": telegram_identity.pw_gid,
        },
        "current_binding": binding,
        "current_binding_bytes": binding_bytes,
    }


def _public_service_projection(value: Mapping[str, object]) -> dict[str, object]:
    return {
        "binding_projection": SERVICE_BINDING_PROJECTION,
        **{
            key: value[key]
            for key in (
                "active_state",
                "sub_state",
                "result",
                "nrestarts",
                "pid",
                "invocation_id",
                "binding_digest",
            )
        },
    }


def _build_live_plan(bundle_context: Mapping[str, object], live: Mapping[str, object]) -> dict[str, object]:
    bundle = bundle_context["bundle"]
    artifacts = bundle["artifacts"]
    unsigned = {
        "schema": LIVE_PLAN_SCHEMA,
        "status": "ready_default_off",
        "bundle_digest": bundle["bundle_digest"],
        "source": live["source"],
        "target_artifacts": {
            name: artifacts[name]["release_digest"]
            for name in ("core", "telegram_runtime", "telegram_plugin", "p16_adapter")
        },
        "prestate": {
            "selected": live["selected"],
            "compatibility": live["compatibility"],
            "services": {
                name: _public_service_projection(projection)
                for name, projection in live["services"].items()
            },
            "readiness": live["readiness"],
            "files": live["files"],
            "history": live["history"],
            "artifact_targets": live["artifact_targets"],
            "incident_selector": live["files"]["incident_selector"],
            "incident_marker": live["files"]["incident_marker"],
            "p16_telegram_dropin": live["files"]["p16_telegram_dropin"],
        },
        "activation": {
            "selector_then_marker": True,
            "marker_created_last": True,
            "dropin_path_order": "after_generation13",
            "public_reply_contract": "unchanged",
            "channel": "telegram_owner_private_only",
            "attempts_consumed": live["attempts"],
            "attempts_maximum": MAX_ATTEMPTS,
        },
        "rollback": {
            "marker_removed_first": True,
            "restore_core_and_telegram_prestate": True,
            "preserve_history": True,
            "preserve_installed_artifacts": True,
            "preserve_receipts_backups_and_attempt_ledger": True,
        },
        "content_free": True,
        "private_content_read": False,
        "channel_called": False,
        "model_called": False,
        "provider_called": False,
        "health_called": False,
        "mutation_performed": False,
    }
    return {
        **unsigned,
        "live_plan_digest": digest("myuna-p16-phase1-t2-live-plan-v1", unsigned),
    }


def prepare_live(
    *,
    bundle_root: Path,
    core_source_root: Path,
    deploy_source_root: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    bundle_context = _load_bundle_context(bundle_root)
    live = _live_context(bundle_context, core_source_root, deploy_source_root)
    plan = _build_live_plan(bundle_context, live)
    return bundle_context, live, plan


def preflight_live(
    *,
    bundle_root: Path,
    core_source_root: Path,
    deploy_source_root: Path,
) -> dict[str, object]:
    _bundle, _live, plan = prepare_live(
        bundle_root=bundle_root,
        core_source_root=core_source_root,
        deploy_source_root=deploy_source_root,
    )
    return plan


def _render_telegram_dropin(core: Path, runtime: Path) -> bytes:
    return (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/python3 {runtime}/runtime/telegram_owner_runtime_gateway.py\n"
        f"Environment=PYTHONPATH={core}/src:{runtime}/runtime\n"
        f"ReadWritePaths={INCIDENT_HISTORY_ROOT / 'telegram'}\n"
    ).encode("ascii")


def _marker_payload(bundle_digest: str, selector_digest: str) -> bytes:
    return canonical(
        {
            "schema": MARKER_SCHEMA,
            "status": "enabled",
            "bundle_digest": bundle_digest,
            "selector_digest": selector_digest,
        }
    ) + b"\n"


def _mkdir_exact(path: Path, *, uid: int, gid: int, mode: int) -> None:
    if _absent(path):
        path.mkdir(parents=True, exist_ok=False)
    require(path.is_dir() and not path.is_symlink(), "protected_directory_rejected")
    os.chown(path, uid, gid)
    os.chmod(path, mode)
    _fsync_directory(path.parent)
    _directory_projection(path, uid=uid, gid=gid, mode=mode, allow_absent=False)


def _install_artifact(
    source: Path,
    destination_root: Path,
    inventory: Mapping[str, object],
    *,
    gid: int,
) -> Path:
    if _absent(destination_root):
        destination_root.mkdir(parents=True, exist_ok=False)
        os.chown(destination_root, 0, gid)
        os.chmod(destination_root, 0o550)
    else:
        metadata = destination_root.lstat()
        require(
            not destination_root.is_symlink()
            and stat.S_ISDIR(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) & 0o002 == 0,
            "artifact_release_root_rejected",
        )
    destination = destination_root / source.name
    if destination.exists() or destination.is_symlink():
        _validate_artifact(destination, inventory, source.name, len(inventory["files"]))
        return destination
    temporary = Path(tempfile.mkdtemp(prefix=f".{source.name[:12]}-", dir=destination_root))
    shutil.copytree(source, temporary, dirs_exist_ok=True, symlinks=False)
    for path in [temporary, *temporary.rglob("*")]:
        require(not path.is_symlink(), "artifact_symlink_rejected")
        os.chown(path, 0, gid)
        os.chmod(path, 0o550 if path.is_dir() else 0o440)
    _fsync_directory(temporary)
    os.replace(temporary, destination)
    _fsync_directory(destination_root)
    _validate_artifact(destination, inventory, source.name, len(inventory["files"]))
    return destination


def _backup_file(root: Path, name: str, source: Path) -> dict[str, object]:
    projection = _file_projection(source)
    _atomic_write(root / name, _read_regular(source, maximum=8_000_000), mode=0o600, exclusive=True)
    return {"backup_name": name, "source": projection}


def _create_backup(plan: Mapping[str, object]) -> Path:
    root = BACKUP_ROOT / str(plan["live_plan_digest"])
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(BACKUP_ROOT, 0, 0)
    os.chmod(BACKUP_ROOT, 0o700)
    require(_absent(root), "activation_backup_preexisting")
    root.mkdir(mode=0o700)
    os.chown(root, 0, 0)
    manifest = {
        "schema": "myuna.p16-phase1-t2-backup.v1",
        "live_plan_digest": plan["live_plan_digest"],
        "files": {
            "core_binding": _backup_file(root, "CORE_BINDING", CORE_BINDING),
            "core_selector": _backup_file(root, "CORE_SELECTOR", CORE_SELECTOR),
            "core_guard": _backup_file(
                root, "CORE_RELEASE_GUARD", legacy_p16.CORE_GUARD
            ),
            "p07_core_gate": _backup_file(root, "P07_CORE_GATE", P07_CORE_GATE),
            "generation13_telegram_dropin": _backup_file(
                root, "GENERATION13_TELEGRAM_DROPIN", GENERATION13_TELEGRAM_DROPIN
            ),
            "p07_selector": _backup_file(root, "P07_SELECTOR", P07_SELECTOR),
            "p07_release_set": _backup_file(root, "P07_RELEASE_SET", RELEASE_SET_PATH),
            "runtime_config": _backup_file(root, "OWNER_RUNTIME_CONFIG", OWNER_RUNTIME_CONFIG),
            "plugin_config": _backup_file(root, "TELEGRAM_CONFIG", TELEGRAM_CONFIG),
            "effective_v6": _backup_file(root, "EFFECTIVE_V6_ENV", EFFECTIVE_V6_ENV),
            "incident_selector": _backup_file(
                root, "INCIDENT_HISTORY_SELECTOR", INCIDENT_HISTORY_SELECTOR
            ),
            "incident_marker": _backup_file(
                root, "INCIDENT_HISTORY_MARKER", INCIDENT_HISTORY_MARKER
            ),
            "p16_telegram_dropin": _backup_file(
                root, "P16_TELEGRAM_DROPIN", P16_TELEGRAM_DROPIN
            ),
        },
        "target_prestate": {
            "incident_selector": plan["prestate"]["incident_selector"],
            "incident_marker": plan["prestate"]["incident_marker"],
            "p16_telegram_dropin": plan["prestate"]["p16_telegram_dropin"],
        },
        "history_action": "preserve",
    }
    manifest["backup_digest"] = digest("myuna-p16-phase1-t2-backup-v1", manifest)
    _atomic_write(root / "BACKUP.json", canonical(manifest) + b"\n", mode=0o600, exclusive=True)
    _atomic_write(root / "LIVE_PLAN.json", canonical(plan) + b"\n", mode=0o600, exclusive=True)
    _fsync_directory(root)
    return root


def _restore_exact(path: Path, backup: Path, projection: Mapping[str, object]) -> None:
    _atomic_write(
        path,
        _read_regular(backup, maximum=8_000_000),
        mode=int(str(projection["mode"]), 8),
        uid=int(projection["uid"]),
        gid=int(projection["gid"]),
    )
    require(_file_projection(path) == projection, "rollback_file_drifted")


def _load_backup(root: Path, live_plan_digest: str) -> dict[str, object]:
    require(root == BACKUP_ROOT / live_plan_digest and root.is_dir() and not root.is_symlink(), "activation_backup_rejected")
    payload = _read_canonical(root / "BACKUP.json")
    supplied = payload.get("backup_digest")
    unsigned = {key: value for key, value in payload.items() if key != "backup_digest"}
    require(
        payload.get("schema") == "myuna.p16-phase1-t2-backup.v1"
        and payload.get("live_plan_digest") == live_plan_digest
        and supplied == digest("myuna-p16-phase1-t2-backup-v1", unsigned),
        "activation_backup_rejected",
    )
    return payload


def _disable_marker() -> None:
    INCIDENT_HISTORY_MARKER.unlink(missing_ok=True)
    _fsync_directory(INCIDENT_HISTORY_MARKER.parent)


def _remove_default_off_targets() -> None:
    P16_TELEGRAM_DROPIN.unlink(missing_ok=True)
    INCIDENT_HISTORY_SELECTOR.unlink(missing_ok=True)
    _fsync_directory(P16_TELEGRAM_DROPIN.parent)
    _fsync_directory(INCIDENT_HISTORY_SELECTOR.parent)


def _restore_prestate(backup_root: Path, plan: Mapping[str, object]) -> dict[str, object]:
    _disable_marker()
    _systemctl("stop", TELEGRAM_SOCKET, TELEGRAM_SERVICE, CORE_SERVICE)
    _verify_targets_stopped()
    backup = _load_backup(backup_root, str(plan["live_plan_digest"]))
    files = backup["files"]
    _restore_exact(CORE_BINDING, backup_root / "CORE_BINDING", files["core_binding"]["source"])
    _restore_exact(CORE_SELECTOR, backup_root / "CORE_SELECTOR", files["core_selector"]["source"])
    _remove_default_off_targets()
    _restore_exact(
        INCIDENT_HISTORY_SELECTOR,
        backup_root / "INCIDENT_HISTORY_SELECTOR",
        files["incident_selector"]["source"],
    )
    _restore_exact(
        P16_TELEGRAM_DROPIN,
        backup_root / "P16_TELEGRAM_DROPIN",
        files["p16_telegram_dropin"]["source"],
    )
    _systemctl("daemon-reload")
    _systemctl("start", CORE_SERVICE)
    _systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)
    _restore_exact(
        INCIDENT_HISTORY_MARKER,
        backup_root / "INCIDENT_HISTORY_MARKER",
        files["incident_marker"]["source"],
    )
    return _verify_prestate(plan)


def _verify_prestate(plan: Mapping[str, object]) -> dict[str, object]:
    expected = plan["prestate"]
    services = {
        "core": _service_projection(CORE_SERVICE),
        "telegram": _service_projection(TELEGRAM_SERVICE),
        "telegram_socket": _service_projection(TELEGRAM_SOCKET, socket=True),
        "p08": _service_projection(P08_SERVICE),
        "p08_socket": _service_projection(P08_SOCKET, socket=True),
    }
    for name, projection in services.items():
        _require_active(projection, socket=name.endswith("socket"))
        require(
            projection["binding_digest"] == expected["services"][name]["binding_digest"],
            "rollback_service_binding_drifted",
        )
    current_core = legacy_p16._selected_core_release(str(services["core"]["working_directory"]))
    current_runtime = legacy_p16._selected_gateway_release(str(services["telegram"]["exec_start"]), channel="telegram")
    require(
        current_core.name == expected["selected"]["core"]
        and current_runtime.name == expected["selected"]["telegram_runtime"]
        and _selected_plugin_digest() == expected["selected"]["telegram_plugin"]
        and _load_v6_release() == expected["compatibility"]["effective_definition_id"]
        and _file_projection(INCIDENT_HISTORY_MARKER) == expected["incident_marker"]
        and _file_projection(INCIDENT_HISTORY_SELECTOR) == expected["incident_selector"]
        and _file_projection(P16_TELEGRAM_DROPIN) == expected["p16_telegram_dropin"],
        "rollback_prestate_drifted",
    )
    require(
        _file_projection(GENERATION13_TELEGRAM_DROPIN)
        == expected["files"]["generation13_telegram_dropin"]
        and _file_projection(legacy_p16.CORE_GUARD) == expected["files"]["core_guard"]
        and _file_projection(P07_CORE_GATE) == expected["files"]["p07_core_gate"]
        and _file_projection(P07_SELECTOR) == expected["files"]["p07_selector"]
        and _file_projection(RELEASE_SET_PATH) == expected["files"]["p07_release_set"]
        and _file_projection(OWNER_RUNTIME_CONFIG) == expected["files"]["runtime_config"]
        and _file_projection(TELEGRAM_CONFIG) == expected["files"]["plugin_config"]
        and _file_projection(EFFECTIVE_V6_ENV) == expected["files"]["effective_v6"]
        and _file_projection(p08_activation.SELECTOR_JSON)
        == expected["files"]["p08_selector"],
        "rollback_protected_file_drifted",
    )
    telegram_identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    require(
        _history_projection(telegram_identity.pw_uid, telegram_identity.pw_gid)
        == expected["history"],
        "rollback_history_drifted",
    )
    release_set = _p07_snapshot(str(expected["compatibility"]["p07_release_set_id"]))
    readiness = _readiness_projection(
        release_set,
        services["telegram"],
        wait_for_process=True,
    )
    require(
        readiness["release_set_id"] == expected["readiness"]["release_set_id"]
        and readiness["selector_digest"] == expected["readiness"]["selector_digest"]
        and readiness["runtime_config_digest"] == expected["readiness"]["runtime_config_digest"],
        "rollback_readiness_drifted",
    )
    return {
        "status": "prestate_restored",
        "selected": expected["selected"],
        "p07_release_set_id": release_set.release_set_id,
        "history_preserved": True,
        "services_active": True,
    }


def _service_identity_smoke(
    runtime: Path,
    selector_digest: str,
    telegram_gid: int,
    *,
    marker_expected: bool,
) -> None:
    code = (
        "from incident_history_runtime_adapter_v1 import "
        "INCIDENT_HISTORY_MARKER,INCIDENT_HISTORY_SELECTOR,load_approved_incident_history_selector;"
        "from gateway_enqueue import approved_marker_enabled;"
        "value=load_approved_incident_history_selector(INCIDENT_HISTORY_SELECTOR,expected_uid=0);"
        f"marker=approved_marker_enabled(str(INCIDENT_HISTORY_MARKER));"
        f"raise SystemExit(0 if value is not None and marker is {marker_expected!r} else 19)"
    )
    completed = subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            TELEGRAM_RUNTIME_USER,
            "--",
            "/usr/bin/env",
            f"PYTHONPATH={runtime}/runtime",
            "PYTHONDONTWRITEBYTECODE=1",
            "/usr/bin/python3",
            "-c",
            code,
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10.0,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    require(completed.returncode == 0, "service_identity_selector_smoke_failed")
    selector = load_approved_incident_history_selector(
        INCIDENT_HISTORY_SELECTOR,
        expected_uid=0,
        expected_gid=telegram_gid,
    )
    require(
        selector is not None
        and digest("myuna-p16-incident-history-selector-v1", selector) == selector_digest,
        "incident_selector_drifted",
    )


def _verify_target(
    plan: Mapping[str, object],
    bundle_context: Mapping[str, object],
    *,
    require_marker: bool,
    wait_for_process: bool = False,
) -> dict[str, object]:
    bundle = bundle_context["bundle"]
    targets = plan["target_artifacts"]
    services = {
        "core": _service_projection(CORE_SERVICE),
        "telegram": _service_projection(TELEGRAM_SERVICE),
        "telegram_socket": _service_projection(TELEGRAM_SOCKET, socket=True),
        "p08": _service_projection(P08_SERVICE),
        "p08_socket": _service_projection(P08_SOCKET, socket=True),
    }
    for name, projection in services.items():
        _require_active(projection, socket=name.endswith("socket"))
    core = legacy_p16._selected_core_release(str(services["core"]["working_directory"]))
    runtime = legacy_p16._selected_gateway_release(str(services["telegram"]["exec_start"]), channel="telegram")
    require(core.name == targets["core"] and runtime.name == targets["telegram_runtime"], "target_release_selection_rejected")
    require(_selected_plugin_digest() == targets["telegram_plugin"], "target_plugin_selection_rejected")
    require(
        _file_projection(P16_TELEGRAM_DROPIN)["sha256"]
        == _sha(_render_telegram_dropin(core, runtime)),
        "target_telegram_dropin_rejected",
    )
    telegram_gid = pwd.getpwnam(TELEGRAM_RUNTIME_USER).pw_gid
    selector = load_approved_incident_history_selector(
        INCIDENT_HISTORY_SELECTOR, expected_uid=0, expected_gid=telegram_gid
    )
    expected_selector = build_selector(bundle)
    require(selector == expected_selector, "target_incident_selector_rejected")
    legacy_p16._verify_core_selection(core, _read_regular(CORE_BINDING, maximum=64_000))
    require(
        _read_regular(CORE_SELECTOR, maximum=64_000) == legacy_p16._core_selector(core)
        and _file_projection(legacy_p16.CORE_GUARD)
        == plan["prestate"]["files"]["core_guard"]
        and _file_projection(P07_CORE_GATE)
        == plan["prestate"]["files"]["p07_core_gate"]
        and _file_projection(GENERATION13_TELEGRAM_DROPIN)
        == plan["prestate"]["files"]["generation13_telegram_dropin"]
        and _file_projection(P07_SELECTOR) == plan["prestate"]["files"]["p07_selector"]
        and _file_projection(RELEASE_SET_PATH) == plan["prestate"]["files"]["p07_release_set"]
        and _file_projection(OWNER_RUNTIME_CONFIG) == plan["prestate"]["files"]["runtime_config"]
        and _file_projection(TELEGRAM_CONFIG) == plan["prestate"]["files"]["plugin_config"]
        and _file_projection(EFFECTIVE_V6_ENV) == plan["prestate"]["files"]["effective_v6"]
        and _file_projection(p08_activation.SELECTOR_JSON)
        == plan["prestate"]["files"]["p08_selector"],
        "target_protected_file_drifted",
    )
    marker_present = not _absent(INCIDENT_HISTORY_MARKER)
    require(marker_present == require_marker, "target_incident_marker_rejected")
    if require_marker:
        marker_projection = _file_projection(INCIDENT_HISTORY_MARKER)
        selector_digest = digest("myuna-p16-incident-history-selector-v1", expected_selector)
        require(
            marker_projection["uid"] == 0
            and marker_projection["gid"] == 0
            and marker_projection["mode"] == "0440"
            and _read_regular(INCIDENT_HISTORY_MARKER, maximum=4096)
            == _marker_payload(str(bundle["bundle_digest"]), selector_digest),
            "target_incident_marker_rejected",
        )
    release_set = _p07_snapshot(str(plan["prestate"]["compatibility"]["p07_release_set_id"]))
    readiness = _readiness_projection(
        release_set,
        services["telegram"],
        wait_for_process=wait_for_process,
    )
    require(
        _load_v6_release() == plan["prestate"]["compatibility"]["effective_definition_id"]
        and services["p08"]["binding_digest"] == plan["prestate"]["services"]["p08"]["binding_digest"]
        and services["p08_socket"]["binding_digest"] == plan["prestate"]["services"]["p08_socket"]["binding_digest"],
        "target_compatibility_drifted",
    )
    return {
        "status": "active" if require_marker else "installed_default_off",
        "selected": targets,
        "p07_release_set_id": release_set.release_set_id,
        "readiness_digest": digest("myuna-p16-phase1-t2-target-readiness-v1", readiness),
        "service_restart_class": "zero",
        "public_reply_contract": "unchanged",
    }


def _write_receipt(schema: str, payload: dict[str, object]) -> tuple[dict[str, object], Path]:
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(RECEIPT_ROOT, 0, 0)
    os.chmod(RECEIPT_ROOT, 0o700)
    recorded_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    unsigned = {"schema": schema, "recorded_at": recorded_at, **payload}
    receipt = {
        **unsigned,
        "receipt_digest": digest("myuna-p16-phase1-t2-receipt-v1", unsigned),
    }
    stamp = recorded_at.replace("-", "").replace(":", "").replace(".", "")
    path = RECEIPT_ROOT / f"{stamp}-{receipt['receipt_digest'][:16]}.json"
    _atomic_write(path, canonical(receipt) + b"\n", mode=0o600, exclusive=True)
    return receipt, path


def activate(
    *,
    bundle_root: Path,
    core_source_root: Path,
    deploy_source_root: Path,
    expected_live_plan_digest: str,
    confirmation: str,
) -> dict[str, object]:
    bundle_context, live, plan = prepare_live(
        bundle_root=bundle_root,
        core_source_root=core_source_root,
        deploy_source_root=deploy_source_root,
    )
    require(
        plan["live_plan_digest"] == expected_live_plan_digest
        and confirmation == f"ACTIVATE:{expected_live_plan_digest}",
        "activation_confirmation_rejected",
    )
    bundle = bundle_context["bundle"]
    lineage = bundle["attempt_lineage"]
    backup_root = _create_backup(plan)
    attempt = _consume_attempt(bundle, expected_live_plan_digest)
    stage = "install_artifacts"
    try:
        identities = live["identities"]
        artifacts = bundle_context["artifacts"]
        inventories = bundle_context["inventories"]
        core = _install_artifact(
            artifacts["core"], CORE_RELEASE_ROOT, inventories["core"], gid=int(identities["core_gid"])
        )
        runtime = _install_artifact(
            artifacts["telegram_runtime"], RUNTIME_ROOT, inventories["telegram_runtime"], gid=int(identities["telegram_gid"])
        )
        _install_artifact(
            artifacts["p16_adapter"], ADAPTER_RELEASE_ROOT, inventories["p16_adapter"], gid=int(identities["telegram_gid"])
        )
        stage = "provision_history_storage"
        _mkdir_exact(STATE_ROOT.parent, uid=0, gid=0, mode=0o751)
        _mkdir_exact(INCIDENT_HISTORY_ROOT, uid=0, gid=0, mode=0o751)
        _mkdir_exact(
            INCIDENT_HISTORY_ROOT / "telegram",
            uid=int(identities["telegram_uid"]),
            gid=int(identities["telegram_gid"]),
            mode=0o700,
        )
        stage = "disable_terminal_predecessor_marker"
        _disable_marker()
        stage = "write_default_off_selector_and_dropin"
        selector = build_selector(bundle)
        selector_digest = digest("myuna-p16-incident-history-selector-v1", selector)
        _atomic_write(
            INCIDENT_HISTORY_SELECTOR,
            canonical(selector) + b"\n",
            mode=0o440,
            uid=0,
            gid=int(identities["telegram_gid"]),
            exclusive=False,
        )
        _atomic_write(
            P16_TELEGRAM_DROPIN,
            _render_telegram_dropin(core, runtime),
            mode=0o644,
            uid=0,
            gid=0,
            exclusive=False,
        )
        manifest = json.loads(_read_regular(core / "P16_MANIFEST.json").decode("ascii"))
        core_binding = legacy_p16._core_runtime_binding(
            core,
            manifest=manifest,
            current_binding=live["current_binding"],
            approval_plan_digest=expected_live_plan_digest,
            guard_payload=_read_regular(legacy_p16.CORE_GUARD, maximum=64_000),
        )
        stage = "stop_target_services"
        _systemctl("stop", TELEGRAM_SOCKET, TELEGRAM_SERVICE, CORE_SERVICE)
        _verify_targets_stopped()
        stage = "select_overlay_releases"
        _atomic_write(
            CORE_BINDING,
            core_binding,
            mode=0o640,
            uid=0,
            gid=int(identities["core_gid"]),
        )
        _atomic_write(CORE_SELECTOR, legacy_p16._core_selector(core), mode=0o644)
        legacy_p16._verify_core_selection(core, core_binding)
        _systemctl("daemon-reload")
        stage = "start_target_services"
        _systemctl("start", CORE_SERVICE)
        _systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)
        stage = "verify_default_off_target"
        default_off = _verify_target(
            plan,
            bundle_context,
            require_marker=False,
            wait_for_process=True,
        )
        stage = "service_identity_selector_smoke"
        _service_identity_smoke(
            runtime,
            selector_digest,
            int(identities["telegram_gid"]),
            marker_expected=False,
        )
        stage = "enable_marker_last"
        _atomic_write(
            INCIDENT_HISTORY_MARKER,
            _marker_payload(str(bundle["bundle_digest"]), selector_digest),
            mode=0o440,
            uid=0,
            gid=0,
            exclusive=True,
        )
        stage = "verify_enabled_target"
        enabled = _verify_target(plan, bundle_context, require_marker=True)
        _service_identity_smoke(
            runtime,
            selector_digest,
            int(identities["telegram_gid"]),
            marker_expected=True,
        )
    except BaseException as exc:
        activation_gate = _failure_gate(exc)
        try:
            rollback_result = _restore_prestate(backup_root, plan)
        except BaseException as rollback_exc:
            rollback_gate = _failure_gate(rollback_exc)
            _write_receipt(
                ACTIVATION_RECEIPT_SCHEMA,
                {
                    "status": "hard_stop_rollback_failed",
                    "attempt": attempt,
                    "attempt_series_id": lineage["attempt_series_id"],
                    "strategy_id": lineage["strategy_id"],
                    "bundle_digest": bundle["bundle_digest"],
                    "live_plan_digest": expected_live_plan_digest,
                    "activation_failure_gate": activation_gate,
                    "rollback_failure_gate": rollback_gate,
                    "failure_stage": stage,
                    "history_preserved": True,
                    "content_free": True,
                    "private_content_read": False,
                    "channel_called": False,
                    "model_called": False,
                    "provider_called": False,
                    "health_called": False,
                },
            )
            raise P16Phase1T2Rejected("rollback_failed_hard_stop") from None
        receipt, path = _write_receipt(
            ACTIVATION_RECEIPT_SCHEMA,
            {
                "status": "activation_failed_rolled_back",
                "attempt": attempt,
                "attempt_series_id": lineage["attempt_series_id"],
                "strategy_id": lineage["strategy_id"],
                "bundle_digest": bundle["bundle_digest"],
                "live_plan_digest": expected_live_plan_digest,
                "activation_failure_gate": activation_gate,
                "failure_stage": stage,
                "rollback": rollback_result,
                "history_preserved": True,
                "content_free": True,
                "private_content_read": False,
                "channel_called": False,
                "model_called": False,
                "provider_called": False,
                "health_called": False,
            },
        )
        raise P16Phase1T2Rejected(f"activation_failed_rolled_back_{receipt['receipt_digest'][:12]}") from None

    receipt, path = _write_receipt(
        ACTIVATION_RECEIPT_SCHEMA,
        {
            "status": "active_waiting_owner_organic_canary",
            "attempt": attempt,
            "attempt_series_id": lineage["attempt_series_id"],
            "strategy_id": lineage["strategy_id"],
            "bundle_digest": bundle["bundle_digest"],
            "live_plan_digest": expected_live_plan_digest,
            "target": enabled,
            "default_off_verification_digest": digest(
                "myuna-p16-phase1-t2-default-off-verification-v1", default_off
            ),
            "marker_created_last": True,
            "history_preserved": True,
            "public_reply_contract": "unchanged",
            "content_free": True,
            "private_content_read": False,
            "channel_called": False,
            "model_called": False,
            "provider_called": False,
            "health_called": False,
        },
    )
    return {**receipt, "receipt_path": str(path)}


def _load_activation_receipt(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    require(
        resolved.parent == RECEIPT_ROOT.resolve(strict=True)
        and not resolved.is_symlink(),
        "activation_receipt_path_rejected",
    )
    receipt = _read_canonical(resolved)
    supplied = receipt.get("receipt_digest")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    require(
        receipt.get("schema") == ACTIVATION_RECEIPT_SCHEMA
        and receipt.get("status") == "active_waiting_owner_organic_canary"
        and supplied == digest("myuna-p16-phase1-t2-receipt-v1", unsigned),
        "activation_receipt_rejected",
    )
    return receipt


def rollback(
    *,
    activation_receipt: Path,
    bundle_root: Path,
    confirmation: str,
) -> dict[str, object]:
    receipt = _load_activation_receipt(activation_receipt)
    require(
        confirmation == f"ROLLBACK:{receipt['receipt_digest']}",
        "rollback_confirmation_rejected",
    )
    plan_digest = str(receipt["live_plan_digest"])
    backup_root = BACKUP_ROOT / plan_digest
    plan = _read_canonical(backup_root / "LIVE_PLAN.json")
    require(plan.get("live_plan_digest") == plan_digest, "rollback_plan_rejected")
    bundle_context = _load_bundle_context(bundle_root)
    require(
        bundle_context["bundle"]["bundle_digest"] == receipt["bundle_digest"],
        "rollback_bundle_rejected",
    )
    _verify_target(plan, bundle_context, require_marker=True)
    restored = _restore_prestate(backup_root, plan)
    rollback_receipt, path = _write_receipt(
        ROLLBACK_RECEIPT_SCHEMA,
        {
            "status": "rolled_back",
            "activation_receipt_digest": receipt["receipt_digest"],
            "bundle_digest": receipt["bundle_digest"],
            "live_plan_digest": plan_digest,
            "restored": restored,
            "history_preserved": True,
            "installed_artifacts_preserved": True,
            "content_free": True,
            "private_content_read": False,
            "channel_called": False,
            "model_called": False,
            "provider_called": False,
            "health_called": False,
        },
    )
    return {**rollback_receipt, "receipt_path": str(path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight_parser = subparsers.add_parser("preflight-live")
    preflight_parser.add_argument("--bundle-root", type=Path, required=True)
    preflight_parser.add_argument("--core-source-root", type=Path, required=True)
    preflight_parser.add_argument("--deploy-source-root", type=Path, required=True)

    activation_parser = subparsers.add_parser("activate")
    activation_parser.add_argument("--bundle-root", type=Path, required=True)
    activation_parser.add_argument("--core-source-root", type=Path, required=True)
    activation_parser.add_argument("--deploy-source-root", type=Path, required=True)
    activation_parser.add_argument("--expected-live-plan-digest", required=True)
    activation_parser.add_argument("--confirmation", required=True)

    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument("--activation-receipt", type=Path, required=True)
    rollback_parser.add_argument("--bundle-root", type=Path, required=True)
    rollback_parser.add_argument("--confirmation", required=True)

    args = parser.parse_args()
    if args.command == "preflight-live":
        result = preflight_live(
            bundle_root=args.bundle_root,
            core_source_root=args.core_source_root,
            deploy_source_root=args.deploy_source_root,
        )
    elif args.command == "activate":
        result = activate(
            bundle_root=args.bundle_root,
            core_source_root=args.core_source_root,
            deploy_source_root=args.deploy_source_root,
            expected_live_plan_digest=args.expected_live_plan_digest,
            confirmation=args.confirmation,
        )
    else:
        result = rollback(
            activation_receipt=args.activation_receipt,
            bundle_root=args.bundle_root,
            confirmation=args.confirmation,
        )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
