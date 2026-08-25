#!/usr/bin/python3
"""Source-owned, content-free launcher for P08 prepare and formal gates.

The launcher is intentionally independent from the P08 controller import
closure.  It validates the committed Deploy/Core source identities and the
digest-named target release before claiming a call, invokes the mode-0644
controller through the exact interpreter, and persists only source-validated
plans and content-free capture projections.  Raw child stdout/stderr never
enters durable evidence.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Callable, Mapping, Sequence


LAUNCHER_SCHEMA = "myuna.p08-prepare-formal-drift-launcher.v5"
ARTIFACT_CONTRACT_SCHEMA = "myuna.p08-prepare-formal-drift-launcher-artifact.v5"
SOURCE_BINDING_SCHEMA = "myuna.p08-prepare-formal-drift-source-binding.v5"
HOST_CONTRACT_SCHEMA = "myuna.p08-prepare-formal-drift-host-contract.v5"
PREPARE_INVOCATION_SCHEMA = "myuna.p08-prepare-invocation.v2"
PREPARE_CLAIM_SCHEMA = "myuna.p08-prepare-call-claim.v2"
PREPARE_CAPTURE_SCHEMA = "myuna.p08-prepare-capture.v2"
PREPARE_RESULT_SCHEMA = "myuna.p08-prepare-capture-result.v2"
SEQUENCE_SCHEMA = "myuna.p08-formal-preflight-sequence.v3"
CLAIM_SCHEMA = "myuna.p08-formal-preflight-call-claim.v3"
CAPTURE_SCHEMA = "myuna.p08-formal-preflight-capture.v3"
SEQUENCE_RESULT_SCHEMA = "myuna.p08-formal-preflight-sequence-result.v3"
DRIFT_INVOCATION_SCHEMA = "myuna.p08-drift-invocation.v1"
DRIFT_CLAIM_SCHEMA = "myuna.p08-drift-call-claim.v1"
DRIFT_CAPTURE_SCHEMA = "myuna.p08-drift-capture.v1"
DRIFT_RESULT_SCHEMA = "myuna.p08-drift-capture-result.v1"
CLI_RESULT_SCHEMA = "myuna.p08-prepare-formal-drift-launcher-cli-result.v5"
PHASE_LIVENESS_SCHEMA = "myuna.p08-prepare-formal-drift-phase-liveness.v2"

CONTROLLER_READINESS_SCHEMA = (
    "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-readiness.v13"
)
CONTROLLER_CLI_RESULT_SCHEMA = (
    "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-cli-result.v13"
)
CONTROLLER_PLAN_SCHEMA = (
    "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-plan.v13"
)
CONTROLLER_STRATEGY_SCHEMA = (
    "myuna.p08-current-selected-forward-continuity-lineage-sha-repair-strategy.v13"
)
FORWARD_CONTINUITY_CONTRACT_SCHEMA = "myuna.p08-forward-continuity-orchestration.v1"
FORWARD_CONTINUITY_READINESS_SCHEMA = "myuna.p08-forward-continuity-readiness.v1"
TARGET_RELEASE_SCHEMA = "myuna.p08-active-temporal-code-release.v2"

INTERPRETER = Path("/usr/bin/python3")
DEPLOY_ROOT = Path("/srv/myuna/repos/deploy")
CORE_ROOT = Path("/srv/myuna/repos/core")
CORE_SOURCE_ROOT = CORE_ROOT / "src"
CONTROLLER_RELATIVE = Path("scripts/p08_current_selected_upgrade_v1.py")
LAUNCHER_RELATIVE = Path("scripts/p08_formal_preflight_launcher_v1.py")
BUILDER_RELATIVE = Path("scripts/build_p08_active_temporal_release_v2.py")
EVIDENCE_ROOT = Path(
    "/var/lib/myuna-activation-backups/"
    "p08-current-selected-forward-continuity-lineage-sha-repair-v13"
)

FORWARD_CONTINUITY_CORE_COMMIT = "97be9ef1f6182810575f62f79fd8b08680d1568c"
FORWARD_CONTINUITY_P08_HANDOFF_SHA256 = (
    "367dbfdbb1a2d872bd5f4c19f1daba6e398a788051107b866cb60b16f1c109f7"
)
FORWARD_CONTINUITY_P10B_HANDOFF_SHA256 = (
    "129c409236049eb74bf1400dd4c2c1c5fad4106a10ed29217bc23f6f8a03cd7f"
)
FORWARD_CONTINUITY_PREDECESSOR_CORE_COMMIT = (
    "065ef4b647f63925ae20bb564007c127433c0b81"
)
FORWARD_CONTINUITY_PREDECESSOR_RELEASE_DIGEST = (
    "1b589a474c56e138082f014724065dd57d38440b08c57b1497e5a4cb3cbe3e06"
)

ROLE_PREPARE = "prepare"
ROLE_FORMAL = "formal"
ROLE_DRIFT = "drift"
INVOCATION_ROLES = (ROLE_PREPARE, ROLE_FORMAL, ROLE_DRIFT)

CORE_PATHS = (
    "src/myuna_core/__init__.py",
    "src/myuna_core/audit.py",
    "src/myuna_core/authenticated_conversation.py",
    "src/myuna_core/channel_gateway.py",
    "src/myuna_core/identity.py",
    "src/myuna_core/integrations/__init__.py",
    "src/myuna_core/active_temporal_context",
    "src/myuna_core/capability_runtime",
    "src/myuna_core/integrations/openclaw",
    "src/myuna_core/operations",
    "src/myuna_core/trusted_time",
)
DEPLOY_PATHS = (
    "systemd/myuna-active-temporal-context-v1.service",
    "systemd/myuna-active-temporal-context-v1.socket",
    "systemd/myuna-active-temporal-context-v1.sysusers.conf",
    "systemd/myuna-active-temporal-context-v1.tmpfiles.conf",
    "scripts/build_p08_active_temporal_release_v2.py",
    "scripts/p08_temporal_gateway_v1.py",
    "scripts/p08_temporal_service_v1.py",
    "scripts/p08_existing_state_upgrade_v1.py",
    "scripts/p08_post_target_action_v1.py",
    "scripts/p08_current_selected_upgrade_v1.py",
    "scripts/p08_forward_continuity_orchestration_v1.py",
    "scripts/p08_formal_preflight_launcher_v1.py",
    "docs/ADR-087-p07-p08-single-nonce-stage-integration.md",
    "scripts/build_p07_owner_private_memory_transactional_runtime.py",
    "scripts/p07_owner_private_memory_production_plan.py",
    "scripts/p07_owner_private_memory_transactional_runtime.py",
    "tests/test_build_p07_owner_private_memory_transactional_runtime.py",
    "tests/test_p07_owner_private_memory_production_plan.py",
    "tests/test_p07_owner_private_memory_transactional_runtime.py",
)

FIXED_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONPATH": str(CORE_SOURCE_ROOT),
}
EXPECTED_UID = 0
EXPECTED_GID = 0
EXPECTED_GROUPS = (0,)
INVOCATION_UMASK = 0o077
MEASURED_SINGLE_VALIDATION_MILLISECONDS = 23_993
FORMAL_VALIDATION_PASSES = 2
ROLE_TIMEOUT_SECONDS = {ROLE_PREPARE: 60, ROLE_FORMAL: 180, ROLE_DRIFT: 120}
ROLE_NO_PROGRESS_TIMEOUT_SECONDS = {
    ROLE_PREPARE: 75,
    ROLE_FORMAL: 75,
    ROLE_DRIFT: 75,
}
# Compatibility alias for tests and callers that only consume the reviewed
# prepare/formal constant. Runtime enforcement is role-bound above.
NO_PROGRESS_TIMEOUT_SECONDS = 75
TERMINATION_GRACE_SECONDS = 2
PHASE_FD_ENV = "MYUNA_P08_PHASE_LIVENESS_FD"
PHASE_NONCE_ENV = "MYUNA_P08_PHASE_LIVENESS_NONCE"
PHASE_ROLE_ENV = "MYUNA_P08_PHASE_LIVENESS_ROLE"
PHASE_ENV_KEYS = (PHASE_FD_ENV, PHASE_NONCE_ENV, PHASE_ROLE_ENV)
PHASE_STARTUP = "startup"
PHASE_SOURCE_LINEAGE = "source_lineage"
PHASE_CURRENT_PUBLIC_SNAPSHOT = "current_public_snapshot"
PHASE_TARGET_VALIDATION_PASS1 = "target_validation_pass1"
PHASE_TARGET_VALIDATION_PASS2 = "plan_verify_target_validation_pass2"
PHASE_CANONICAL_SERIALIZATION = "canonical_serialization"
ROLE_PHASES = {
    ROLE_PREPARE: (
        PHASE_STARTUP,
        PHASE_SOURCE_LINEAGE,
        PHASE_TARGET_VALIDATION_PASS1,
        PHASE_CURRENT_PUBLIC_SNAPSHOT,
        PHASE_CANONICAL_SERIALIZATION,
    ),
    ROLE_FORMAL: (
        PHASE_STARTUP,
        PHASE_SOURCE_LINEAGE,
        PHASE_TARGET_VALIDATION_PASS1,
        PHASE_CURRENT_PUBLIC_SNAPSHOT,
        PHASE_TARGET_VALIDATION_PASS2,
        PHASE_CANONICAL_SERIALIZATION,
    ),
    ROLE_DRIFT: (
        PHASE_STARTUP,
        PHASE_SOURCE_LINEAGE,
        PHASE_CURRENT_PUBLIC_SNAPSHOT,
        PHASE_TARGET_VALIDATION_PASS1,
        PHASE_CANONICAL_SERIALIZATION,
    ),
}
MAX_PHASE_LINE_BYTES = 1024
MAX_PHASE_STREAM_BYTES = 16_384
MAX_STDOUT_BYTES = 262_144
MAX_STDERR_BYTES = 16_384
MAX_JSON_BYTES = 2_097_152
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_CODE = re.compile(r"^[a-z0-9_]{1,96}$")


class LauncherRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CanonicalArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise LauncherRejected("launcher_argument_rejected")

    def exit(self, status: int = 0, message: str | None = None) -> None:
        del status, message
        raise LauncherRejected("launcher_argument_rejected")


def require(condition: bool, code: str) -> None:
    if not condition:
        raise LauncherRejected(code)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def expected_forward_continuity_contract() -> dict[str, object]:
    """Return the exact source-bound continuity contract accepted by the launcher."""

    body = {
        "assessment_action_owned": True,
        "assessment_persistent_mutation": False,
        "automatic_startup_transition": False,
        "core_commit": FORWARD_CONTINUITY_CORE_COMMIT,
        "max_attempts": 1,
        "no_fallback": True,
        "no_retry": True,
        "p08_architecture_handoff_sha256": (
            FORWARD_CONTINUITY_P08_HANDOFF_SHA256
        ),
        "p10b_t1_handoff_sha256": FORWARD_CONTINUITY_P10B_HANDOFF_SHA256,
        "postcommit_ambiguity_action": "reconcile_only",
        "predecessor_core_commit": (
            FORWARD_CONTINUITY_PREDECESSOR_CORE_COMMIT
        ),
        "predecessor_forward_state_compatible": True,
        "predecessor_release_digest": (
            FORWARD_CONTINUITY_PREDECESSOR_RELEASE_DIGEST
        ),
        "readiness_opaque_content_read": False,
        "readiness_persistent_mutation": False,
        "rollback_code_public_only_after_commit": True,
        "schema": FORWARD_CONTINUITY_CONTRACT_SCHEMA,
        "state_backup_restore_after_forward_commit": False,
        "transition_direction": "forward_only",
        "transition_explicit": True,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def digest_file(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> str:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= max_bytes,
            "source_file_identity_rejected",
        )
        digest = sha256()
        observed = 0
        while observed < before.st_size:
            chunk = os.read(descriptor, min(1_048_576, before.st_size - observed))
            require(bool(chunk), "source_file_identity_rejected")
            digest.update(chunk)
            observed += len(chunk)
        require(not os.read(descriptor, 1), "source_file_identity_rejected")
        after = os.fstat(descriptor)
        require(
            observed == before.st_size
            and (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_uid,
                before.st_gid,
                before.st_size,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_size,
            ),
            "source_file_identity_rejected",
        )
        return digest.hexdigest()
    except LauncherRejected:
        raise
    except OSError as exc:
        raise LauncherRejected("source_file_identity_rejected") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _regular_projection(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LauncherRejected("source_file_identity_rejected") from exc
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink == 1,
        "source_file_identity_rejected",
    )
    return {
        "mode": stat.S_IMODE(metadata.st_mode),
        "sha256": digest_file(path),
        "size": metadata.st_size,
        "type": "file",
    }


def _interpreter_projection(path: Path = INTERPRETER) -> dict[str, object]:
    try:
        declared = path.lstat()
        resolved_path = path.resolve(strict=True)
        resolved = resolved_path.lstat()
    except OSError as exc:
        raise LauncherRejected("interpreter_identity_rejected") from exc
    require(
        (stat.S_ISLNK(declared.st_mode) or stat.S_ISREG(declared.st_mode))
        and stat.S_ISREG(resolved.st_mode)
        and resolved.st_nlink == 1
        and resolved.st_uid == 0
        and resolved.st_gid == 0
        and stat.S_IMODE(resolved.st_mode) & 0o111 != 0,
        "interpreter_identity_rejected",
    )
    return {
        "declared_path": str(path),
        "declared_type": "symlink" if stat.S_ISLNK(declared.st_mode) else "file",
        "resolved_gid": resolved.st_gid,
        "resolved_mode": stat.S_IMODE(resolved.st_mode),
        "resolved_path": str(resolved_path),
        "resolved_sha256": digest_file(resolved_path, max_bytes=64 * 1_048_576),
        "resolved_size": resolved.st_size,
        "resolved_uid": resolved.st_uid,
    }


def _git(root: Path, arguments: Sequence[str], *, code: str) -> bytes:
    try:
        completed = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-c",
                f"safe.directory={root}",
                "-C",
                str(root),
                *arguments,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LauncherRejected(code) from exc
    require(
        completed.returncode == 0
        and not completed.stderr
        and len(completed.stdout) <= 4 * 1_048_576,
        code,
    )
    return completed.stdout


def _git_source_projection(
    *, root: Path, declared_root: Path, commit: str, pathspecs: Sequence[str]
) -> dict[str, object]:
    require(HEX40.fullmatch(commit) is not None, "source_commit_rejected")
    require(root.is_dir() and not root.is_symlink(), "source_root_rejected")
    head = _git(root, ["rev-parse", "HEAD"], code="source_commit_rejected").strip()
    require(head.decode("ascii", "strict") == commit, "source_commit_rejected")
    tree = _git(root, ["show", "-s", "--format=%T", commit], code="source_tree_rejected")
    tree_text = tree.strip().decode("ascii", "strict")
    require(HEX40.fullmatch(tree_text) is not None, "source_tree_rejected")
    status = _git(
        root,
        ["status", "--porcelain=v1", "--untracked-files=all", "--", *pathspecs],
        code="source_status_rejected",
    )
    require(not status, "source_status_rejected")
    raw = _git(
        root,
        ["ls-tree", "-r", "--full-tree", commit, "--", *pathspecs],
        code="source_inventory_rejected",
    )
    rows: list[dict[str, object]] = []
    observed: set[str] = set()
    for line in raw.decode("utf-8", "strict").splitlines():
        header, path = line.split("\t", 1)
        mode, kind, object_id = header.split(" ", 2)
        require(
            kind == "blob"
            and re.fullmatch(r"[0-7]{6}", mode) is not None
            and HEX40.fullmatch(object_id) is not None
            and path not in observed,
            "source_inventory_rejected",
        )
        observed.add(path)
        rows.append(
            {"mode": mode, "object": object_id, "path": path, "type": kind}
        )
    for selected in pathspecs:
        require(
            selected in observed
            or any(path.startswith(selected.rstrip("/") + "/") for path in observed),
            "source_inventory_rejected",
        )
    rows.sort(key=lambda row: str(row["path"]))
    pathspec_projection = sorted(pathspecs)
    return {
        "commit": commit,
        "declared_root": str(declared_root),
        "inventory_count": len(rows),
        "inventory_sha256": digest_bytes(canonical(rows)),
        "pathspec_sha256": digest_bytes(canonical(pathspec_projection)),
        "tree": tree_text,
    }


def source_binding_contract(
    *,
    core_root: Path,
    deploy_root: Path,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, object]:
    body = {
        "core": _git_source_projection(
            root=core_root,
            declared_root=CORE_ROOT,
            commit=core_commit,
            pathspecs=CORE_PATHS,
        ),
        "deploy": _git_source_projection(
            root=deploy_root,
            declared_root=DEPLOY_ROOT,
            commit=deploy_commit,
            pathspecs=DEPLOY_PATHS,
        ),
        "schema": SOURCE_BINDING_SCHEMA,
    }
    return {**body, "binding_digest": digest_bytes(canonical(body))}


def artifact_contract(root: Path) -> dict[str, object]:
    controller = _regular_projection(root / CONTROLLER_RELATIVE)
    launcher = _regular_projection(root / LAUNCHER_RELATIVE)
    observed_controller_mode = int(controller.pop("mode"))
    observed_launcher_mode = int(launcher.pop("mode"))
    require(observed_controller_mode in (0o644, 0o444), "controller_mode_rejected")
    require(observed_launcher_mode in (0o755, 0o644, 0o444), "launcher_mode_rejected")
    controller.update(
        {"allowed_installed_modes": [0o444, 0o644], "source_mode": 0o644}
    )
    launcher.update(
        {
            "allowed_installed_modes": [0o444, 0o644],
            "source_mode": 0o755,
        }
    )
    body = {
        "controller": controller,
        "controller_path": CONTROLLER_RELATIVE.as_posix(),
        "launcher": launcher,
        "launcher_path": LAUNCHER_RELATIVE.as_posix(),
        "schema": ARTIFACT_CONTRACT_SCHEMA,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def host_contract(*, interpreter: Path = INTERPRETER) -> dict[str, object]:
    phase_contract = {
        "environment_keys_sha256": digest_bytes(canonical(PHASE_ENV_KEYS)),
        "hard_deadline_extensible": False,
        "max_line_bytes": MAX_PHASE_LINE_BYTES,
        "max_stream_bytes": MAX_PHASE_STREAM_BYTES,
        "role_no_progress_timeout_seconds": dict(
            ROLE_NO_PROGRESS_TIMEOUT_SECONDS
        ),
        "phases": {
            role: list(phases) for role, phases in ROLE_PHASES.items()
        },
        "schema": PHASE_LIVENESS_SCHEMA,
    }
    body = {
        "cwd": str(DEPLOY_ROOT),
        "environment_identity_sha256": digest_bytes(canonical(FIXED_ENVIRONMENT)),
        "expected_gid": EXPECTED_GID,
        "expected_groups": list(EXPECTED_GROUPS),
        "expected_uid": EXPECTED_UID,
        "interpreter": _interpreter_projection(interpreter),
        "max_stderr_bytes": MAX_STDERR_BYTES,
        "max_stdout_bytes": MAX_STDOUT_BYTES,
        "measured_single_validation_milliseconds": (
            MEASURED_SINGLE_VALIDATION_MILLISECONDS
        ),
        "formal_validation_passes": FORMAL_VALIDATION_PASSES,
        "phase_liveness": {
            **phase_contract,
            "contract_digest": digest_bytes(canonical(phase_contract)),
        },
        "role_timeout_seconds": dict(ROLE_TIMEOUT_SECONDS),
        "schema": HOST_CONTRACT_SCHEMA,
        "stdin_closed": True,
        "termination_grace_seconds": TERMINATION_GRACE_SECONDS,
        "umask": INVOCATION_UMASK,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def release_contract(root: Path) -> dict[str, object]:
    body = {
        "artifact": artifact_contract(root),
        "call_indexes": [1, 2],
        "capture_schema": CAPTURE_SCHEMA,
        "child_interpreter": str(INTERPRETER),
        "controller_cli_result_schema": CONTROLLER_CLI_RESULT_SCHEMA,
        "controller_readiness_schema": CONTROLLER_READINESS_SCHEMA,
        "forward_continuity_contract": expected_forward_continuity_contract(),
        "forward_continuity_readiness_schema": (
            FORWARD_CONTINUITY_READINESS_SCHEMA
        ),
        "evidence_raw_stderr_retained": False,
        "exactly_two": True,
        "launcher_schema": LAUNCHER_SCHEMA,
        "prepare_capture_schema": PREPARE_CAPTURE_SCHEMA,
        "prepare_claim_schema": PREPARE_CLAIM_SCHEMA,
        "prepare_invocation_schema": PREPARE_INVOCATION_SCHEMA,
        "prepare_plan_persistence": "canonical_validated_no_replace",
        "prepare_result_schema": PREPARE_RESULT_SCHEMA,
        "progress_schema": PHASE_LIVENESS_SCHEMA,
        "drift_capture_schema": DRIFT_CAPTURE_SCHEMA,
        "drift_claim_schema": DRIFT_CLAIM_SCHEMA,
        "drift_exactly_once": True,
        "drift_invocation_schema": DRIFT_INVOCATION_SCHEMA,
        "drift_result_schema": DRIFT_RESULT_SCHEMA,
        "roles": [ROLE_PREPARE, ROLE_FORMAL, ROLE_DRIFT],
        "sequence_result_schema": SEQUENCE_RESULT_SCHEMA,
        "sequence_schema": SEQUENCE_SCHEMA,
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def build_manifest_contract(
    *,
    release_root: Path,
    core_root: Path,
    deploy_root: Path,
    core_commit: str,
    deploy_commit: str,
) -> dict[str, object]:
    body = {
        "host": host_contract(),
        "launcher": release_contract(release_root),
        "source_binding": source_binding_contract(
            core_root=core_root,
            deploy_root=deploy_root,
            core_commit=core_commit,
            deploy_commit=deploy_commit,
        ),
    }
    return {**body, "contract_digest": digest_bytes(canonical(body))}


def _load_manifest(root: Path) -> tuple[dict[str, object], str]:
    path = root / "manifest.json"
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8", "strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherRejected("target_manifest_rejected") from exc
    require(
        isinstance(payload, dict)
        and payload.get("schema") == TARGET_RELEASE_SCHEMA
        and 0 < len(raw) <= MAX_JSON_BYTES,
        "target_manifest_rejected",
    )
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        require(not stat.S_ISLNK(metadata.st_mode), "target_release_link_rejected")
        if stat.S_ISDIR(metadata.st_mode) or relative == "manifest.json":
            continue
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"},
            "target_release_inventory_rejected",
        )
        files.append(
            {
                "path": relative,
                "sha256": digest_file(path),
                "size": metadata.st_size,
            }
        )
    require(payload.get("files") == files, "target_release_inventory_rejected")
    release_digest = digest_bytes(canonical(payload))
    require(root.name == release_digest, "target_release_digest_rejected")
    return payload, release_digest


def _load_plan_input(path: Path) -> tuple[dict[str, object], dict[str, object]]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_uid == EXPECTED_UID
            and before.st_gid == EXPECTED_GID
            and 0 < before.st_size <= MAX_JSON_BYTES,
            "drift_plan_identity_rejected",
        )
        chunks: list[bytes] = []
        remaining = MAX_JSON_BYTES + 1
        while remaining > 0:
            block = os.read(descriptor, min(65_536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        path_after = path.lstat()
        require(
            len(raw) == before.st_size
            and (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_uid,
                before.st_gid,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            "drift_plan_identity_rejected",
        )
        require(
            (
                path_after.st_dev,
                path_after.st_ino,
                path_after.st_mode,
                path_after.st_nlink,
                path_after.st_uid,
                path_after.st_gid,
                path_after.st_size,
                path_after.st_mtime_ns,
                path_after.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            "drift_plan_identity_rejected",
        )
        payload = json.loads(raw.decode("ascii", "strict"))
    except LauncherRejected:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherRejected("drift_plan_identity_rejected") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    require(
        isinstance(payload, dict)
        and raw == canonical(payload) + b"\n"
        and payload.get("schema") == CONTROLLER_PLAN_SCHEMA,
        "drift_plan_identity_rejected",
    )
    body = dict(payload)
    plan_digest = body.pop("plan_digest", None)
    body.pop("schema", None)
    require(
        isinstance(plan_digest, str)
        and HEX64.fullmatch(plan_digest) is not None
        and digest_bytes(canonical(body)) == plan_digest,
        "drift_plan_identity_rejected",
    )
    projection = {
        "mode": 0o600,
        "plan_digest": plan_digest,
        "sha256": digest_bytes(raw),
        "size": len(raw),
        "type": "file",
    }
    return payload, projection


def production_invocation_contract(
    target_release: Path,
    *,
    role: str = ROLE_FORMAL,
    plan_path: Path | None = None,
) -> dict[str, object]:
    require(role in INVOCATION_ROLES, "invocation_role_rejected")
    manifest, release_digest = _load_manifest(target_release)
    core_commit = str(manifest.get("core_commit", ""))
    deploy_commit = str(manifest.get("deploy_commit", ""))
    expected_binding = build_manifest_contract(
        release_root=target_release,
        core_root=CORE_ROOT,
        deploy_root=DEPLOY_ROOT,
        core_commit=core_commit,
        deploy_commit=deploy_commit,
    )
    require(
        manifest.get("formal_preflight_launcher_contract") == expected_binding,
        "launcher_manifest_binding_rejected",
    )
    selected_upgrade = manifest.get("current_selected_upgrade_contract")
    require(
        isinstance(selected_upgrade, dict)
        and selected_upgrade.get("formal_launcher")
        == expected_binding["launcher"],
        "controller_launcher_binding_rejected",
    )
    plan_projection: dict[str, object] | None = None
    if role == ROLE_DRIFT:
        require(plan_path is not None, "drift_plan_identity_rejected")
        selected_plan = plan_path.resolve()
        selected_prepare = selected_plan.parent
        require(
            selected_plan.name == "PLAN.INPUT.json"
            and HEX64.fullmatch(selected_prepare.name) is not None
            and selected_prepare.parent
            == EVIDENCE_ROOT / "prepare-captures",
            "drift_plan_identity_rejected",
        )
        plan, plan_projection = _load_plan_input(selected_plan)
        target = plan.get("target")
        require(
            isinstance(target, dict)
            and target.get("release_digest") == release_digest
            and target.get("release_source") == str(target_release),
            "drift_plan_target_rejected",
        )
        argv = [
            str(INTERPRETER),
            str(DEPLOY_ROOT / CONTROLLER_RELATIVE),
            "verify",
            "--plan",
            str(selected_plan),
        ]
        formal_invocation = production_invocation_contract(
            target_release, role=ROLE_FORMAL
        )
        formal_sequence = sequence_contract(formal_invocation)
        formal_result = (
            EVIDENCE_ROOT
            / "formal-sequences"
            / str(formal_sequence["sequence_identity"])
            / "RESULT.json"
        )
        formal_result_sha256 = digest_file(formal_result)
    else:
        require(plan_path is None, "invocation_role_rejected")
        controller_command = "prepare" if role == ROLE_PREPARE else "preflight"
        argv = [
            str(INTERPRETER),
            str(DEPLOY_ROOT / CONTROLLER_RELATIVE),
            controller_command,
            "--target-release",
            str(target_release),
        ]
    body = {
        "argv_identity_sha256": digest_bytes(canonical(argv)),
        "controller_sha256": expected_binding["launcher"]["artifact"][
            "controller"
        ]["sha256"],
        "cwd": str(DEPLOY_ROOT),
        "environment_identity_sha256": digest_bytes(canonical(FIXED_ENVIRONMENT)),
        "hard_timeout_seconds": ROLE_TIMEOUT_SECONDS[role],
        "host_contract_digest": expected_binding["host"]["contract_digest"],
        "launcher_contract_digest": expected_binding["launcher"]["contract_digest"],
        "no_progress_timeout_seconds": ROLE_NO_PROGRESS_TIMEOUT_SECONDS[role],
        "phase_liveness_contract_digest": expected_binding["host"][
            "phase_liveness"
        ]["contract_digest"],
        "role": role,
        "schema": LAUNCHER_SCHEMA,
        "source_binding_digest": expected_binding["source_binding"][
            "binding_digest"
        ],
        "target_release_digest": release_digest,
    }
    if plan_projection is not None:
        body.update(
            {
                "drift_exactly_once": True,
                "formal_invocation_identity_sha256": formal_invocation[
                    "invocation_identity_sha256"
                ],
                "formal_sequence_identity": formal_sequence["sequence_identity"],
                "formal_result_sha256": formal_result_sha256,
                "plan_digest": plan_projection["plan_digest"],
                "plan_sha256": plan_projection["sha256"],
                "prepare_identity": plan_path.resolve().parent.name,
            }
        )
    return {
        **body,
        "invocation_identity_sha256": digest_bytes(canonical(body)),
        "_argv": argv,
        "_environment": dict(FIXED_ENVIRONMENT),
    }


def public_invocation_contract(contract: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in contract.items() if not key.startswith("_")}


def sequence_contract(invocation: Mapping[str, object]) -> dict[str, object]:
    require(invocation.get("role") == ROLE_FORMAL, "invocation_role_rejected")
    public = public_invocation_contract(invocation)
    body = {
        "call_indexes": [1, 2],
        "invocation_identity_sha256": public["invocation_identity_sha256"],
        "launcher_contract_digest": public["launcher_contract_digest"],
        "schema": SEQUENCE_SCHEMA,
        "source_binding_digest": public["source_binding_digest"],
        "target_release_digest": public["target_release_digest"],
    }
    return {**body, "sequence_identity": digest_bytes(canonical(body))}


def call_nonce(sequence_identity: str, call_index: int) -> str:
    require(
        HEX64.fullmatch(sequence_identity) is not None and call_index in (1, 2),
        "call_identity_rejected",
    )
    return digest_bytes(
        canonical(
            {
                "call_index": call_index,
                "domain": "p08-formal-preflight-call-v1",
                "sequence_identity": sequence_identity,
            }
        )
    )


def prepare_contract(invocation: Mapping[str, object]) -> dict[str, object]:
    require(invocation.get("role") == ROLE_PREPARE, "invocation_role_rejected")
    public = public_invocation_contract(invocation)
    body = {
        "invocation_identity_sha256": public["invocation_identity_sha256"],
        "launcher_contract_digest": public["launcher_contract_digest"],
        "role": ROLE_PREPARE,
        "schema": PREPARE_INVOCATION_SCHEMA,
        "source_binding_digest": public["source_binding_digest"],
        "target_release_digest": public["target_release_digest"],
    }
    return {**body, "prepare_identity": digest_bytes(canonical(body))}


def prepare_nonce(prepare_identity: str) -> str:
    require(HEX64.fullmatch(prepare_identity) is not None, "prepare_identity_rejected")
    return digest_bytes(
        canonical(
            {
                "domain": "p08-prepare-call-v1",
                "prepare_identity": prepare_identity,
            }
        )
    )


def drift_contract(invocation: Mapping[str, object]) -> dict[str, object]:
    public = public_invocation_contract(invocation)
    identity = public.pop("invocation_identity_sha256", None)
    expected_keys = {
        "argv_identity_sha256",
        "controller_sha256",
        "cwd",
        "drift_exactly_once",
        "environment_identity_sha256",
        "formal_invocation_identity_sha256",
        "formal_result_sha256",
        "formal_sequence_identity",
        "hard_timeout_seconds",
        "host_contract_digest",
        "launcher_contract_digest",
        "no_progress_timeout_seconds",
        "phase_liveness_contract_digest",
        "plan_digest",
        "plan_sha256",
        "prepare_identity",
        "role",
        "schema",
        "source_binding_digest",
        "target_release_digest",
    }
    digest_keys = expected_keys - {
        "cwd",
        "drift_exactly_once",
        "hard_timeout_seconds",
        "no_progress_timeout_seconds",
        "role",
        "schema",
    }
    require(
        invocation.get("role") == ROLE_DRIFT
        and set(public) == expected_keys
        and public.get("schema") == LAUNCHER_SCHEMA
        and public.get("cwd") == str(DEPLOY_ROOT)
        and public.get("drift_exactly_once") is True
        and public.get("hard_timeout_seconds") == ROLE_TIMEOUT_SECONDS[ROLE_DRIFT]
        and public.get("no_progress_timeout_seconds")
        == ROLE_NO_PROGRESS_TIMEOUT_SECONDS[ROLE_DRIFT]
        and all(
            isinstance(public.get(key), str)
            and HEX64.fullmatch(str(public[key])) is not None
            for key in digest_keys
        )
        and isinstance(identity, str)
        and HEX64.fullmatch(identity) is not None
        and digest_bytes(canonical(public)) == identity,
        "drift_invocation_contract_rejected",
    )
    body = {
        "call_indexes": [1],
        "formal_invocation_identity_sha256": public[
            "formal_invocation_identity_sha256"
        ],
        "formal_sequence_identity": public["formal_sequence_identity"],
        "formal_result_sha256": public["formal_result_sha256"],
        "invocation_identity_sha256": identity,
        "launcher_contract_digest": public["launcher_contract_digest"],
        "plan_digest": public["plan_digest"],
        "plan_sha256": public["plan_sha256"],
        "prepare_identity": public["prepare_identity"],
        "role": ROLE_DRIFT,
        "schema": DRIFT_INVOCATION_SCHEMA,
        "source_binding_digest": public["source_binding_digest"],
        "target_release_digest": public["target_release_digest"],
    }
    return {**body, "drift_identity": digest_bytes(canonical(body))}


def drift_nonce(drift_identity: str) -> str:
    require(HEX64.fullmatch(drift_identity) is not None, "drift_identity_rejected")
    return digest_bytes(
        canonical(
            {
                "call_index": 1,
                "domain": "p08-non-formal-drift-call-v1",
                "drift_identity": drift_identity,
            }
        )
    )


@dataclass(frozen=True)
class ProcessObservation:
    process_created: bool
    pid: int | None
    started_ns: int
    ended_ns: int
    returncode: int | None
    timed_out: bool
    stdout: bytes
    stderr: bytes
    timeout_class: str | None = None
    progress_valid: bool = False
    progress_complete: bool = False
    progress_events: tuple[dict[str, object], ...] = ()
    progress_error: str | None = None
    termination_escalated: bool = False
    drain_completed: bool = True


ProcessRunner = Callable[
    [Sequence[str], Mapping[str, str], Path, int, str, str], ProcessObservation
]


_PHASE_EMITTER_STATE: dict[str, object] | None = None


def emit_phase(phase: str) -> None:
    """Emit one source-owned content-free liveness event when launcher-bound."""

    global _PHASE_EMITTER_STATE
    observed = {key: os.environ.get(key) for key in PHASE_ENV_KEYS}
    if all(value is None for value in observed.values()):
        return
    require(all(value is not None for value in observed.values()), "phase_liveness_contract_rejected")
    role = str(observed[PHASE_ROLE_ENV])
    nonce = str(observed[PHASE_NONCE_ENV])
    try:
        descriptor = int(str(observed[PHASE_FD_ENV]), 10)
    except ValueError as exc:
        raise LauncherRejected("phase_liveness_contract_rejected") from exc
    require(
        role in INVOCATION_ROLES
        and HEX64.fullmatch(nonce) is not None
        and descriptor >= 3,
        "phase_liveness_contract_rejected",
    )
    if _PHASE_EMITTER_STATE is None:
        _PHASE_EMITTER_STATE = {
            "descriptor": descriptor,
            "last_monotonic_ns": -1,
            "nonce": nonce,
            "role": role,
            "sequence": 0,
        }
    state = _PHASE_EMITTER_STATE
    require(
        state["descriptor"] == descriptor
        and state["nonce"] == nonce
        and state["role"] == role,
        "phase_liveness_contract_rejected",
    )
    sequence = int(state["sequence"]) + 1
    expected = ROLE_PHASES[role]
    require(
        sequence <= len(expected) and phase == expected[sequence - 1],
        "phase_liveness_order_rejected",
    )
    timestamp = time.monotonic_ns()
    require(timestamp > int(state["last_monotonic_ns"]), "phase_liveness_clock_rejected")
    event = {
        "monotonic_ns": timestamp,
        "nonce": nonce,
        "phase": phase,
        "role": role,
        "schema": PHASE_LIVENESS_SCHEMA,
        "sequence": sequence,
    }
    raw = canonical(event) + b"\n"
    require(len(raw) <= MAX_PHASE_LINE_BYTES, "phase_liveness_oversize_rejected")
    try:
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            require(count > 0, "phase_liveness_write_rejected")
            written += count
    except OSError as exc:
        raise LauncherRejected("phase_liveness_write_rejected") from exc
    state["last_monotonic_ns"] = timestamp
    state["sequence"] = sequence


def _validate_phase_line(
    raw: bytes,
    *,
    role: str,
    nonce: str,
    expected_sequence: int,
    prior_timestamp: int,
) -> dict[str, object]:
    try:
        payload = json.loads(raw.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherRejected("phase_liveness_malformed") from exc
    expected = ROLE_PHASES[role]
    require(
        isinstance(payload, dict)
        and raw == canonical(payload)
        and set(payload)
        == {"monotonic_ns", "nonce", "phase", "role", "schema", "sequence"}
        and payload.get("schema") == PHASE_LIVENESS_SCHEMA
        and payload.get("nonce") == nonce
        and payload.get("role") == role
        and payload.get("sequence") == expected_sequence
        and expected_sequence <= len(expected)
        and payload.get("phase") == expected[expected_sequence - 1]
        and type(payload.get("monotonic_ns")) is int
        and int(payload["monotonic_ns"]) > prior_timestamp,
        "phase_liveness_mismatch",
    )
    return dict(payload)


def _signal_group(process: subprocess.Popen[bytes], selected: int) -> None:
    try:
        os.killpg(process.pid, selected)
    except OSError:
        try:
            process.send_signal(selected)
        except OSError:
            pass


def _bounded_terminate_and_drain(
    process: subprocess.Popen[bytes], *, terminate: bool
) -> tuple[bytes, bytes, bool, bool]:
    escalated = False
    if terminate and process.poll() is None:
        _signal_group(process, signal.SIGTERM)
    try:
        stdout, stderr = process.communicate(timeout=TERMINATION_GRACE_SECONDS)
        return stdout, stderr, escalated, True
    except subprocess.TimeoutExpired:
        escalated = True
        _signal_group(process, signal.SIGKILL)
    try:
        stdout, stderr = process.communicate(timeout=TERMINATION_GRACE_SECONDS)
        return stdout, stderr, escalated, True
    except subprocess.TimeoutExpired:
        _signal_group(process, signal.SIGKILL)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        try:
            process.wait(timeout=TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        return b"", b"", True, False


def _phase_trace_sha256(events: Sequence[Mapping[str, object]], role: str) -> str:
    return digest_bytes(
        canonical(
            {
                "phases": [event["phase"] for event in events],
                "role": role,
                "schema": PHASE_LIVENESS_SCHEMA,
            }
        )
    )


def _deadline_class(
    now: float, *, hard_deadline: float, progress_deadline: float
) -> str | None:
    if now >= hard_deadline:
        return "hard_total"
    if now >= progress_deadline:
        return "no_progress"
    return None


def _run_process(
    argv: Sequence[str],
    environment: Mapping[str, str],
    cwd: Path,
    timeout: int,
    role: str,
    liveness_nonce: str,
) -> ProcessObservation:
    started = time.time_ns()
    started_monotonic = time.monotonic()
    require(
        role in INVOCATION_ROLES
        and timeout == ROLE_TIMEOUT_SECONDS[role]
        and HEX64.fullmatch(liveness_nonce) is not None
        and not any(key in environment for key in PHASE_ENV_KEYS),
        "phase_liveness_contract_rejected",
    )
    read_descriptor = -1
    write_descriptor = -1
    try:
        read_descriptor, write_descriptor = os.pipe()
        os.set_blocking(read_descriptor, False)
        os.set_inheritable(write_descriptor, True)
        child_environment = dict(environment)
        child_environment.update(
            {
                PHASE_FD_ENV: str(write_descriptor),
                PHASE_NONCE_ENV: liveness_nonce,
                PHASE_ROLE_ENV: role,
            }
        )
        process = subprocess.Popen(
            list(argv),
            cwd=str(cwd),
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            umask=INVOCATION_UMASK,
            pass_fds=(write_descriptor,),
        )
    except OSError:
        for descriptor in (read_descriptor, write_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        return ProcessObservation(False, None, started, time.time_ns(), None, False, b"", b"")
    os.close(write_descriptor)
    write_descriptor = -1
    hard_deadline = started_monotonic + timeout
    no_progress_timeout = ROLE_NO_PROGRESS_TIMEOUT_SECONDS[role]
    progress_deadline = started_monotonic + no_progress_timeout
    buffer = b""
    total_progress = 0
    events: list[dict[str, object]] = []
    progress_error: str | None = None
    timeout_class: str | None = None
    pipe_eof = False
    selector = selectors.DefaultSelector()
    selector.register(read_descriptor, selectors.EVENT_READ)
    try:
        while process.poll() is None and progress_error is None and timeout_class is None:
            now = time.monotonic()
            timeout_class = _deadline_class(
                now,
                hard_deadline=hard_deadline,
                progress_deadline=progress_deadline,
            )
            if timeout_class is not None:
                break
            wait = min(hard_deadline - now, progress_deadline - now, 0.1)
            for _key, _mask in selector.select(max(0.0, wait)):
                try:
                    observed = os.read(read_descriptor, 4096)
                except BlockingIOError:
                    continue
                if not observed:
                    pipe_eof = True
                    if process.poll() is None:
                        progress_error = "phase_liveness_pipe_closed"
                    break
                total_progress += len(observed)
                if total_progress > MAX_PHASE_STREAM_BYTES:
                    progress_error = "phase_liveness_oversize"
                    break
                buffer += observed
                if len(buffer) > MAX_PHASE_LINE_BYTES and b"\n" not in buffer:
                    progress_error = "phase_liveness_oversize"
                    break
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line or len(line) > MAX_PHASE_LINE_BYTES:
                        progress_error = "phase_liveness_malformed"
                        break
                    try:
                        event = _validate_phase_line(
                            line,
                            role=role,
                            nonce=liveness_nonce,
                            expected_sequence=len(events) + 1,
                            prior_timestamp=(
                                int(events[-1]["monotonic_ns"]) if events else -1
                            ),
                        )
                    except LauncherRejected as exc:
                        progress_error = exc.code
                        break
                    events.append(event)
                    progress_deadline = time.monotonic() + no_progress_timeout
        terminate = progress_error is not None or timeout_class is not None
        stdout, stderr, escalated, drain_completed = _bounded_terminate_and_drain(
            process, terminate=terminate
        )
        progress_drain_deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
        while not pipe_eof and time.monotonic() < progress_drain_deadline:
            try:
                observed = os.read(read_descriptor, 4096)
            except BlockingIOError:
                remaining = progress_drain_deadline - time.monotonic()
                if remaining <= 0:
                    break
                selector.select(min(0.05, remaining))
                continue
            if not observed:
                pipe_eof = True
                break
            total_progress += len(observed)
            if total_progress > MAX_PHASE_STREAM_BYTES:
                progress_error = progress_error or "phase_liveness_oversize"
                buffer = b""
                continue
            if progress_error is not None:
                continue
            buffer += observed
            while b"\n" in buffer and progress_error is None:
                line, buffer = buffer.split(b"\n", 1)
                try:
                    event = _validate_phase_line(
                        line,
                        role=role,
                        nonce=liveness_nonce,
                        expected_sequence=len(events) + 1,
                        prior_timestamp=(
                            int(events[-1]["monotonic_ns"]) if events else -1
                        ),
                    )
                except LauncherRejected as exc:
                    progress_error = exc.code
                    break
                events.append(event)
        if buffer and progress_error is None:
            progress_error = "phase_liveness_malformed"
        if not pipe_eof and progress_error is None:
            progress_error = "phase_liveness_drain_incomplete"
        drain_completed = drain_completed and pipe_eof
        expected_phases = ROLE_PHASES[role]
        progress_complete = (
            progress_error is None
            and [event["phase"] for event in events] == list(expected_phases)
        )
        return ProcessObservation(
            True,
            process.pid,
            started,
            time.time_ns(),
            process.returncode,
            timeout_class is not None,
            stdout,
            stderr,
            timeout_class=timeout_class,
            progress_valid=progress_error is None,
            progress_complete=progress_complete,
            progress_events=tuple(events),
            progress_error=progress_error,
            termination_escalated=escalated,
            drain_completed=drain_completed,
        )
    finally:
        selector.close()
        if read_descriptor >= 0:
            os.close(read_descriptor)


def _validate_runtime_identity() -> None:
    require(
        os.geteuid() == EXPECTED_UID
        and os.getegid() == EXPECTED_GID
        and tuple(sorted(os.getgroups())) == EXPECTED_GROUPS,
        "privilege_identity_rejected",
    )
    require(Path.cwd() == DEPLOY_ROOT, "cwd_identity_rejected")
    require(Path(sys.executable).resolve() == INTERPRETER.resolve(), "interpreter_identity_rejected")


def _directory(path: Path, *, mode: int = 0o700) -> None:
    metadata = path.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == mode
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid(),
        "evidence_directory_rejected",
    )


def _write_exclusive(path: Path, payload: Mapping[str, object]) -> None:
    raw = canonical(payload) + b"\n"
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        written = 0
        while written < len(raw):
            observed = os.write(descriptor, raw[written:])
            require(observed > 0, "capture_persist_rejected")
            written += observed
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    except FileExistsError as exc:
        raise LauncherRejected("capture_replay_rejected") from exc
    except OSError as exc:
        raise LauncherRejected("capture_persist_rejected") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        metadata = path.lstat()
        readback = path.read_bytes()
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_uid == os.geteuid()
            and metadata.st_gid == os.getegid()
            and readback == raw,
            "capture_persist_rejected",
        )
        descriptor = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except LauncherRejected:
        raise
    except OSError as exc:
        raise LauncherRejected("capture_persist_rejected") from exc


def _sequence_directory(evidence_root: Path, sequence: Mapping[str, object]) -> Path:
    try:
        parent = evidence_root.parent.lstat()
        require(
            stat.S_ISDIR(parent.st_mode)
            and not stat.S_ISLNK(parent.st_mode)
            and parent.st_uid == os.geteuid()
            and parent.st_gid == os.getegid(),
            "evidence_parent_rejected",
        )
        os.mkdir(evidence_root, 0o700)
        descriptor = os.open(
            evidence_root.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except FileExistsError:
        pass
    except LauncherRejected:
        raise
    except OSError as exc:
        raise LauncherRejected("evidence_parent_rejected") from exc
    _directory(evidence_root)
    sequences = evidence_root / "formal-sequences"
    try:
        os.mkdir(sequences, 0o700)
    except FileExistsError:
        pass
    _directory(sequences)
    selected = sequences / str(sequence["sequence_identity"])
    try:
        os.mkdir(selected, 0o700)
        _write_exclusive(selected / "SEQUENCE.json", sequence)
    except FileExistsError:
        pass
    _directory(selected)
    try:
        observed_sequence = (selected / "SEQUENCE.json").read_bytes()
    except OSError as exc:
        raise LauncherRejected("sequence_identity_rejected") from exc
    require(
        observed_sequence == canonical(sequence) + b"\n",
        "sequence_identity_rejected",
    )
    return selected


def _existing_sequence_directory(
    evidence_root: Path, sequence: Mapping[str, object]
) -> Path:
    selected = (
        evidence_root
        / "formal-sequences"
        / str(sequence["sequence_identity"])
    )
    try:
        _directory(evidence_root)
        _directory(evidence_root / "formal-sequences")
        _directory(selected)
        observed_sequence = (selected / "SEQUENCE.json").read_bytes()
    except LauncherRejected:
        raise
    except OSError as exc:
        raise LauncherRejected("sequence_identity_rejected") from exc
    require(
        observed_sequence == canonical(sequence) + b"\n",
        "sequence_identity_rejected",
    )
    return selected


def _prepare_directory(
    evidence_root: Path, prepare: Mapping[str, object]
) -> Path:
    try:
        parent = evidence_root.parent.lstat()
        require(
            stat.S_ISDIR(parent.st_mode)
            and not stat.S_ISLNK(parent.st_mode)
            and parent.st_uid == os.geteuid()
            and parent.st_gid == os.getegid(),
            "evidence_parent_rejected",
        )
        os.mkdir(evidence_root, 0o700)
        descriptor = os.open(
            evidence_root.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except FileExistsError:
        pass
    except LauncherRejected:
        raise
    except OSError as exc:
        raise LauncherRejected("evidence_parent_rejected") from exc
    _directory(evidence_root)
    prepares = evidence_root / "prepare-captures"
    try:
        os.mkdir(prepares, 0o700)
    except FileExistsError:
        pass
    _directory(prepares)
    selected = prepares / str(prepare["prepare_identity"])
    try:
        os.mkdir(selected, 0o700)
        _write_exclusive(selected / "PREPARE.json", prepare)
    except FileExistsError:
        pass
    _directory(selected)
    try:
        observed_prepare = (selected / "PREPARE.json").read_bytes()
    except OSError as exc:
        raise LauncherRejected("prepare_identity_rejected") from exc
    require(
        observed_prepare == canonical(prepare) + b"\n",
        "prepare_identity_rejected",
    )
    return selected


def _drift_directory(
    evidence_root: Path, drift: Mapping[str, object]
) -> Path:
    try:
        parent = evidence_root.parent.lstat()
        require(
            stat.S_ISDIR(parent.st_mode)
            and not stat.S_ISLNK(parent.st_mode)
            and parent.st_uid == os.geteuid()
            and parent.st_gid == os.getegid(),
            "evidence_parent_rejected",
        )
        os.mkdir(evidence_root, 0o700)
        descriptor = os.open(
            evidence_root.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except FileExistsError:
        pass
    except LauncherRejected:
        raise
    except OSError as exc:
        raise LauncherRejected("evidence_parent_rejected") from exc
    _directory(evidence_root)
    captures = evidence_root / "drift-captures"
    try:
        os.mkdir(captures, 0o700)
    except FileExistsError:
        pass
    _directory(captures)
    selected = captures / str(drift["drift_identity"])
    try:
        os.mkdir(selected, 0o700)
        _write_exclusive(selected / "DRIFT.json", drift)
    except FileExistsError:
        pass
    _directory(selected)
    try:
        observed = (selected / "DRIFT.json").read_bytes()
    except OSError as exc:
        raise LauncherRejected("drift_identity_rejected") from exc
    require(observed == canonical(drift) + b"\n", "drift_identity_rejected")
    return selected


def _parse_child(
    observation: ProcessObservation,
) -> tuple[str, str | None, str | None, bool]:
    if (
        not observation.process_created
        or observation.timed_out
        or observation.returncode is None
        or observation.returncode < 0
        or len(observation.stdout) > MAX_STDOUT_BYTES
        or len(observation.stderr) > MAX_STDERR_BYTES
        or observation.stderr
        or not observation.stdout
        or not observation.progress_valid
        or not observation.drain_completed
    ):
        return "indeterminate", None, None, False
    try:
        payload = json.loads(observation.stdout.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        return "indeterminate", None, None, False
    if not isinstance(payload, dict) or observation.stdout != canonical(payload) + b"\n":
        return "indeterminate", None, None, False
    if observation.returncode == 0:
        plan = payload.get("plan")
        valid = (
            set(payload)
            == {
                "forward_continuity",
                "opaque_content_read",
                "opaque_content_read_deferred_to_action_owned_backup",
                "persistent_mutation",
                "plan",
                "plan_digest",
                "schema",
                "status",
            }
            and
            payload.get("schema") == CONTROLLER_READINESS_SCHEMA
            and payload.get("status") == "ready"
            and payload.get("opaque_content_read") is False
            and payload.get("persistent_mutation") is False
            and payload.get("opaque_content_read_deferred_to_action_owned_backup") is True
            and observation.progress_complete
            and HEX64.fullmatch(str(payload.get("plan_digest", ""))) is not None
            and isinstance(plan, dict)
            and plan.get("plan_digest") == payload.get("plan_digest")
            and _valid_forward_continuity_readiness(payload, plan)
        )
        return (
            "ready" if valid else "indeterminate",
            str(payload.get("plan_digest")) if valid else None,
            digest_bytes(canonical(payload)) if valid else None,
            valid,
        )
    if observation.returncode == 2:
        code = payload.get("code")
        category = payload.get("category")
        valid = (
            payload.get("schema") == CONTROLLER_CLI_RESULT_SCHEMA
            and payload.get("status") == "rejected"
            and isinstance(code, str)
            and SAFE_CODE.fullmatch(code) is not None
            and category in {"typed_rejection", "unexpected_controller_failure"}
            and payload.get("opaque_content_read") is False
            and payload.get("persistent_mutation") is False
            and payload.get("retryable") is False
            and set(payload)
            == {
                "category",
                "code",
                "opaque_content_read",
                "persistent_mutation",
                "retryable",
                "schema",
                "status",
            }
        )
        return (
            "rejected" if valid else "indeterminate",
            f"{category}:{code}" if valid else None,
            digest_bytes(canonical(payload)) if valid else None,
            valid,
        )
    return "indeterminate", None, None, False


def _valid_forward_continuity_readiness(
    payload: Mapping[str, object], plan: Mapping[str, object]
) -> bool:
    """Validate the exact nested metadata-only forward-continuity readiness."""

    readiness = payload.get("forward_continuity")
    strategy = plan.get("strategy")
    if not isinstance(readiness, dict) or not isinstance(strategy, dict):
        return False
    expected_contract = expected_forward_continuity_contract()
    strategy_digest = strategy.get("strategy_digest")
    plan_digest = plan.get("plan_digest")
    contract_digest = expected_contract["contract_digest"]
    if (
        set(readiness)
        != {
            "contract_digest",
            "opaque_content_read",
            "persistent_mutation",
            "plan_digest",
            "readiness_digest",
            "schema",
            "status",
            "strategy_digest",
            "transition_deferred_to_action_ownership",
        }
        or readiness.get("schema") != FORWARD_CONTINUITY_READINESS_SCHEMA
        or readiness.get("status") != "ready"
        or readiness.get("opaque_content_read") is not False
        or readiness.get("persistent_mutation") is not False
        or readiness.get("transition_deferred_to_action_ownership") is not True
        or readiness.get("plan_digest") != plan_digest
        or readiness.get("strategy_digest") != strategy_digest
        or readiness.get("contract_digest") != contract_digest
        or plan.get("schema") != CONTROLLER_PLAN_SCHEMA
        or strategy.get("schema") != CONTROLLER_STRATEGY_SCHEMA
        or strategy.get("forward_continuity") != expected_contract
        or HEX64.fullmatch(str(plan_digest or "")) is None
        or HEX64.fullmatch(str(strategy_digest or "")) is None
    ):
        return False

    plan_body = dict(plan)
    plan_body.pop("plan_digest", None)
    plan_body.pop("schema", None)
    strategy_body = dict(strategy)
    strategy_body.pop("strategy_digest", None)
    readiness_body = dict(readiness)
    readiness_digest = readiness_body.pop("readiness_digest", None)
    return (
        digest_bytes(canonical(plan_body)) == plan_digest
        and digest_bytes(canonical(strategy_body)) == strategy_digest
        and isinstance(readiness_digest, str)
        and HEX64.fullmatch(readiness_digest) is not None
        and digest_bytes(canonical(readiness_body)) == readiness_digest
    )


def _validated_ready_plan(
    observation: ProcessObservation, *, expected_plan_digest: str
) -> dict[str, object]:
    try:
        plan = json.loads(observation.stdout.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherRejected("prepare_plan_rejected") from exc
    require(
        isinstance(plan, dict)
        and observation.stdout == canonical(plan) + b"\n"
        and plan.get("schema") == CONTROLLER_PLAN_SCHEMA
        and plan.get("plan_digest") == expected_plan_digest,
        "prepare_plan_rejected",
    )
    raw = dict(plan)
    plan_digest = raw.pop("plan_digest", None)
    plan_schema = raw.pop("schema", None)
    require(
        plan_schema == CONTROLLER_PLAN_SCHEMA
        and plan_digest == expected_plan_digest
        and digest_bytes(canonical(raw)) == expected_plan_digest,
        "prepare_plan_rejected",
    )
    return dict(plan)


def _parse_prepare_child(
    observation: ProcessObservation,
) -> tuple[str, str | None, str | None, bool]:
    if (
        not observation.process_created
        or observation.timed_out
        or observation.returncode is None
        or observation.returncode < 0
        or len(observation.stdout) > MAX_STDOUT_BYTES
        or len(observation.stderr) > MAX_STDERR_BYTES
        or observation.stderr
        or not observation.stdout
        or not observation.progress_valid
        or not observation.drain_completed
    ):
        return "indeterminate", None, None, False
    try:
        payload = json.loads(observation.stdout.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        return "indeterminate", None, None, False
    if not isinstance(payload, dict) or observation.stdout != canonical(payload) + b"\n":
        return "indeterminate", None, None, False
    if observation.returncode == 0:
        raw = dict(payload)
        plan_digest = raw.pop("plan_digest", None)
        plan_schema = raw.pop("schema", None)
        valid = (
            plan_schema == CONTROLLER_PLAN_SCHEMA
            and isinstance(plan_digest, str)
            and HEX64.fullmatch(plan_digest) is not None
            and digest_bytes(canonical(raw)) == plan_digest
            and observation.progress_complete
        )
        return (
            "ready" if valid else "indeterminate",
            plan_digest if valid else None,
            digest_bytes(canonical(payload)) if valid else None,
            valid,
        )
    if observation.returncode == 2:
        code = payload.get("code")
        category = payload.get("category")
        valid = (
            payload.get("schema") == CONTROLLER_CLI_RESULT_SCHEMA
            and payload.get("status") == "rejected"
            and isinstance(code, str)
            and SAFE_CODE.fullmatch(code) is not None
            and category in {"typed_rejection", "unexpected_controller_failure"}
            and payload.get("opaque_content_read") is False
            and payload.get("persistent_mutation") is False
            and payload.get("retryable") is False
            and set(payload)
            == {
                "category",
                "code",
                "opaque_content_read",
                "persistent_mutation",
                "retryable",
                "schema",
                "status",
            }
        )
        return (
            "rejected" if valid else "indeterminate",
            f"{category}:{code}" if valid else None,
            digest_bytes(canonical(payload)) if valid else None,
            valid,
        )
    return "indeterminate", None, None, False


def _parse_drift_child(
    observation: ProcessObservation,
    *,
    expected_plan_digest: str,
    expected_plan_sha256: str,
) -> tuple[str, str | None, str | None, bool]:
    if (
        not observation.process_created
        or observation.timed_out
        or observation.returncode is None
        or observation.returncode < 0
        or len(observation.stdout) > MAX_STDOUT_BYTES
        or len(observation.stderr) > MAX_STDERR_BYTES
        or observation.stderr
        or not observation.stdout
        or not observation.progress_valid
        or not observation.drain_completed
    ):
        return "indeterminate", None, None, False
    try:
        payload = json.loads(observation.stdout.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        return "indeterminate", None, None, False
    if not isinstance(payload, dict) or observation.stdout != canonical(payload) + b"\n":
        return "indeterminate", None, None, False
    if observation.returncode == 0:
        raw = dict(payload)
        plan_digest = raw.pop("plan_digest", None)
        plan_schema = raw.pop("schema", None)
        valid = (
            plan_schema == CONTROLLER_PLAN_SCHEMA
            and plan_digest == expected_plan_digest
            and digest_bytes(canonical(raw)) == expected_plan_digest
            and digest_bytes(observation.stdout) == expected_plan_sha256
            and observation.progress_complete
        )
        return (
            "ready" if valid else "indeterminate",
            plan_digest if valid else None,
            digest_bytes(canonical(payload)) if valid else None,
            valid,
        )
    if observation.returncode == 2:
        code = payload.get("code")
        category = payload.get("category")
        valid = (
            payload.get("schema") == CONTROLLER_CLI_RESULT_SCHEMA
            and payload.get("status") == "rejected"
            and isinstance(code, str)
            and SAFE_CODE.fullmatch(code) is not None
            and category in {"typed_rejection", "unexpected_controller_failure"}
            and payload.get("opaque_content_read") is False
            and payload.get("persistent_mutation") is False
            and payload.get("retryable") is False
            and set(payload)
            == {
                "category",
                "code",
                "opaque_content_read",
                "persistent_mutation",
                "retryable",
                "schema",
                "status",
            }
        )
        return (
            "rejected" if valid else "indeterminate",
            f"{category}:{code}" if valid else None,
            digest_bytes(canonical(payload)) if valid else None,
            valid,
        )
    return "indeterminate", None, None, False


def _elapsed_bucket(observation: ProcessObservation) -> str:
    elapsed = max(0, observation.ended_ns - observation.started_ns) / 1_000_000_000
    if elapsed < 15:
        return "lt_15s"
    if elapsed < 30:
        return "15_30s"
    if elapsed < 60:
        return "30_60s"
    if elapsed < 120:
        return "60_120s"
    if elapsed < 180:
        return "120_180s"
    return "gte_180s"


def _progress_projection(
    observation: ProcessObservation, *, role: str
) -> dict[str, object]:
    events = list(observation.progress_events)
    return {
        "drain_completed": observation.drain_completed,
        "elapsed_bucket": _elapsed_bucket(observation),
        "hard_timeout_seconds": ROLE_TIMEOUT_SECONDS[role],
        "no_progress_timeout_seconds": ROLE_NO_PROGRESS_TIMEOUT_SECONDS[role],
        "phase_liveness_binding_sha256": digest_bytes(canonical(events)),
        "phase_liveness_complete": observation.progress_complete,
        "phase_liveness_error": observation.progress_error,
        "phase_liveness_event_count": len(events),
        "phase_liveness_last_phase": events[-1]["phase"] if events else None,
        "phase_liveness_schema": PHASE_LIVENESS_SCHEMA,
        "phase_liveness_trace_sha256": _phase_trace_sha256(events, role),
        "termination_escalated": observation.termination_escalated,
        "timeout_class": observation.timeout_class,
    }


def capture_prepare_call(
    *,
    invocation: Mapping[str, object],
    evidence_root: Path,
    runner: ProcessRunner = _run_process,
) -> dict[str, object]:
    prepare = prepare_contract(invocation)
    selected = _prepare_directory(evidence_root, prepare)
    require(not (selected / "CLAIM.json").exists(), "prepare_replay_rejected")
    nonce = prepare_nonce(str(prepare["prepare_identity"]))
    claim = {
        "invocation_identity_sha256": invocation["invocation_identity_sha256"],
        "prepare_identity": prepare["prepare_identity"],
        "prepare_nonce": nonce,
        "schema": PREPARE_CLAIM_SCHEMA,
    }
    _write_exclusive(selected / "CLAIM.json", claim)
    argv = invocation.get("_argv")
    environment = invocation.get("_environment")
    require(
        isinstance(argv, list)
        and all(isinstance(item, str) for item in argv)
        and isinstance(environment, dict)
        and all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in environment.items()
        ),
        "invocation_contract_rejected",
    )
    try:
        observation = runner(
            argv,
            environment,
            Path(str(invocation["cwd"])),
            ROLE_TIMEOUT_SECONDS[ROLE_PREPARE],
            ROLE_PREPARE,
            nonce,
        )
    except BaseException:
        observation = ProcessObservation(
            False,
            None,
            time.time_ns(),
            time.time_ns(),
            None,
            False,
            b"",
            b"",
        )
    status, detail, parsed_identity, canonical_result = _parse_prepare_child(
        observation
    )
    validated_plan: dict[str, object] | None = None
    if status == "ready":
        try:
            require(detail is not None, "prepare_plan_rejected")
            validated_plan = _validated_ready_plan(
                observation, expected_plan_digest=detail
            )
        except LauncherRejected:
            status = "indeterminate"
            detail = None
            parsed_identity = None
            canonical_result = False
    if observation.timed_out:
        exit_class = "timeout"
    elif not observation.process_created:
        exit_class = "preinvocation_failure"
    elif observation.returncode is not None and observation.returncode < 0:
        exit_class = "signal"
    elif observation.returncode in (0, 2):
        exit_class = "exit"
    else:
        exit_class = "unexpected_exit"
    capture = {
        "argv_identity_sha256": invocation["argv_identity_sha256"],
        "canonical_result": canonical_result,
        "ended_ns": observation.ended_ns,
        "environment_identity_sha256": invocation["environment_identity_sha256"],
        "exit_class": exit_class,
        "exit_code": (
            observation.returncode
            if observation.returncode is not None and observation.returncode >= 0
            else None
        ),
        "invocation_identity_sha256": invocation["invocation_identity_sha256"],
        "parsed_result_identity_sha256": parsed_identity,
        "pid": observation.pid,
        "prepare_identity": prepare["prepare_identity"],
        "prepare_nonce": nonce,
        "process_created": observation.process_created,
        "raw_output_retained": False,
        "result_detail": detail,
        "schema": PREPARE_CAPTURE_SCHEMA,
        "signal": (
            -observation.returncode
            if observation.returncode is not None and observation.returncode < 0
            else None
        ),
        "started_ns": observation.started_ns,
        "status": status,
        "stderr_sha256": digest_bytes(observation.stderr),
        "stderr_size": len(observation.stderr),
        "stdout_sha256": digest_bytes(observation.stdout),
        "stdout_size": len(observation.stdout),
        "target_release_digest": invocation["target_release_digest"],
        "timed_out": observation.timed_out,
        **_progress_projection(observation, role=ROLE_PREPARE),
    }
    _write_exclusive(selected / "CAPTURE.json", capture)
    if status == "ready":
        require(
            detail is not None and validated_plan is not None,
            "prepare_plan_rejected",
        )
        plan = validated_plan
        _write_exclusive(selected / "PLAN.INPUT.json", plan)
        result = {
            "capture_identity_sha256": digest_bytes(canonical(capture)),
            "persistent_product_mutation": False,
            "plan_digest": detail,
            "plan_sha256": digest_bytes(canonical(plan) + b"\n"),
            "prepare_identity": prepare["prepare_identity"],
            "raw_output_retained": False,
            "schema": PREPARE_RESULT_SCHEMA,
            "status": "ready",
        }
        _write_exclusive(selected / "RESULT.json", result)
        return result
    return capture


def capture_formal_call(
    *,
    invocation: Mapping[str, object],
    evidence_root: Path,
    call_index: int,
    runner: ProcessRunner = _run_process,
) -> dict[str, object]:
    require(call_index in (1, 2), "call_index_rejected")
    sequence = sequence_contract(invocation)
    selected = _sequence_directory(evidence_root, sequence)
    if call_index == 2:
        require(
            (selected / "CALL-1.CAPTURE.json").is_file()
            and not (selected / "CALL-2.CLAIM.json").exists(),
            "call_order_rejected",
        )
    else:
        require(not (selected / "CALL-1.CLAIM.json").exists(), "capture_replay_rejected")
    nonce = call_nonce(str(sequence["sequence_identity"]), call_index)
    claim = {
        "call_index": call_index,
        "call_nonce": nonce,
        "invocation_identity_sha256": invocation["invocation_identity_sha256"],
        "schema": CLAIM_SCHEMA,
        "sequence_identity": sequence["sequence_identity"],
    }
    _write_exclusive(selected / f"CALL-{call_index}.CLAIM.json", claim)
    argv = invocation.get("_argv")
    environment = invocation.get("_environment")
    require(
        isinstance(argv, list)
        and all(isinstance(item, str) for item in argv)
        and isinstance(environment, dict)
        and all(isinstance(key, str) and isinstance(value, str) for key, value in environment.items()),
        "invocation_contract_rejected",
    )
    try:
        observation = runner(
            argv,
            environment,
            Path(str(invocation["cwd"])),
            ROLE_TIMEOUT_SECONDS[ROLE_FORMAL],
            ROLE_FORMAL,
            nonce,
        )
    except BaseException:
        observation = ProcessObservation(False, None, time.time_ns(), time.time_ns(), None, False, b"", b"")
    status, detail, parsed_identity, canonical_result = _parse_child(observation)
    if observation.timed_out:
        exit_class = "timeout"
    elif not observation.process_created:
        exit_class = "preinvocation_failure"
    elif observation.returncode is not None and observation.returncode < 0:
        exit_class = "signal"
    elif observation.returncode in (0, 2):
        exit_class = "exit"
    else:
        exit_class = "unexpected_exit"
    capture = {
        "argv_identity_sha256": invocation["argv_identity_sha256"],
        "call_index": call_index,
        "call_nonce": nonce,
        "canonical_result": canonical_result,
        "ended_ns": observation.ended_ns,
        "environment_identity_sha256": invocation["environment_identity_sha256"],
        "exit_class": exit_class,
        "exit_code": observation.returncode if observation.returncode is not None and observation.returncode >= 0 else None,
        "invocation_identity_sha256": invocation["invocation_identity_sha256"],
        "parsed_result_identity_sha256": parsed_identity,
        "pid": observation.pid,
        "process_created": observation.process_created,
        "raw_output_retained": False,
        "result_detail": detail,
        "schema": CAPTURE_SCHEMA,
        "sequence_identity": sequence["sequence_identity"],
        "signal": -observation.returncode if observation.returncode is not None and observation.returncode < 0 else None,
        "started_ns": observation.started_ns,
        "status": status,
        "stderr_sha256": digest_bytes(observation.stderr),
        "stderr_size": len(observation.stderr),
        "stdout_sha256": digest_bytes(observation.stdout),
        "stdout_size": len(observation.stdout),
        "target_release_digest": invocation["target_release_digest"],
        "timed_out": observation.timed_out,
        **_progress_projection(observation, role=ROLE_FORMAL),
    }
    _write_exclusive(selected / f"CALL-{call_index}.CAPTURE.json", capture)
    return capture


def capture_drift_call(
    *,
    invocation: Mapping[str, object],
    evidence_root: Path,
    runner: ProcessRunner = _run_process,
) -> dict[str, object]:
    drift = drift_contract(invocation)
    formal_invocation = {
        "invocation_identity_sha256": invocation[
            "formal_invocation_identity_sha256"
        ],
        "launcher_contract_digest": invocation["launcher_contract_digest"],
        "role": ROLE_FORMAL,
        "source_binding_digest": invocation["source_binding_digest"],
        "target_release_digest": invocation["target_release_digest"],
    }
    require(
        sequence_contract(formal_invocation)["sequence_identity"]
        == invocation["formal_sequence_identity"],
        "exact_two_sequence_rejected",
    )
    formal_result_path = (
        evidence_root
        / "formal-sequences"
        / str(invocation["formal_sequence_identity"])
        / "RESULT.json"
    )

    def require_exact_two() -> None:
        validate_persisted_exact_two(
            invocation=formal_invocation,
            evidence_root=evidence_root,
        )
        require(
            digest_file(formal_result_path)
            == invocation["formal_result_sha256"],
            "exact_two_sequence_rejected",
        )

    require_exact_two()
    selected = _drift_directory(evidence_root, drift)
    require(
        not (selected / "CLAIM.json").exists(),
        "drift_replay_rejected",
    )
    nonce = drift_nonce(str(drift["drift_identity"]))
    claim = {
        "call_index": 1,
        "drift_identity": drift["drift_identity"],
        "drift_nonce": nonce,
        "invocation_identity_sha256": invocation["invocation_identity_sha256"],
        "schema": DRIFT_CLAIM_SCHEMA,
    }
    _write_exclusive(selected / "CLAIM.json", claim)
    require_exact_two()
    argv = invocation.get("_argv")
    environment = invocation.get("_environment")
    require(
        isinstance(argv, list)
        and len(argv) == 5
        and argv[0] == str(INTERPRETER)
        and argv[1] == str(DEPLOY_ROOT / CONTROLLER_RELATIVE)
        and argv[2:4] == ["verify", "--plan"]
        and isinstance(argv[4], str)
        and isinstance(environment, dict)
        and all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in environment.items()
        )
        and environment == FIXED_ENVIRONMENT,
        "drift_invocation_contract_rejected",
    )
    plan_path = Path(argv[4])

    def require_plan_exact() -> None:
        require(
            plan_path.resolve().parent
            == evidence_root.resolve()
            / "prepare-captures"
            / str(invocation["prepare_identity"]),
            "drift_plan_identity_rejected",
        )
        _, projection = _load_plan_input(plan_path)
        require(
            projection["plan_digest"] == invocation["plan_digest"]
            and projection["sha256"] == invocation["plan_sha256"],
            "drift_plan_identity_rejected",
        )

    require_plan_exact()
    try:
        observation = runner(
            argv,
            environment,
            Path(str(invocation["cwd"])),
            ROLE_TIMEOUT_SECONDS[ROLE_DRIFT],
            ROLE_DRIFT,
            nonce,
        )
    except BaseException:
        observation = ProcessObservation(
            False, None, time.time_ns(), time.time_ns(), None, False, b"", b""
        )
    require_exact_two()
    require_plan_exact()
    status, detail, parsed_identity, canonical_result = _parse_drift_child(
        observation,
        expected_plan_digest=str(invocation["plan_digest"]),
        expected_plan_sha256=str(invocation["plan_sha256"]),
    )
    if observation.timed_out:
        exit_class = "timeout"
    elif not observation.process_created:
        exit_class = "preinvocation_failure"
    elif observation.returncode is not None and observation.returncode < 0:
        exit_class = "signal"
    elif observation.returncode in (0, 2):
        exit_class = "exit"
    else:
        exit_class = "unexpected_exit"
    capture = {
        "argv_identity_sha256": invocation["argv_identity_sha256"],
        "call_index": 1,
        "canonical_result": canonical_result,
        "drift_identity": drift["drift_identity"],
        "drift_nonce": nonce,
        "ended_ns": observation.ended_ns,
        "environment_identity_sha256": invocation["environment_identity_sha256"],
        "exit_class": exit_class,
        "exit_code": (
            observation.returncode
            if observation.returncode is not None and observation.returncode >= 0
            else None
        ),
        "invocation_identity_sha256": invocation["invocation_identity_sha256"],
        "parsed_result_identity_sha256": parsed_identity,
        "pid": observation.pid,
        "plan_digest": invocation["plan_digest"],
        "plan_sha256": invocation["plan_sha256"],
        "prepare_identity": invocation["prepare_identity"],
        "process_created": observation.process_created,
        "raw_output_retained": False,
        "result_detail": detail,
        "schema": DRIFT_CAPTURE_SCHEMA,
        "signal": (
            -observation.returncode
            if observation.returncode is not None and observation.returncode < 0
            else None
        ),
        "started_ns": observation.started_ns,
        "status": status,
        "stderr_sha256": digest_bytes(observation.stderr),
        "stderr_size": len(observation.stderr),
        "stdout_sha256": digest_bytes(observation.stdout),
        "stdout_size": len(observation.stdout),
        "target_release_digest": invocation["target_release_digest"],
        "timed_out": observation.timed_out,
        **_progress_projection(observation, role=ROLE_DRIFT),
    }
    _write_exclusive(selected / "CAPTURE.json", capture)
    if status == "ready":
        result = {
            "call_count": 1,
            "capture_identity_sha256": digest_bytes(canonical(capture)),
            "drift_identity": drift["drift_identity"],
            "persistent_product_mutation": False,
            "plan_digest": invocation["plan_digest"],
            "prepare_identity": invocation["prepare_identity"],
            "raw_output_retained": False,
            "result_identity_sha256": parsed_identity,
            "schema": DRIFT_RESULT_SCHEMA,
            "status": "ready",
        }
        _write_exclusive(selected / "RESULT.json", result)
        return result
    return capture


def _load_capture(path: Path) -> dict[str, object]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_uid == EXPECTED_UID
            and before.st_gid == EXPECTED_GID
            and 0 < before.st_size <= MAX_JSON_BYTES,
            "capture_evidence_rejected",
        )
        chunks: list[bytes] = []
        observed = 0
        while observed < before.st_size:
            block = os.read(descriptor, min(65_536, before.st_size - observed))
            require(bool(block), "capture_evidence_rejected")
            chunks.append(block)
            observed += len(block)
        require(not os.read(descriptor, 1), "capture_evidence_rejected")
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        require(
            observed == before.st_size
            and (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_uid,
                before.st_gid,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            "capture_evidence_rejected",
        )
        payload = json.loads(raw.decode("ascii", "strict"))
    except LauncherRejected:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherRejected("capture_evidence_rejected") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    require(
        isinstance(payload, dict) and raw == canonical(payload) + b"\n",
        "capture_evidence_rejected",
    )
    return payload


def _validated_exact_two(
    *,
    invocation: Mapping[str, object],
    evidence_root: Path,
    existing_only: bool = False,
) -> tuple[Path, dict[str, object]]:
    sequence = sequence_contract(invocation)
    selected = (
        _existing_sequence_directory(evidence_root, sequence)
        if existing_only
        else _sequence_directory(evidence_root, sequence)
    )
    first = _load_capture(selected / "CALL-1.CAPTURE.json")
    second = _load_capture(selected / "CALL-2.CAPTURE.json")
    common_keys = (
        "argv_identity_sha256",
        "environment_identity_sha256",
        "hard_timeout_seconds",
        "invocation_identity_sha256",
        "no_progress_timeout_seconds",
        "parsed_result_identity_sha256",
        "phase_liveness_complete",
        "phase_liveness_error",
        "phase_liveness_event_count",
        "phase_liveness_last_phase",
        "phase_liveness_schema",
        "phase_liveness_trace_sha256",
        "sequence_identity",
        "status",
        "stderr_sha256",
        "stderr_size",
        "stdout_sha256",
        "stdout_size",
        "target_release_digest",
        "timeout_class",
    )
    require(
        first.get("schema") == CAPTURE_SCHEMA
        and second.get("schema") == CAPTURE_SCHEMA
        and first.get("call_index") == 1
        and second.get("call_index") == 2
        and first.get("call_nonce") == call_nonce(str(sequence["sequence_identity"]), 1)
        and second.get("call_nonce") == call_nonce(str(sequence["sequence_identity"]), 2)
        and all(first.get(key) == second.get(key) for key in common_keys)
        and first.get("status") == "ready"
        and first.get("process_created") is True
        and second.get("process_created") is True
        and first.get("exit_code") == 0
        and second.get("exit_code") == 0
        and first.get("stderr_size") == 0
        and second.get("stderr_size") == 0
        and first.get("canonical_result") is True
        and second.get("canonical_result") is True
        and first.get("phase_liveness_complete") is True
        and second.get("phase_liveness_complete") is True
        and first.get("phase_liveness_error") is None
        and second.get("phase_liveness_error") is None
        and first.get("drain_completed") is True
        and second.get("drain_completed") is True,
        "exact_two_sequence_rejected",
    )
    result = {
        "calls": 2,
        "invocation_identity_sha256": invocation["invocation_identity_sha256"],
        "persistent_product_mutation": False,
        "result_identity_sha256": first["parsed_result_identity_sha256"],
        "schema": SEQUENCE_RESULT_SCHEMA,
        "sequence_identity": sequence["sequence_identity"],
        "status": "ready",
        "stdout_sha256": first["stdout_sha256"],
    }
    return selected, result


def verify_exact_two(
    *, invocation: Mapping[str, object], evidence_root: Path
) -> dict[str, object]:
    selected, result = _validated_exact_two(
        invocation=invocation, evidence_root=evidence_root
    )
    _write_exclusive(selected / "RESULT.json", result)
    return result


def validate_persisted_exact_two(
    *, invocation: Mapping[str, object], evidence_root: Path
) -> dict[str, object]:
    selected, expected = _validated_exact_two(
        invocation=invocation,
        evidence_root=evidence_root,
        existing_only=True,
    )
    observed = _load_capture(selected / "RESULT.json")
    require(observed == expected, "exact_two_sequence_rejected")
    return observed


def main(argv: Sequence[str] | None = None) -> int:
    try:
        parser = CanonicalArgumentParser(add_help=False)
        commands = parser.add_subparsers(
            dest="command", required=True, parser_class=CanonicalArgumentParser
        )
        prepare = commands.add_parser("prepare-capture", add_help=False)
        prepare.add_argument("--target-release", type=Path, required=True)
        capture = commands.add_parser("formal-capture", add_help=False)
        capture.add_argument("--target-release", type=Path, required=True)
        capture.add_argument(
            "--call-index", type=int, choices=(1, 2), required=True
        )
        drift = commands.add_parser("drift-capture", add_help=False)
        drift.add_argument("--target-release", type=Path, required=True)
        drift.add_argument("--plan", type=Path, required=True)
        verify = commands.add_parser("verify-formal-sequence", add_help=False)
        verify.add_argument("--target-release", type=Path, required=True)
        values = parser.parse_args(argv)
        os.chdir(DEPLOY_ROOT)
        _validate_runtime_identity()
        evidence_root = EVIDENCE_ROOT
        if values.command == "prepare-capture":
            invocation = production_invocation_contract(
                values.target_release.resolve(), role=ROLE_PREPARE
            )
            result = capture_prepare_call(
                invocation=invocation,
                evidence_root=evidence_root,
            )
        elif values.command == "drift-capture":
            invocation = production_invocation_contract(
                values.target_release.resolve(),
                role=ROLE_DRIFT,
                plan_path=values.plan,
            )
            result = capture_drift_call(
                invocation=invocation,
                evidence_root=evidence_root,
            )
        else:
            invocation = production_invocation_contract(
                values.target_release.resolve(), role=ROLE_FORMAL
            )
            result = (
                capture_formal_call(
                    invocation=invocation,
                    evidence_root=evidence_root,
                    call_index=values.call_index,
                )
                if values.command == "formal-capture"
                else verify_exact_two(
                    invocation=invocation, evidence_root=evidence_root
                )
            )
        print(canonical(result).decode("ascii"))
        if values.command in {
            "prepare-capture",
            "drift-capture",
            "verify-formal-sequence",
        }:
            if result["status"] == "ready":
                return 0
            return 2 if result["status"] == "rejected" else 3
        return 0 if result["status"] == "ready" else 2 if result["status"] == "rejected" else 3
    except LauncherRejected as exc:
        print(
            canonical(
                {"code": exc.code, "schema": CLI_RESULT_SCHEMA, "status": "rejected"}
            ).decode("ascii")
        )
        return 2
    except Exception:
        print(
            canonical(
                {
                    "code": "unexpected_launcher_failure",
                    "schema": CLI_RESULT_SCHEMA,
                    "status": "rejected",
                }
            ).decode("ascii")
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
