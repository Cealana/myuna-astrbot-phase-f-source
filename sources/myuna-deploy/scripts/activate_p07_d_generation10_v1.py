#!/usr/bin/env python3
"""Rollback-bound generation-10 P07-D successor release-set activation."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
from typing import Mapping

from activate_p07_hybrid_external_generation_v1 import (
    ActivationRejected,
    CORE_BINDING,
    CORE_GATE,
    CORE_RELEASE_ROOT,
    CORE_SELECTOR,
    RUNTIME_ROOT,
    TELEGRAM_RUNTIME_USER,
    TELEGRAM_SERVICE,
    TELEGRAM_SOCKET,
    active,
    atomic_write,
    core_evidence,
    digest_bytes,
    digest_file,
    install_tree,
    optional_bytes,
    render_core_binding,
    render_telegram_dropin,
    restore_optional,
    show,
    systemctl,
    tree_inventory,
    validate_immutable_release_tree,
    validate_runtime,
    verify_runtime_startup_smoke,
)
from activate_p07_external_epoch_rollover_v1 import (
    CORE_SERVICE,
    SELECTOR_PATH,
    TELEGRAM_CONFIG,
    TELEGRAM_DROPIN,
    NEW_EPOCH_DATABASE as B_V4_EPOCH_DATABASE,
    inspect_epoch_metadata,
    load_target_runtime_config_snapshot,
    require_resume_config_not_binding_source,
    validate_selector_payload as validate_b_v4_selector_payload,
)
from external_context_epoch_v3 import (
    ExternalEpochV3Binding,
    ExternalEpochV3Rejected,
    ExternalEpochV3Store,
)
from external_epoch_bundle import (
    ExternalEpochBundleRejected,
    inspect_epoch_bundle,
    require_same_bundle,
    restore_epoch_bundle_permissions,
    seal_epoch_bundle,
)
from myuna_core.external_context.release_set import (
    P07DReleaseSet,
    RELEASE_SET_EPOCH_ID_10,
    RELEASE_SET_EPOCH_PATH_10,
)
from p07_credential_binding import (
    CREDENTIAL_NAME,
    CredentialBindingRejected,
    effective_credential_declarations,
    verify_effective_credential,
    verify_strict_binding,
)
from p07_d_activation_transaction import (
    ActivationPrestate,
    AtomicReleaseSetTransaction,
    FunctionalObservation,
    ReleaseSetActivationRejected,
    ServiceObservation,
    TargetPreflightObservation,
)
from p07_d_generation10_release_set import (
    GENERATION,
    build_release_set,
    canonical,
    digest,
    protected_manifest_path,
    rollback_manifest_digest,
    selector_payload,
    service_binding_digest,
)
from p07_d_generation13_release_set import phase_f_selected_target
from p07_d_release_set import (
    ProtectedReleaseSetSnapshot,
    load_protected_release_set_snapshot,
    runtime_binding_digest,
)
from p07_d_release_set_acl import (
    ReleaseSetAclRejected,
    apply_release_set_acl,
    inspect_release_set_acl,
)
from p07_d_runtime_readiness import (
    SCHEMA as RUNTIME_READINESS_SCHEMA,
    RuntimeProcessObservation,
    content_free_metadata_digest,
    readiness_path,
    wait_for_runtime_readiness,
)

RELEASE_SET_EPOCH_ID = RELEASE_SET_EPOCH_ID_10
RELEASE_SET_EPOCH_PATH = RELEASE_SET_EPOCH_PATH_10


SCHEMA = "myuna.p07-d-generation10-activation.v1"
RELEASE_SET_PATH = protected_manifest_path()
CORE_DROPIN_ROOT = Path("/etc/systemd/system/myuna-core@qq.service.d")
CORE_CREDENTIAL_SOURCE = Path("/etc/myuna/secrets/deepseek-api-key")
EFFECTIVE_CREDENTIAL = Path(f"/run/credentials/{CORE_SERVICE}/{CREDENTIAL_NAME}")
EFFECTIVE_V6_ENV = Path("/etc/myuna/effective-v6.env")
OWNER_RUNTIME_CONFIG = Path("/etc/myuna-telegram-gateway/owner-runtime-v1.json")
BACKUP_ROOT = Path("/var/backups/myuna/p07-d-generation10-activation-v1")
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07-d-generation9-activation-v1")
ATTEMPT_LEDGER = Path(
    "/var/lib/myuna-telegram-gateway/p07-d-generation9-activation-v1/"
    "ATTEMPT_LEDGER.json"
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TYPED_FAILURE_GATE = re.compile(r"^[a-z][a-z0-9_]{2,127}$")


class Generation10ActivationRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _failure_projection(exc: Exception) -> dict[str, str]:
    final_gate = getattr(exc, "code", None)
    if not isinstance(final_gate, str) or _TYPED_FAILURE_GATE.fullmatch(final_gate) is None:
        final_gate = "generation10_activation_rejected"
    projection = {"failure_gate": final_gate}
    for attribute, field in (
        ("activation_failure_code", "activation_failure_gate"),
        ("rollback_failure_code", "rollback_failure_gate"),
    ):
        candidate = getattr(exc, attribute, None)
        if isinstance(candidate, str) and _TYPED_FAILURE_GATE.fullmatch(candidate) is not None:
            projection[field] = candidate
    return projection


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Generation10ActivationRejected(code)


def _safe_file_projection(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    require(not path.is_symlink() and stat.S_ISREG(metadata.st_mode), "protected_file_type_rejected")
    return {
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": path.as_posix(),
        "sha256": digest_file(path),
        "size": metadata.st_size,
        "uid": metadata.st_uid,
    }


def _credential_projection() -> dict[str, object]:
    strict = verify_strict_binding(
        CORE_DROPIN_ROOT,
        canonical_dropin="credentials.conf",
        expected_source=CORE_CREDENTIAL_SOURCE,
    )
    effective = effective_credential_declarations(CORE_DROPIN_ROOT)
    require(len(effective) == 1 and effective[0][1] == CORE_CREDENTIAL_SOURCE, "credential_projection_rejected")
    dropins = tuple(
        _safe_file_projection(path)
        for path in sorted(CORE_DROPIN_ROOT.glob("*.conf"), key=lambda item: item.name)
    )
    effective_metadata = verify_effective_credential(EFFECTIVE_CREDENTIAL)
    dropin_set_digest = digest("myuna-p07-d-credential-dropin-set-v1", dropins)
    projection = {
        "effective_count": 1,
        "effective_source": CORE_CREDENTIAL_SOURCE.as_posix(),
        "name": CREDENTIAL_NAME,
        "source_category": "systemd_load_credential",
    }
    return {
        **projection,
        "dropin_set_digest": dropin_set_digest,
        "projection_digest": digest(
            "myuna-p07-d-effective-credential-v1",
            {**projection, "effective_metadata": effective_metadata, "strict_status": strict["status"]},
        ),
    }


def _load_v6_release() -> str:
    metadata = EFFECTIVE_V6_ENV.lstat()
    require(
        not EFFECTIVE_V6_ENV.is_symlink()
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and stat.S_IMODE(metadata.st_mode) & 0o007 == 0,
        "effective_v6_metadata_rejected",
    )
    selected: list[str] = []
    for raw_line in EFFECTIVE_V6_ENV.read_text("utf-8").splitlines():
        if raw_line.startswith("MYUNA_DEFINITION_RELEASE="):
            selected.append(raw_line.split("=", 1)[1])
    require(len(selected) == 1 and selected[0].startswith("v6-") and "v7" not in selected[0].lower(), "effective_v6_selection_rejected")
    return selected[0]


def _load_b_selector() -> tuple[bytes, dict[str, object]]:
    metadata = SELECTOR_PATH.lstat()
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    require(
        not SELECTOR_PATH.is_symlink()
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == telegram_gid
        and stat.S_IMODE(metadata.st_mode) == 0o640,
        "b_selector_metadata_rejected",
    )
    raw = SELECTOR_PATH.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Generation10ActivationRejected("b_selector_document_rejected") from exc
    validate_b_v4_selector_payload(payload)
    require(payload["generation"] == 4 and raw == canonical(payload), "b_selector_rejected")
    return raw, payload


def _expected_b_metadata(
    *, revision: int, turns: int, summaries: int, pending: int,
) -> dict[str, object]:
    observed = inspect_epoch_metadata(B_V4_EPOCH_DATABASE)
    require(
        observed.get("schema_name") == "myuna.external-authorized-epoch.v1"
        and observed.get("schema_version") == 1
        and observed.get("selected_revision") == revision
        and observed.get("max_revision") == revision
        and observed.get("turn_count") == turns
        and observed.get("summary_count") == summaries
        and observed.get("pending_count") == pending == 0,
        "b_epoch_metadata_rejected",
    )
    return observed


def _service_observation(unit: str) -> ServiceObservation:
    raw_restarts = show(unit, "NRestarts")
    require(
        raw_restarts.isdigit() or (unit.endswith(".socket") and raw_restarts == ""),
        "service_restart_projection_rejected",
    )
    return ServiceObservation(
        unit=unit,
        active_state=show(unit, "ActiveState"),
        sub_state=show(unit, "SubState"),
        result=show(unit, "Result"),
        nrestarts=int(raw_restarts or "0"),
    )


def _runtime_process_observation() -> RuntimeProcessObservation:
    raw_restarts = show(TELEGRAM_SERVICE, "NRestarts")
    raw_pid = show(TELEGRAM_SERVICE, "MainPID")
    require(raw_restarts.isdigit() and raw_pid.isdigit(), "runtime_process_projection_rejected")
    return RuntimeProcessObservation(
        active_state=show(TELEGRAM_SERVICE, "ActiveState"),
        sub_state=show(TELEGRAM_SERVICE, "SubState"),
        result=show(TELEGRAM_SERVICE, "Result"),
        nrestarts=int(raw_restarts),
        main_pid=int(raw_pid),
        invocation_id=show(TELEGRAM_SERVICE, "InvocationID"),
    )
def _file_digest_or_absent(path: Path) -> str:
    if not path.exists() and not path.is_symlink():
        return digest("myuna-p07-d-absent-v1", {"path": path.as_posix()})
    return digest_file(path)


def _prestate_service_bindings() -> tuple[tuple[str, str], ...]:
    return tuple(sorted((
        (CORE_SERVICE, digest("myuna-p07-d-prestate-service-v1", {
            "binding": digest_file(CORE_BINDING), "gate": _file_digest_or_absent(CORE_GATE),
            "selector": digest_file(CORE_SELECTOR), "unit": CORE_SERVICE,
        })),
        (TELEGRAM_SERVICE, digest("myuna-p07-d-prestate-service-v1", {
            "dropin": digest_file(TELEGRAM_DROPIN), "selector": digest_file(SELECTOR_PATH),
            "resume_config": digest_file(TELEGRAM_CONFIG),
            "unit": TELEGRAM_SERVICE,
        })),
        (TELEGRAM_SOCKET, digest("myuna-p07-d-prestate-service-v1", {"unit": TELEGRAM_SOCKET})),
    )))


def _render_core_gate() -> bytes:
    return (
        "[Service]\n"
        "Environment=MYUNA_P07_HYBRID_EXTERNAL_ENABLED=true\n"
        "Environment=MYUNA_P07_D_RELEASE_SET_ENABLED=true\n"
    ).encode("ascii")


@dataclass(slots=True)
class PreparedActivation:
    core_candidate: Path
    runtime_candidate: Path
    core_commit: str
    deploy_commit: str
    release_set: P07DReleaseSet
    release_set_bytes: bytes
    selector_bytes: bytes
    core_binding_bytes: bytes
    core_selector_bytes: bytes
    core_gate_bytes: bytes
    telegram_dropin_bytes: bytes
    plan_bytes: bytes
    prestate: dict[str, object]

    @property
    def plan_digest(self) -> str:
        return digest_bytes(self.plan_bytes)


def _target_service_bindings(
    *,
    core_uid: int,
    core_gid: int,
    telegram_uid: int,
    telegram_gid: int,
    core_release: str,
    runtime_release: str,
    selector_digest: str,
    runtime_config_digest: str,
    acl_digest: str,
) -> tuple[dict[str, object], ...]:
    definitions = (
        ("core", CORE_SERVICE, core_uid, core_gid, {
            "/target/core-release": core_release,
            "/target/gate": digest_bytes(_render_core_gate()),
        }),
        ("telegram", TELEGRAM_SERVICE, telegram_uid, telegram_gid, {
            "/target/runtime-release": runtime_release,
            readiness_path(RELEASE_SET_EPOCH_PATH).as_posix(): digest(
                "myuna-p07-d-runtime-readiness-contract-v1",
                {
                    "path": readiness_path(RELEASE_SET_EPOCH_PATH).as_posix(),
                    "schema": RUNTIME_READINESS_SCHEMA,
                },
            ),
            SELECTOR_PATH.as_posix(): selector_digest,
            OWNER_RUNTIME_CONFIG.as_posix(): runtime_config_digest,
        }),
        ("telegram_socket", TELEGRAM_SOCKET, telegram_uid, telegram_gid, {
            "/target/socket-contract": digest("myuna-p07-d-socket-v1", {"unit": TELEGRAM_SOCKET}),
        }),
    )
    return tuple({
        "binding_digest": service_binding_digest(
            kind=kind,
            unit=unit,
            uid=uid,
            gid=gid,
            binding_files=files,
            release_set_acl_digest=acl_digest,
        ),
        "desired_state": "active",
        "gid": gid,
        "kind": kind,
        "stable_observation_seconds": 5,
        "uid": uid,
        "unit": unit,
    } for kind, unit, uid, gid, files in definitions)


def prepare_activation(
    core_candidate: Path,
    runtime_candidate: Path,
    *,
    core_commit: str,
    deploy_commit: str,
    expected_core_release: str,
    expected_runtime_release: str,
    expected_definition_release: str,
    expected_b_epoch_sha256: str,
    expected_revision: int,
    expected_turns: int,
    expected_summaries: int,
    expected_pending: int,
) -> PreparedActivation:
    require(os.geteuid() == 0, "root_identity_required")
    require(_COMMIT.fullmatch(core_commit) is not None and _COMMIT.fullmatch(deploy_commit) is not None, "source_commit_rejected")
    for value in (expected_core_release, expected_runtime_release, expected_b_epoch_sha256):
        require(_DIGEST.fullmatch(value) is not None, "expected_digest_rejected")
    require(active(CORE_SERVICE) and active(TELEGRAM_SERVICE) and active(TELEGRAM_SOCKET), "b_services_inactive")
    require(
        not RELEASE_SET_PATH.exists() and not RELEASE_SET_PATH.is_symlink(),
        "b_release_set_prestate_rejected",
    )
    require(show(CORE_SERVICE, "WorkingDirectory").endswith(expected_core_release), "b_core_release_drifted")
    require(f"/{expected_runtime_release}/runtime/telegram_owner_runtime_gateway.py" in show(TELEGRAM_SERVICE, "ExecStart"), "b_runtime_release_drifted")
    require(_load_v6_release() == expected_definition_release, "effective_v6_release_drifted")
    resume_config = json.loads(TELEGRAM_CONFIG.read_text("utf-8"))
    require_resume_config_not_binding_source(resume_config)
    credential = _credential_projection()
    verify_effective_credential(EFFECTIVE_CREDENTIAL)
    b_selector_bytes, b_selector = _load_b_selector()
    require(not Path(RELEASE_SET_EPOCH_PATH).parent.exists() and not Path(RELEASE_SET_EPOCH_PATH).parent.is_symlink(), "generation10_epoch_preexisting")
    first_config = load_target_runtime_config_snapshot()
    b_metadata = _expected_b_metadata(
        revision=expected_revision,
        turns=expected_turns,
        summaries=expected_summaries,
        pending=expected_pending,
    )
    telegram_identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    first_bundle = inspect_epoch_bundle(
        B_V4_EPOCH_DATABASE,
        expected_file_mode=0o600,
        expected_parent_mode=0o700,
        expected_uid=telegram_identity.pw_uid,
        expected_gid=telegram_identity.pw_gid,
    )
    database_entry = next(
        item for item in first_bundle["bundle_projection"]["files"] if item["name"] == "epoch.db"
    )
    require(database_entry["sha256"] == expected_b_epoch_sha256, "b_epoch_digest_drifted")
    time.sleep(0.25)
    second_bundle = inspect_epoch_bundle(
        B_V4_EPOCH_DATABASE,
        expected_file_mode=0o600,
        expected_parent_mode=0o700,
        expected_uid=telegram_identity.pw_uid,
        expected_gid=telegram_identity.pw_gid,
    )
    b_bundle_digest = require_same_bundle(first_bundle, second_bundle)
    second_config = load_target_runtime_config_snapshot()
    require(first_config == second_config, "runtime_config_snapshot_drifted")
    core, _artifact, _receipt = core_evidence(core_candidate)
    require(core.source_commit == core_commit and core.tree_sha256 == core_candidate.name, "core_candidate_rejected")
    runtime_release = validate_runtime(runtime_candidate, core_commit, deploy_commit)
    verify_runtime_startup_smoke(runtime_candidate)
    core_inventory = tree_inventory(core_candidate)
    runtime_inventory = tree_inventory(runtime_candidate)
    require(len(core_inventory) == core.file_count, "core_candidate_inventory_rejected")
    selector_bytes = canonical(selector_payload(b_bundle_digest))
    selector_digest = digest_bytes(selector_bytes)
    runtime_config = first_config.config
    runtime_config_binding = runtime_binding_digest(
        channel_kind=runtime_config.channel_kind,
        client_id="telegram-owner-private",
        principal_id=runtime_config.principal_id,
        namespace_id=runtime_config.namespace_id,
    )
    core_identity = pwd.getpwnam("myuna")
    acl_payload = {
        "core_uid": core_identity.pw_uid,
        "entries": sorted((
            "group::---", "mask::r--", "other::---", "user::rw-",
            f"user:{core_identity.pw_uid}:r--", f"user:{telegram_identity.pw_uid}:r--",
        )),
        "file_gid": 0,
        "file_mode": 0o640,
        "file_uid": 0,
        "schema": "myuna.p07-d-release-set-acl.v1",
        "telegram_uid": telegram_identity.pw_uid,
    }
    acl_digest = sha256(b"myuna-p07-d-release-set-acl-v1\0" + json.dumps(acl_payload, separators=(",", ":"), sort_keys=True).encode("ascii")).hexdigest()
    services = _target_service_bindings(
        core_uid=core_identity.pw_uid,
        core_gid=core_identity.pw_gid,
        telegram_uid=telegram_identity.pw_uid,
        telegram_gid=telegram_identity.pw_gid,
        core_release=core.tree_sha256,
        runtime_release=runtime_release,
        selector_digest=selector_digest,
        runtime_config_digest=first_config.content_sha256,
        acl_digest=acl_digest,
    )
    prestate_files = {
        "core_binding": _safe_file_projection(CORE_BINDING),
        "core_gate": _safe_file_projection(CORE_GATE) if CORE_GATE.exists() else None,
        "core_selector": _safe_file_projection(CORE_SELECTOR),
        "release_set": _safe_file_projection(RELEASE_SET_PATH) if RELEASE_SET_PATH.exists() else None,
        "selector": _safe_file_projection(SELECTOR_PATH),
        "telegram_dropin": _safe_file_projection(TELEGRAM_DROPIN),
        "telegram_resume_config": _safe_file_projection(TELEGRAM_CONFIG),
    }
    prestate_services = tuple(_service_observation(unit) for unit in (CORE_SERVICE, TELEGRAM_SERVICE, TELEGRAM_SOCKET))
    require(all(item.active_state == "active" and item.result == "success" for item in prestate_services), "b_service_state_rejected")
    prestate = {
        "b_bundle": second_bundle,
        "b_epoch_metadata": b_metadata,
        "b_selector": b_selector,
        "credential": credential,
        "definition_release": expected_definition_release,
        "files": prestate_files,
        "runtime_config": first_config.projection(),
        "service_bindings": list(_prestate_service_bindings()),
        "services": [item.__dict__ if hasattr(item, "__dict__") else {
            "active_state": item.active_state, "nrestarts": item.nrestarts,
            "result": item.result, "sub_state": item.sub_state, "unit": item.unit,
        } for item in prestate_services],
    }
    rollback_manifest = {
        "files": prestate_files,
        "selector_digest": digest_bytes(b_selector_bytes),
        "service_bindings": prestate["service_bindings"],
        "services": prestate["services"],
    }
    release_set = build_release_set(
        core={
            "entrypoint": (CORE_RELEASE_ROOT / core.tree_sha256 / "src/myuna_core/__main__.py").as_posix(),
            "file_count": len(core_inventory),
            "inventory_digest": digest("myuna-p07-d-core-inventory-v1", core_inventory),
            "release_digest": core.tree_sha256,
            "tree_digest": core.tree_sha256,
        },
        telegram_runtime={
            "entrypoint": (RUNTIME_ROOT / runtime_release / "runtime/telegram_owner_runtime_gateway.py").as_posix(),
            "file_count": len(runtime_inventory),
            "inventory_digest": digest("myuna-p07-d-runtime-inventory-v1", runtime_inventory),
            "release_digest": runtime_release,
        },
        selector={
            "digest": selector_digest,
            "generation": GENERATION,
            "path": SELECTOR_PATH.as_posix(),
            "schema": "myuna.external-epoch-selector.v2",
        },
        runtime_config={
            "binding_digest": runtime_config_binding,
            "channel_kind": runtime_config.channel_kind,
            "digest": first_config.content_sha256,
            "gid": first_config.gid,
            "mode": first_config.mode,
            "namespace_id": runtime_config.namespace_id,
            "path": OWNER_RUNTIME_CONFIG.as_posix(),
            "principal_id": runtime_config.principal_id,
            "uid": first_config.uid,
        },
        credential=credential,
        epoch_uid=telegram_identity.pw_uid,
        epoch_gid=telegram_identity.pw_gid,
        services=services,
        rollback={
            "core_release_digest": expected_core_release,
            "desired_service_states_digest": digest("myuna-p07-d-service-prestate-v1", prestate["services"]),
            "epoch_bundle_digest": b_bundle_digest,
            "manifest_digest": rollback_manifest_digest(rollback_manifest),
            "runtime_release_digest": expected_runtime_release,
            "selector_digest": digest_bytes(b_selector_bytes),
        },
    )
    release_set_bytes = canonical(release_set.as_payload())
    plan_preimage = {
        "boundaries": {
            "channel": "authenticated-telegram-owner-private-only",
            "definition_profile": "effective-v6",
            "model_channel_provider_called": False,
            "old_epoch_content_migrated": False,
            "p01b_or_qq_changed": False,
        },
        "candidates": {
            "core_commit": core_commit,
            "core_release": core.tree_sha256,
            "deploy_commit": deploy_commit,
            "runtime_release": runtime_release,
        },
        "executor_sha256": digest_file(Path(__file__).resolve()),
        "prestate_digest": digest("myuna-p07-d-generation10-prestate-v1", prestate),
        "release_set_file_sha256": digest_bytes(release_set_bytes),
        "release_set_id": release_set.release_set_id,
        "rollback_manifest_digest": release_set.rollback["manifest_digest"],
        "schema": SCHEMA,
        "target_epoch": RELEASE_SET_EPOCH_PATH,
    }
    plan_bytes = canonical(plan_preimage)
    core_binding, core_selector = render_core_binding(core, digest_bytes(plan_bytes))
    return PreparedActivation(
        core_candidate=core_candidate,
        runtime_candidate=runtime_candidate,
        core_commit=core_commit,
        deploy_commit=deploy_commit,
        release_set=release_set,
        release_set_bytes=release_set_bytes,
        selector_bytes=selector_bytes,
        core_binding_bytes=core_binding,
        core_selector_bytes=core_selector,
        core_gate_bytes=_render_core_gate(),
        telegram_dropin_bytes=render_telegram_dropin(runtime_release),
        plan_bytes=plan_bytes,
        prestate=prestate,
    )


def _write_release_set(path: Path, payload: bytes, *, core_uid: int, telegram_uid: int) -> None:
    atomic_write(path, payload, mode=0o600, gid=0)
    projection = apply_release_set_acl(path, core_uid=core_uid, telegram_uid=telegram_uid)
    require(projection.file_mode == 0o640, "release_set_acl_apply_rejected")


def _cross_identity_manifest_smoke(prepared: PreparedActivation) -> None:
    core_identity = pwd.getpwnam("myuna")
    telegram_identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    core_uid = core_identity.pw_uid
    telegram_uid = telegram_identity.pw_uid
    with tempfile.TemporaryDirectory(prefix="p07-d-release-set-smoke-") as directory:
        root = Path(directory)
        os.chmod(root, 0o755)
        core_release = root / "core"
        runtime_release = root / "runtime"
        for source, target, gid in (
            (prepared.core_candidate, core_release, core_identity.pw_gid),
            (prepared.runtime_candidate, runtime_release, telegram_identity.pw_gid),
        ):
            shutil.copytree(source, target)
            for item in (target, *target.rglob("*")):
                require(not item.is_symlink() and (item.is_dir() or item.is_file()), "cross_identity_release_tree_rejected")
                os.chown(item, 0, gid)
                os.chmod(item, 0o550 if item.is_dir() else 0o440)
        path = root / "release-set.json"
        _write_release_set(path, prepared.release_set_bytes, core_uid=core_uid, telegram_uid=telegram_uid)
        probes = (
            ("myuna", core_release / "src", "myuna_core.external_context.release_binding", "load_release_set_file"),
            (TELEGRAM_RUNTIME_USER, runtime_release / "runtime", "p07_d_release_set", "load_protected_release_set_snapshot"),
        )
        for index, (user, pythonpath, module, function) in enumerate(probes):
            program = (
                f"from {module} import {function};"
                f"v={function}(__import__('pathlib').Path({str(path)!r}),expected_uid=0,expected_gid=0);"
                "assert getattr(v,'release_set',v).generation==10"
            )
            completed = subprocess.run(
                ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/env", "-i", "PATH=/usr/bin", f"PYTHONPATH={pythonpath}", "PYTHONDONTWRITEBYTECODE=1", "/usr/bin/python3", "-B", "-c", program],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            failure_class = (
                "permission"
                if b"PermissionError" in completed.stderr
                else "import"
                if b"ModuleNotFoundError" in completed.stderr or b"ImportError" in completed.stderr
                else "contract"
                if b"AssertionError" in completed.stderr
                else "other"
            )
            require(
                completed.returncode == 0,
                f"cross_identity_core_release_set_smoke_{failure_class}_rejected"
                if index == 0
                else f"cross_identity_telegram_release_set_smoke_{failure_class}_rejected",
            )


def _optional_restore(path: Path, payload: bytes | None, *, mode: int, gid: int) -> None:
    restore_optional(path, payload, mode=mode, gid=gid)


class Generation10LiveBackend:
    def __init__(self, prepared: PreparedActivation, backup_root: Path) -> None:
        self.prepared = prepared
        self.backup_root = backup_root
        self.snapshot_path = backup_root / "TARGET_RELEASE_SET.json"
        self.prestate_payloads = {
            "CORE_BINDING": CORE_BINDING.read_bytes(),
            "CORE_SELECTOR": CORE_SELECTOR.read_bytes(),
            "CORE_GATE": optional_bytes(CORE_GATE),
            "TELEGRAM_DROPIN": TELEGRAM_DROPIN.read_bytes(),
            "SELECTOR": SELECTOR_PATH.read_bytes(),
            "RELEASE_SET": optional_bytes(RELEASE_SET_PATH),
        }
        self.bundle_prestate = dict(prepared.prestate["b_bundle"])
        self.bundle_sealed = False
        self.prestate_observation = self._observe_prestate_exact()
        core_uid = pwd.getpwnam("myuna").pw_uid
        telegram_uid = pwd.getpwnam(TELEGRAM_RUNTIME_USER).pw_uid
        _write_release_set(self.snapshot_path, prepared.release_set_bytes, core_uid=core_uid, telegram_uid=telegram_uid)

    def load_target_snapshot(self) -> ProtectedReleaseSetSnapshot:
        return load_protected_release_set_snapshot(self.snapshot_path, expected_uid=0, expected_gid=0)

    def capture_prestate(self) -> ActivationPrestate:
        require(self._observe_prestate_exact() == self.prestate_observation, "activation_prestate_drifted")
        return ActivationPrestate(
            state_digest=digest("myuna-p07-d-generation10-prestate-observation-v1", self._functional_payload(self.prestate_observation)),
            desired_service_units=(CORE_SERVICE, TELEGRAM_SERVICE, TELEGRAM_SOCKET),
            rollback_release_set_id=None,
        )

    def observe_target_preflight(self, snapshot: ProtectedReleaseSetSnapshot) -> TargetPreflightObservation:
        selected = snapshot.release_set
        require(selected == self.prepared.release_set, "target_release_set_snapshot_rejected")
        credential = _credential_projection()
        return TargetPreflightObservation(
            core_file_count=selected.core["file_count"],
            core_inventory_digest=selected.core["inventory_digest"],
            core_release_digest=selected.core["release_digest"],
            core_tree_digest=selected.core["tree_digest"],
            runtime_file_count=selected.telegram_runtime["file_count"],
            runtime_inventory_digest=selected.telegram_runtime["inventory_digest"],
            runtime_release_digest=selected.telegram_runtime["release_digest"],
            selector_digest=selected.selector["digest"],
            selector_generation=selected.selector["generation"],
            selector_schema=selected.selector["schema"],
            runtime_config_path=selected.runtime_config["path"],
            runtime_config_digest=selected.runtime_config["digest"],
            runtime_binding_digest=selected.runtime_config["binding_digest"],
            credential_name=credential["name"],
            credential_effective_count=credential["effective_count"],
            credential_effective_source=credential["effective_source"],
            credential_dropin_set_digest=credential["dropin_set_digest"],
            credential_projection_digest=credential["projection_digest"],
            credential_source_category=credential["source_category"],
            target_epoch_path=RELEASE_SET_EPOCH_PATH,
            target_epoch_exists=Path(RELEASE_SET_EPOCH_PATH).parent.exists() or Path(RELEASE_SET_EPOCH_PATH).parent.is_symlink(),
            failed_epoch_selected=False,
            service_binding_digests=tuple(sorted((item["unit"], item["binding_digest"]) for item in selected.services)),
        )

    def verify_rollback_ready(self, prestate: ActivationPrestate) -> None:
        require(prestate.state_digest == digest("myuna-p07-d-generation10-prestate-observation-v1", self._functional_payload(self.prestate_observation)), "rollback_prestate_digest_rejected")
        for name, payload in self.prestate_payloads.items():
            if payload is not None:
                atomic_write(self.backup_root / name, payload, mode=0o600)
        atomic_write(self.backup_root / "PRESTATE.json", canonical(self.prepared.prestate), mode=0o600)

    def stop_target_services(self) -> None:
        systemctl("stop", TELEGRAM_SOCKET, TELEGRAM_SERVICE, CORE_SERVICE)

    def verify_target_services_stopped(self) -> None:
        require(not active(CORE_SERVICE) and not active(TELEGRAM_SERVICE) and not active(TELEGRAM_SOCKET), "target_services_not_stopped")

    def apply_target_release_set(self, snapshot: ProtectedReleaseSetSnapshot) -> None:
        require(snapshot.release_set == self.prepared.release_set, "target_release_set_snapshot_rejected")
        current_selector, payload = _load_b_selector()
        require(current_selector == self.prestate_payloads["SELECTOR"] and payload["generation"] == 4, "b_selector_changed_during_activation")
        telegram_identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
        first = inspect_epoch_bundle(B_V4_EPOCH_DATABASE, expected_file_mode=0o600, expected_parent_mode=0o700, expected_uid=telegram_identity.pw_uid, expected_gid=telegram_identity.pw_gid)
        time.sleep(0.25)
        second = inspect_epoch_bundle(B_V4_EPOCH_DATABASE, expected_file_mode=0o600, expected_parent_mode=0o700, expected_uid=telegram_identity.pw_uid, expected_gid=telegram_identity.pw_gid)
        bundle_digest = require_same_bundle(first, second)
        require(bundle_digest == snapshot.release_set.rollback["epoch_bundle_digest"], "b_bundle_changed_during_activation")
        atomic_write(self.backup_root / "STOPPED_BUNDLE_PRESTATE.json", canonical(second), mode=0o600)
        core_gid = grp.getgrnam("myuna").gr_gid
        telegram_gid = telegram_identity.pw_gid
        install_tree(self.prepared.core_candidate, CORE_RELEASE_ROOT / snapshot.release_set.core["release_digest"], gid=core_gid, directory_mode=0o550, file_mode=0o440)
        validate_immutable_release_tree(CORE_RELEASE_ROOT / snapshot.release_set.core["release_digest"], core_evidence(self.prepared.core_candidate)[0])
        install_tree(self.prepared.runtime_candidate, RUNTIME_ROOT / snapshot.release_set.telegram_runtime["release_digest"], gid=telegram_gid, directory_mode=0o550, file_mode=0o440)
        require(tree_inventory(self.prepared.runtime_candidate) == tree_inventory(RUNTIME_ROOT / snapshot.release_set.telegram_runtime["release_digest"]), "installed_runtime_drifted")
        seal_epoch_bundle(B_V4_EPOCH_DATABASE, expected_bundle_digest=bundle_digest, source_uid=telegram_identity.pw_uid, source_gid=telegram_gid, sealed_gid=telegram_gid)
        self.bundle_sealed = True
        target_parent = Path(RELEASE_SET_EPOCH_PATH).parent
        require(not target_parent.exists() and not target_parent.is_symlink(), "generation10_epoch_preexisting")
        target_parent.mkdir(mode=0o700)
        os.chown(target_parent, telegram_identity.pw_uid, telegram_gid)
        os.chmod(target_parent, 0o700)
        atomic_write(SELECTOR_PATH, self.prepared.selector_bytes, mode=0o640, gid=telegram_gid)
        atomic_write(TELEGRAM_DROPIN, self.prepared.telegram_dropin_bytes, mode=0o644)
        atomic_write(CORE_BINDING, self.prepared.core_binding_bytes, mode=0o640, gid=core_gid)
        atomic_write(CORE_SELECTOR, self.prepared.core_selector_bytes, mode=0o644)
        atomic_write(CORE_GATE, self.prepared.core_gate_bytes, mode=0o644)
        _write_release_set(RELEASE_SET_PATH, self.prepared.release_set_bytes, core_uid=pwd.getpwnam("myuna").pw_uid, telegram_uid=telegram_identity.pw_uid)

    def daemon_reload(self) -> None:
        systemctl("daemon-reload")

    def start_target_core(self) -> None:
        systemctl("start", CORE_SERVICE)

    def start_target_telegram(self) -> None:
        systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)

    def observe_target(self) -> FunctionalObservation:
        snapshot = load_protected_release_set_snapshot(RELEASE_SET_PATH, expected_uid=0, expected_gid=0)
        require(snapshot.release_set == self.prepared.release_set, "selected_release_set_drifted")
        core_identity = pwd.getpwnam("myuna")
        telegram_identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
        inspect_release_set_acl(RELEASE_SET_PATH, core_uid=core_identity.pw_uid, telegram_uid=telegram_identity.pw_uid)
        require(CORE_BINDING.read_bytes() == self.prepared.core_binding_bytes and CORE_SELECTOR.read_bytes() == self.prepared.core_selector_bytes and CORE_GATE.read_bytes() == self.prepared.core_gate_bytes, "target_core_binding_rejected")
        require(TELEGRAM_DROPIN.read_bytes() == self.prepared.telegram_dropin_bytes and SELECTOR_PATH.read_bytes() == self.prepared.selector_bytes, "target_telegram_binding_rejected")
        require(show(CORE_SERVICE, "WorkingDirectory") == (CORE_RELEASE_ROOT / self.prepared.release_set.core["release_digest"]).as_posix(), "target_core_release_rejected")
        require(f"/{self.prepared.release_set.telegram_runtime['release_digest']}/runtime/telegram_owner_runtime_gateway.py" in show(TELEGRAM_SERVICE, "ExecStart"), "target_runtime_release_rejected")
        runtime_config = load_target_runtime_config_snapshot()
        require(runtime_config.content_sha256 == self.prepared.release_set.runtime_config["digest"], "target_runtime_config_rejected")
        require(_credential_projection()["projection_digest"] == self.prepared.release_set.credential["projection_digest"], "target_credential_rejected")
        require(
            digest_file(TELEGRAM_CONFIG)
            == self.prepared.prestate["files"]["telegram_resume_config"]["sha256"],
            "target_resume_config_drifted",
        )
        require(
            _load_v6_release() == self.prepared.prestate["definition_release"],
            "target_effective_v6_drifted",
        )
        readiness = wait_for_runtime_readiness(
            path=readiness_path(RELEASE_SET_EPOCH_PATH),
            expected_uid=telegram_identity.pw_uid,
            expected_gid=telegram_identity.pw_gid,
            expected_generation=GENERATION,
            expected_release_set_id=self.prepared.release_set.release_set_id,
            expected_epoch_id=RELEASE_SET_EPOCH_ID,
            expected_database_path=RELEASE_SET_EPOCH_PATH,
            expected_selector_digest=self.prepared.release_set.selector["digest"],
            expected_runtime_config_digest=runtime_config.content_sha256,
            observe_process=_runtime_process_observation,
            timeout_seconds=30,
            stable_seconds=5,
        )
        metadata = ExternalEpochV3Store.inspect_existing_metadata(
            RELEASE_SET_EPOCH_PATH,
            epoch_id=RELEASE_SET_EPOCH_ID,
            release_set_id=self.prepared.release_set.release_set_id,
            binding=ExternalEpochV3Binding(channel_kind=runtime_config.config.channel_kind, client_id="telegram-owner-private", principal_id=runtime_config.config.principal_id, namespace_id=runtime_config.config.namespace_id),
            expected_uid=telegram_identity.pw_uid,
            expected_gid=telegram_identity.pw_gid,
        )
        require(
            readiness.epoch_metadata_digest == content_free_metadata_digest(metadata),
            "target_epoch_readiness_metadata_drifted",
        )
        require(metadata["selected_revision"] == metadata["max_revision"] == metadata["turn_count"] == metadata["summary_count"] == metadata["pending_count"] == metadata["queued_summary_count"] == 0, "target_epoch_not_empty")
        return FunctionalObservation(
            services=tuple(_service_observation(unit) for unit in (CORE_SERVICE, TELEGRAM_SERVICE, TELEGRAM_SOCKET)),
            service_binding_digests=tuple(sorted((item["unit"], item["binding_digest"]) for item in self.prepared.release_set.services)),
            selected_release_set_id=self.prepared.release_set.release_set_id,
            core_release_digest=self.prepared.release_set.core["release_digest"],
            runtime_release_digest=self.prepared.release_set.telegram_runtime["release_digest"],
            selector_digest=digest_file(SELECTOR_PATH),
            runtime_config_digest=runtime_config.content_sha256,
            credential_projection_digest=self.prepared.release_set.credential["projection_digest"],
            epoch_identity_digest=self.prepared.release_set.epoch_identity_digest,
            selected_failed_epoch=False,
        )

    def restore_prestate(self, prestate: ActivationPrestate) -> None:
        del prestate
        core_gid = grp.getgrnam("myuna").gr_gid
        telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
        atomic_write(CORE_BINDING, self.prestate_payloads["CORE_BINDING"], mode=0o640, gid=core_gid)
        atomic_write(CORE_SELECTOR, self.prestate_payloads["CORE_SELECTOR"], mode=0o644)
        _optional_restore(CORE_GATE, self.prestate_payloads["CORE_GATE"], mode=0o644, gid=0)
        atomic_write(TELEGRAM_DROPIN, self.prestate_payloads["TELEGRAM_DROPIN"], mode=0o644)
        atomic_write(SELECTOR_PATH, self.prestate_payloads["SELECTOR"], mode=0o640, gid=telegram_gid)
        if self.prestate_payloads["RELEASE_SET"] is None:
            if RELEASE_SET_PATH.exists() or RELEASE_SET_PATH.is_symlink():
                preserved = self.backup_root / "ROLLED_BACK_TARGET_RELEASE_SET.json"
                require(not preserved.exists(), "rollback_release_set_evidence_exists")
                os.replace(RELEASE_SET_PATH, preserved)
                os.chmod(preserved, 0o600)
                os.chown(preserved, 0, 0)
        else:
            atomic_write(RELEASE_SET_PATH, self.prestate_payloads["RELEASE_SET"], mode=0o640, gid=0)
        if self.bundle_sealed:
            restore_epoch_bundle_permissions(B_V4_EPOCH_DATABASE, prestate=self.bundle_prestate, expected_bundle_digest=self.prepared.release_set.rollback["epoch_bundle_digest"])

    def start_prestate_services(self, prestate: ActivationPrestate) -> None:
        del prestate
        systemctl("start", CORE_SERVICE, TELEGRAM_SOCKET, TELEGRAM_SERVICE)

    def observe_prestate(self) -> FunctionalObservation:
        time.sleep(5)
        return self._observe_prestate_exact()

    def expected_rollback_observation(self, prestate: ActivationPrestate) -> FunctionalObservation:
        del prestate
        return self.prestate_observation

    def _observe_prestate_exact(self) -> FunctionalObservation:
        selector, payload = _load_b_selector()
        require(payload["generation"] == 4 and digest_bytes(selector) == self.prepared.release_set.rollback["selector_digest"], "rollback_selector_rejected")
        require(show(CORE_SERVICE, "WorkingDirectory").endswith(self.prepared.release_set.rollback["core_release_digest"]), "rollback_core_release_rejected")
        require(f"/{self.prepared.release_set.rollback['runtime_release_digest']}/runtime/telegram_owner_runtime_gateway.py" in show(TELEGRAM_SERVICE, "ExecStart"), "rollback_runtime_release_rejected")
        require((not RELEASE_SET_PATH.exists() and not RELEASE_SET_PATH.is_symlink()) if self.prestate_payloads.get("RELEASE_SET") is None else digest_file(RELEASE_SET_PATH) == digest_bytes(self.prestate_payloads["RELEASE_SET"]), "rollback_release_set_rejected")
        return FunctionalObservation(
            services=tuple(_service_observation(unit) for unit in (CORE_SERVICE, TELEGRAM_SERVICE, TELEGRAM_SOCKET)),
            service_binding_digests=_prestate_service_bindings(),
            selected_release_set_id=None,
            core_release_digest=self.prepared.release_set.rollback["core_release_digest"],
            runtime_release_digest=self.prepared.release_set.rollback["runtime_release_digest"],
            selector_digest=digest_bytes(selector),
            runtime_config_digest=load_target_runtime_config_snapshot().content_sha256,
            credential_projection_digest=_credential_projection()["projection_digest"],
            epoch_identity_digest=self.prepared.release_set.rollback["epoch_bundle_digest"],
            selected_failed_epoch=False,
        )

    @staticmethod
    def _functional_payload(observation: FunctionalObservation) -> dict[str, object]:
        return {
            "core_release_digest": observation.core_release_digest,
            "credential_projection_digest": observation.credential_projection_digest,
            "epoch_identity_digest": observation.epoch_identity_digest,
            "runtime_config_digest": observation.runtime_config_digest,
            "runtime_release_digest": observation.runtime_release_digest,
            "selected_release_set_id": observation.selected_release_set_id,
            "selector_digest": observation.selector_digest,
            "service_binding_digests": list(observation.service_binding_digests),
            "services": [{"active_state": item.active_state, "nrestarts": item.nrestarts, "result": item.result, "sub_state": item.sub_state, "unit": item.unit} for item in observation.services],
        }


def _attempt_count() -> int:
    if not ATTEMPT_LEDGER.exists() and not ATTEMPT_LEDGER.is_symlink():
        return 0
    metadata = ATTEMPT_LEDGER.lstat()
    require(not ATTEMPT_LEDGER.is_symlink() and stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o600, "attempt_ledger_rejected")
    payload = json.loads(ATTEMPT_LEDGER.read_text("ascii"))
    require(isinstance(payload, dict) and payload.get("schema") == "myuna.p07-d-generation9-attempt-ledger.v1" and type(payload.get("attempts")) is int and 0 <= payload["attempts"] <= 2, "attempt_ledger_rejected")
    return payload["attempts"]


def _consume_attempt(plan_digest: str) -> int:
    count = _attempt_count()
    require(count < 2, "live_attempt_budget_exhausted")
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    count += 1
    atomic_write(ATTEMPT_LEDGER, canonical({"attempts": count, "last_plan_sha256": plan_digest, "schema": "myuna.p07-d-generation9-attempt-ledger.v1"}), mode=0o600)
    return count


def activate(prepared: PreparedActivation, *, expected_plan_sha256: str | None, preflight_only: bool) -> dict[str, object]:
    _cross_identity_manifest_smoke(prepared)
    attempts = _attempt_count()
    require(attempts < 2, "live_attempt_budget_exhausted")
    if expected_plan_sha256 is not None:
        require(prepared.plan_digest == expected_plan_sha256, "plan_digest_drifted")
    if preflight_only:
        return {"attempts": attempts, "plan_sha256": prepared.plan_digest, "release_set_id": prepared.release_set.release_set_id, "status": "ready"}
    if phase_f_selected_target(Path(__file__).resolve().parent):
        raise Generation10ActivationRejected("phase_f_canonical_owner_required")
    require(expected_plan_sha256 is not None, "expected_plan_required")
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    backup_root = BACKUP_ROOT / prepared.plan_digest
    require(not backup_root.exists(), "activation_attempt_already_exists")
    backup_root.mkdir(mode=0o700)
    atomic_write(backup_root / "PLAN.json", prepared.plan_bytes, mode=0o600)
    attempt = _consume_attempt(prepared.plan_digest)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    journal = STATE_ROOT / f"JOURNAL-{stamp}-{prepared.plan_digest[:12]}.json"
    atomic_write(journal, canonical({"attempt": attempt, "plan_sha256": prepared.plan_digest, "schema": SCHEMA, "status": "activating"}), mode=0o600)
    try:
        result = AtomicReleaseSetTransaction(Generation10LiveBackend(prepared, backup_root)).run()
        receipt = {
            "attempt": attempt,
            "channel_called": False,
            "definition_profile": "effective-v6",
            "model_or_provider_called": False,
            "plan_sha256": prepared.plan_digest,
            "private_content_read": False,
            "release_set_id": result.release_set_id,
            "schema": SCHEMA,
            "status": "ACTIVE_WAITING_OWNER_ORGANIC_TELEGRAM_E2E",
        }
        atomic_write(journal, canonical(receipt), mode=0o600)
        atomic_write(STATE_ROOT / f"RECEIPT-{stamp}-{prepared.plan_digest[:12]}.json", canonical(receipt), mode=0o600)
        return receipt
    except Exception as exc:
        failure = _failure_projection(exc)
        atomic_write(
            journal,
            canonical(
                {
                    "attempt": attempt,
                    **failure,
                    "plan_sha256": prepared.plan_digest,
                    "schema": SCHEMA,
                    "status": "rolled_back_or_hard_stop",
                }
            ),
            mode=0o600,
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-candidate", required=True, type=Path)
    parser.add_argument("--runtime-candidate", required=True, type=Path)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--deploy-commit", required=True)
    parser.add_argument("--expected-core-release", required=True)
    parser.add_argument("--expected-runtime-release", required=True)
    parser.add_argument("--expected-definition-release", required=True)
    parser.add_argument("--expected-b-epoch-sha256", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--expected-turns", required=True, type=int)
    parser.add_argument("--expected-summaries", required=True, type=int)
    parser.add_argument("--expected-pending", required=True, type=int)
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    try:
        prepared = prepare_activation(
            arguments.core_candidate.resolve(),
            arguments.runtime_candidate.resolve(),
            core_commit=arguments.core_commit,
            deploy_commit=arguments.deploy_commit,
            expected_core_release=arguments.expected_core_release,
            expected_runtime_release=arguments.expected_runtime_release,
            expected_definition_release=arguments.expected_definition_release,
            expected_b_epoch_sha256=arguments.expected_b_epoch_sha256,
            expected_revision=arguments.expected_revision,
            expected_turns=arguments.expected_turns,
            expected_summaries=arguments.expected_summaries,
            expected_pending=arguments.expected_pending,
        )
        result = activate(prepared, expected_plan_sha256=arguments.expected_plan_sha256, preflight_only=arguments.preflight_only)
    except (
        ActivationRejected,
        CredentialBindingRejected,
        ExternalEpochBundleRejected,
        ExternalEpochV3Rejected,
        Generation10ActivationRejected,
        OSError,
        ReleaseSetAclRejected,
        ReleaseSetActivationRejected,
        sqlite3.Error,
        subprocess.SubprocessError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {**_failure_projection(exc), "status": "rejected"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
