#!/usr/bin/env python3
"""Generation-13 P07 component for the combined P08/P07 transaction.

The component can prepare and apply the P07 half of the transaction, but the
combined coordinator owns the only live-attempt ledger and final acceptance.
Generation 11 is treated as immutable rollback prestate.
"""

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
import sqlite3
import stat
import subprocess
from typing import Callable, Mapping

import telegram_r5_boot_resume as r5_resume

from core_release_selector import validate_immutable_release_tree
from external_context_epoch_v3 import (
    ExternalEpochV3Binding,
    ExternalEpochV3Rejected,
    ExternalEpochV3Store,
    StartupRecoveryV3,
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
    RELEASE_SET_EPOCH_ID_11,
    RELEASE_SET_EPOCH_PATH_11,
    RELEASE_SET_EPOCH_ID_13,
    RELEASE_SET_EPOCH_PATH_13,
    RELEASE_SET_GENERATION_11,
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
from p07_d_generation13_release_set import (
    CONTROLLER_AUTHORITY_ENV,
    CONTROLLER_CONFIG_ENV,
    CONTROLLER_RELEASE_ENV,
    GENERATION,
    build_release_set,
    canonical,
    digest,
    protected_manifest_path,
    rollback_manifest_digest,
    selector_payload,
    service_binding_digest,
)
from p07_d_generation11_release_set import selector_payload as generation11_selector_payload
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

RELEASE_SET_EPOCH_ID = RELEASE_SET_EPOCH_ID_13
RELEASE_SET_EPOCH_PATH = RELEASE_SET_EPOCH_PATH_13
PREVIOUS_EPOCH_ID = RELEASE_SET_EPOCH_ID_11
PREVIOUS_EPOCH_PATH = RELEASE_SET_EPOCH_PATH_11
PREVIOUS_GENERATION = RELEASE_SET_GENERATION_11


SCHEMA = "myuna.p07-generation13-component-activation.v1"
CORE_SERVICE = "myuna-core@qq.service"
TELEGRAM_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
TELEGRAM_SERVICE = "myuna-telegram-owner-runtime-dev.service"
TELEGRAM_RUNTIME_USER = "myuna-gateway-telegram"
CORE_RELEASE_ROOT = Path("/srv/myuna/releases/core")
RUNTIME_ROOT = Path("/opt/myuna/context24-gateway/telegram/releases")
CORE_BINDING = Path("/etc/myuna/core-release-selector/qq.binding.json")
CORE_SELECTOR = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf"
)
CORE_GATE = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/"
    "zzzzzzzzz-p07-hybrid-external-v1.conf"
)
SELECTOR_PATH = Path("/etc/myuna-telegram-gateway/external-epoch-selector-v2.json")
TELEGRAM_CONFIG = Path("/etc/myuna-telegram-gateway/r5-resume-v1.json")
TELEGRAM_DROPIN = Path(
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
    "zzzzzzzzzzz-p07-hybrid-external-v1.conf"
)
_RUNTIME_BINDING_FIELDS = frozenset({"channel_kind", "principal_id", "namespace_id"})
RELEASE_SET_PATH = protected_manifest_path()
CORE_DROPIN_ROOT = Path("/etc/systemd/system/myuna-core@qq.service.d")
CORE_CREDENTIAL_SOURCE = Path("/etc/myuna/secrets/deepseek-api-key")
EFFECTIVE_CREDENTIAL = Path(f"/run/credentials/{CORE_SERVICE}/{CREDENTIAL_NAME}")
EFFECTIVE_V6_ENV = Path("/etc/myuna/effective-v6.env")
OWNER_RUNTIME_CONFIG = Path("/etc/myuna-telegram-gateway/owner-runtime-v1.json")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TYPED_FAILURE_GATE = re.compile(r"^[a-z][a-z0-9_]{2,127}$")


class Generation13ActivationRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _failure_projection(exc: Exception) -> dict[str, str]:
    final_gate = getattr(exc, "code", None)
    if not isinstance(final_gate, str) or _TYPED_FAILURE_GATE.fullmatch(final_gate) is None:
        final_gate = "generation13_activation_rejected"
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
        raise Generation13ActivationRejected(code)


def digest_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def digest_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise Generation13ActivationRejected("file_identity_rejected")
    return digest_bytes(path.read_bytes())


def _run(arguments: list[str], *, check: bool = True, timeout: int = 240) -> str:
    completed = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise Generation13ActivationRejected("command_rejected")
    return completed.stdout.strip()


def show(unit: str, property_name: str) -> str:
    return _run(["/usr/bin/systemctl", "show", unit, "-p", property_name, "--value"])


def active(unit: str) -> bool:
    return _run(["/usr/bin/systemctl", "is-active", unit], check=False) == "active"


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


def _load_previous_release_set() -> tuple[bytes, P07DReleaseSet]:
    snapshot = load_protected_release_set_snapshot(
        RELEASE_SET_PATH,
        expected_uid=0,
        expected_gid=0,
    )
    require(
        snapshot.release_set.generation == PREVIOUS_GENERATION
        and snapshot.release_set.epoch["epoch_id"] == PREVIOUS_EPOCH_ID
        and snapshot.release_set.epoch["database_path"] == PREVIOUS_EPOCH_PATH,
        "previous_release_set_rejected",
    )
    return RELEASE_SET_PATH.read_bytes(), snapshot.release_set


def _load_previous_selector(
    *,
    expected_uid: int = 0,
    expected_gid: int | None = None,
) -> tuple[bytes, dict[str, object]]:
    metadata = SELECTOR_PATH.lstat()
    telegram_gid = (
        grp.getgrnam("myuna-gateway-telegram").gr_gid
        if expected_gid is None
        else expected_gid
    )
    require(
        not SELECTOR_PATH.is_symlink()
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == expected_uid
        and metadata.st_gid == telegram_gid
        and stat.S_IMODE(metadata.st_mode) == 0o640,
        "previous_selector_metadata_rejected",
    )
    raw = SELECTOR_PATH.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Generation13ActivationRejected("previous_selector_document_rejected") from exc
    require(
        isinstance(payload, dict)
        and set(payload)
        == {
            "channel_kind",
            "client_id",
            "database_path",
            "epoch_id",
            "generation",
            "previous_epoch_bundle_digest",
            "previous_epoch_bundle_schema",
            "previous_epoch_id",
            "schema",
            "status",
        }
        and payload.get("schema") == "myuna.external-epoch-selector.v2"
        and payload.get("generation") == PREVIOUS_GENERATION
        and payload.get("epoch_id") == PREVIOUS_EPOCH_ID
        and payload.get("database_path") == PREVIOUS_EPOCH_PATH
        and payload.get("channel_kind") == "astrbot_telegram"
        and payload.get("client_id") == "telegram-owner-private"
        and payload.get("status") == "active"
        and raw == canonical(payload),
        "previous_selector_rejected",
    )
    return raw, payload


def _expected_previous_metadata(
    *,
    previous_release_set: P07DReleaseSet,
    runtime_config: object,
    revision: int,
    turns: int,
    summaries: int,
    pending: int,
) -> dict[str, object]:
    config = runtime_config
    observed = ExternalEpochV3Store.inspect_existing_metadata(
        PREVIOUS_EPOCH_PATH,
        epoch_id=PREVIOUS_EPOCH_ID,
        release_set_id=previous_release_set.release_set_id,
        binding=ExternalEpochV3Binding(
            channel_kind=config.channel_kind,
            client_id="telegram-owner-private",
            principal_id=config.principal_id,
            namespace_id=config.namespace_id,
        ),
        expected_uid=int(previous_release_set.epoch["uid"]),
        expected_gid=int(previous_release_set.epoch["gid"]),
    )
    require(
        observed.get("schema") == "myuna.external-authorized-epoch.v3"
        and observed.get("selected_revision") == revision
        and observed.get("max_revision") == revision
        and observed.get("turn_count") == turns
        and observed.get("summary_count") == summaries
        and observed.get("pending_count") == pending == 0
        and observed.get("queued_summary_count") == 0,
        "previous_epoch_metadata_rejected",
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
    target_telegram_config_digest: str | None = None

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
    expected_previous_epoch_sha256: str,
    expected_previous_release_set_id: str,
    expected_revision: int,
    expected_turns: int,
    expected_summaries: int,
    expected_pending: int,
) -> PreparedActivation:
    # Stage 1 freezes ownership before Stage 2 installs the paired artifact and
    # T2 receipt reconstruction.  It is intentionally impossible for a source
    # caller to reach legacy preparation or any mutable prestate in this commit.
    raise Generation13ActivationRejected("phase_f_stage2_artifact_authority_required")


def _retired_prepare_activation(
    core_candidate: Path,
    runtime_candidate: Path,
    *,
    core_commit: str,
    deploy_commit: str,
    expected_core_release: str,
    expected_runtime_release: str,
    expected_definition_release: str,
    expected_previous_epoch_sha256: str,
    expected_previous_release_set_id: str,
    expected_revision: int,
    expected_turns: int,
    expected_summaries: int,
    expected_pending: int,
) -> PreparedActivation:
    raise Generation13ActivationRejected("phase_f_legacy_prepare_retired")


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
            expected_generation = prepared.release_set.generation
            expected_release_set_id = prepared.release_set.release_set_id
            program = (
                f"from {module} import {function};"
                f"v={function}(__import__('pathlib').Path({str(path)!r}),expected_uid=0,expected_gid=0);"
                "r=getattr(v,'release_set',v);"
                f"assert r.generation=={expected_generation};"
                f"assert r.release_set_id=={expected_release_set_id!r}"
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


@dataclass(frozen=True, slots=True)
class _PhaseFFileState:
    path: Path
    present: bool
    payload: bytes | None
    uid: int | None
    gid: int | None
    mode: int | None
    content_sha256: str | None


@dataclass(frozen=True, slots=True)
class _PhaseFUnitState:
    unit: str
    active_state: str
    sub_state: str
    result: str
    job: str


def _phase_f_file_state(path: Path) -> _PhaseFFileState:
    if not path.exists() and not path.is_symlink():
        return _PhaseFFileState(path, False, None, None, None, None, None)
    metadata = path.lstat()
    require(not path.is_symlink() and stat.S_ISREG(metadata.st_mode), "phase_f_file_type_rejected")
    payload = path.read_bytes()
    return _PhaseFFileState(
        path=path,
        present=True,
        payload=payload,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        mode=stat.S_IMODE(metadata.st_mode),
        content_sha256=digest_bytes(payload),
    )


def _phase_f_unit_state(unit: str) -> _PhaseFUnitState:
    return _PhaseFUnitState(
        unit=unit,
        active_state=show(unit, "ActiveState"),
        sub_state=show(unit, "SubState"),
        result=show(unit, "Result"),
        job=show(unit, "Job"),
    )


def _phase_f_atomic_publish(path: Path, payload: bytes, old: _PhaseFFileState, plan_digest: str) -> None:
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    temporary = f".{path.name}.phase-f-{plan_digest[:16]}"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fchmod(descriptor, 0o640 if old.mode is None else old.mode)
            if old.uid is not None and old.gid is not None:
                os.fchown(descriptor, old.uid, old.gid)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    except FileExistsError as exc:
        raise Generation13ActivationRejected("phase_f_file_partial_ambiguous") from exc
    finally:
        os.close(parent)
    require(_phase_f_file_state(path).content_sha256 == digest_bytes(payload), "phase_f_file_publish_rejected")


def _phase_f_restore_file(old: _PhaseFFileState, plan_digest: str) -> None:
    if old.present:
        assert old.payload is not None
        _phase_f_atomic_publish(old.path, old.payload, old, plan_digest)
        return
    if not old.path.exists() and not old.path.is_symlink():
        return
    current = _phase_f_file_state(old.path)
    require(current.present, "phase_f_file_restore_identity_rejected")
    parent = os.open(old.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.unlink(old.path.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    require(not old.path.exists() and not old.path.is_symlink(), "phase_f_file_remove_rejected")


class Generation13LiveBackend:
    """The sole concrete Phase-F resource observer, mutator and compensator."""

    def __init__(
        self,
        prepared: PreparedActivation,
        *,
        expected_network: r5_resume.PhaseFNetworkProjection,
        frozen_old_container: r5_resume.PhaseFContainerProjection,
        writer: Callable[[], None],
        runner: Callable[..., str] | None = None,
    ) -> None:
        require(frozen_old_container.name == r5_resume.CONTAINER, "phase_f_old_container_name_rejected")
        self.prepared = prepared
        self._runner = r5_resume.run if runner is None else runner
        self._writer = writer
        self.expected_network = expected_network
        self.old_container = frozen_old_container
        config = r5_resume.read_config()
        service = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
        target_config_digest = digest(
            "myuna-phase-f-target-container-config-v1",
            {
                "compose_sha256": digest_file(config.compose_file),
                "gateway_release": config.gateway_release,
                "image": r5_resume.EXPECTED_IMAGE,
                "plan_sha256": prepared.plan_digest,
            },
        )
        archive_name = f"{r5_resume.ARCHIVE_PREFIX}{prepared.plan_digest[:16]}"
        self.target_container = r5_resume.PhaseFTargetContainer(
            plan_digest=prepared.plan_digest,
            target_config_digest=target_config_digest,
            image=r5_resume.EXPECTED_IMAGE,
            user=f"{service.pw_uid}:{service.pw_gid}",
            channel_root=config.channel_root,
            plugin_root=config.plugin_root,
            signing_secret=r5_resume.EPHEMERAL_SIGNING,
            runtime_root=r5_resume.RUNTIME_ROOT,
            media_auth_runtime_root=r5_resume.MEDIA_AUTH_RUNTIME_ROOT,
            archive_name=archive_name,
        )
        canonical = r5_resume.phase_f_container_projection(r5_resume.CONTAINER, runner=self._runner)
        archived = r5_resume.phase_f_container_projection(archive_name, runner=self._runner)
        canonical_is_old = r5_resume._phase_f_same_object(
            frozen_old_container, canonical, name=r5_resume.CONTAINER,
            allow_status_change=True, allow_network_runtime_change=True,
        )
        archived_is_old = r5_resume._phase_f_same_object(
            frozen_old_container, archived, name=archive_name,
            allow_status_change=True, allow_network_runtime_change=True,
        )
        require(canonical_is_old != archived_is_old, "phase_f_old_container_location_ambiguous")
        if canonical_is_old:
            require(archived is None, "phase_f_archive_collision_ambiguous")
        else:
            require(
                canonical is None or (
                    canonical.plan_digest == prepared.plan_digest
                    and canonical.target_config_digest == target_config_digest
                ),
                "phase_f_target_container_substitution",
            )
        self._target_observation = None if canonical_is_old else canonical
        first_network = r5_resume.phase_f_network_projection(runner=self._runner)
        second_network = r5_resume.phase_f_network_projection(runner=self._runner)
        require(
            first_network is not None
            and first_network == second_network
            and r5_resume._phase_f_same_network_object(expected_network, first_network),
            "phase_f_external_network_not_ready",
        )
        allowed_members = set(expected_network.member_container_ids)
        if self._target_observation is not None:
            allowed_members.add(self._target_observation.container_id)
        require(set(first_network.member_container_ids) == allowed_members, "phase_f_external_network_membership_drift")
        self._release_set_old = _phase_f_file_state(RELEASE_SET_PATH)
        self._selector_old = _phase_f_file_state(SELECTOR_PATH)
        self._core_binding_old = _phase_f_file_state(CORE_BINDING)
        self._core_selector_old = _phase_f_file_state(CORE_SELECTOR)
        self._core_gate_old = _phase_f_file_state(CORE_GATE)
        self._runtime_dropin_old = _phase_f_file_state(TELEGRAM_DROPIN)
        self._core_unit_old = _phase_f_unit_state(CORE_SERVICE)
        self._runtime_socket_old = _phase_f_unit_state(TELEGRAM_SOCKET)
        self._runtime_service_old = _phase_f_unit_state(TELEGRAM_SERVICE)
        self._startup_recovery_result: StartupRecoveryV3 | None = None

    def _file_contract(self, operation: str) -> tuple[_PhaseFFileState, bytes]:
        match operation:
            case "O06_PUBLISH_RELEASE_SET":
                return self._release_set_old, self.prepared.release_set_bytes
            case "O07_PUBLISH_EPOCH_SELECTOR":
                return self._selector_old, self.prepared.selector_bytes
            case "O08_PUBLISH_CORE_BINDING":
                return self._core_binding_old, self.prepared.core_binding_bytes
            case "O09_PUBLISH_CORE_SELECTOR":
                return self._core_selector_old, self.prepared.core_selector_bytes
            case "O10_PUBLISH_CORE_GATE":
                return self._core_gate_old, self.prepared.core_gate_bytes
            case "O11_PUBLISH_RUNTIME_DROPIN":
                return self._runtime_dropin_old, self.prepared.telegram_dropin_bytes
            case _:
                raise Generation13ActivationRejected("phase_f_file_operation_rejected")

    def _unit_contract(self, operation: str) -> tuple[_PhaseFUnitState, bool]:
        match operation:
            case "O01_STOP_RUNTIME_SERVICE":
                return self._runtime_service_old, False
            case "O02_STOP_RUNTIME_SOCKET":
                return self._runtime_socket_old, False
            case "O03_STOP_CORE_SERVICE":
                return self._core_unit_old, False
            case "O13_START_CORE_SERVICE":
                return self._core_unit_old, True
            case "O14_START_RUNTIME_SOCKET":
                return self._runtime_socket_old, True
            case "O15_START_RUNTIME_SERVICE":
                return self._runtime_service_old, True
            case _:
                raise Generation13ActivationRejected("phase_f_unit_operation_rejected")

    @staticmethod
    def _unit_is_desired(current: _PhaseFUnitState, active_desired: bool) -> bool:
        if active_desired:
            return current.active_state == "active" and current.job in {"", "0"}
        return current.active_state == "inactive" and current.job in {"", "0"}

    def _observe_file(self, operation: str) -> str:
        old, desired = self._file_contract(operation)
        temporary = old.path.parent / f".{old.path.name}.phase-f-{self.prepared.plan_digest[:16]}"
        if temporary.exists() or temporary.is_symlink():
            return "AMBIGUOUS"
        current = _phase_f_file_state(old.path)
        if current.present and current.content_sha256 == digest_bytes(desired):
            return "DESIRED"
        if current == old:
            return "OLD"
        return "AMBIGUOUS"

    def _old_location(self) -> tuple[r5_resume.PhaseFContainerProjection | None, r5_resume.PhaseFContainerProjection | None]:
        return (
            r5_resume.phase_f_container_projection(r5_resume.CONTAINER, runner=self._runner),
            r5_resume.phase_f_container_projection(self.target_container.archive_name, runner=self._runner),
        )

    def _target_matches(self, value: r5_resume.PhaseFContainerProjection | None) -> bool:
        return bool(
            value is not None
            and value.name == r5_resume.CONTAINER
            and value.image == self.target_container.image
            and value.plan_digest == self.target_container.plan_digest
            and value.target_config_digest == self.target_container.target_config_digest
            and value.user == self.target_container.user
            and value.network_names == (r5_resume.NETWORK,)
        )

    def observe_operation(self, operation: str) -> str:
        if operation.startswith(("O06_", "O07_", "O08_", "O09_", "O10_", "O11_")):
            return self._observe_file(operation)
        if operation in {"O01_STOP_RUNTIME_SERVICE", "O02_STOP_RUNTIME_SOCKET", "O03_STOP_CORE_SERVICE", "O13_START_CORE_SERVICE", "O14_START_RUNTIME_SOCKET", "O15_START_RUNTIME_SERVICE"}:
            old, active_desired = self._unit_contract(operation)
            current = _phase_f_unit_state(old.unit)
            if self._unit_is_desired(current, active_desired):
                return "DESIRED"
            return "OLD" if current == old else "AMBIGUOUS"
        if operation == "O12_DAEMON_RELOAD":
            state = _run(["/usr/bin/systemctl", "show", "--property=NeedDaemonReload", "--value"])
            return "DESIRED" if state == "no" else ("OLD" if state == "yes" else "AMBIGUOUS")
        canonical, archived = self._old_location()
        old_canonical = r5_resume._phase_f_same_object(
            self.old_container, canonical, name=r5_resume.CONTAINER,
            allow_status_change=True, allow_network_runtime_change=True,
        )
        old_archived = r5_resume._phase_f_same_object(
            self.old_container, archived, name=self.target_container.archive_name,
            allow_status_change=True, allow_network_runtime_change=True,
        )
        if operation == "O04_STOP_OLD_CONTAINER":
            if not old_canonical or archived is not None or canonical is None:
                return "AMBIGUOUS"
            if canonical.status in {"created", "exited"}:
                return "DESIRED"
            return "OLD" if canonical.status == "running" else "AMBIGUOUS"
        if operation == "O05_ARCHIVE_OLD_CONTAINER":
            if old_archived and canonical is None:
                return "DESIRED"
            if old_canonical and archived is None and canonical is not None and canonical.status in {"created", "exited"}:
                return "OLD"
            return "AMBIGUOUS"
        if operation in {"O16_CREATE_TARGET_STOPPED", "O17_SET_TARGET_RESTART_POLICY", "O18_START_TARGET_CONTAINER"}:
            if canonical is None and old_archived:
                return "OLD" if operation == "O16_CREATE_TARGET_STOPPED" else "AMBIGUOUS"
            if not self._target_matches(canonical) or not old_archived or canonical is None:
                return "AMBIGUOUS"
            self._target_observation = canonical
            if operation == "O16_CREATE_TARGET_STOPPED":
                return "DESIRED" if canonical.status in {"created", "exited", "running"} else "AMBIGUOUS"
            if operation == "O17_SET_TARGET_RESTART_POLICY":
                policy = (canonical.restart_policy, canonical.restart_maximum_retry_count)
                if policy == (r5_resume.EXPECTED_RESTART_POLICY, r5_resume.EXPECTED_RESTART_MAXIMUM_RETRY_COUNT):
                    return "DESIRED"
                return "OLD" if policy == ("no", 0) else "AMBIGUOUS"
            if canonical.status == "running" and canonical.health == "healthy":
                return "DESIRED"
            return "OLD" if canonical.status in {"created", "exited"} else "AMBIGUOUS"
        raise Generation13ActivationRejected("phase_f_operation_rejected")

    def _apply_unit(self, operation: str) -> None:
        old, active_desired = self._unit_contract(operation)
        _run(["/usr/bin/systemctl", "start" if active_desired else "stop", old.unit])
        require(self.observe_operation(operation) == "DESIRED", "phase_f_unit_poststate_rejected")

    def apply_operation(self, operation: str) -> None:
        if operation.startswith(("O06_", "O07_", "O08_", "O09_", "O10_", "O11_")):
            old, desired = self._file_contract(operation)
            _phase_f_atomic_publish(old.path, desired, old, self.prepared.plan_digest)
            require(self.observe_operation(operation) == "DESIRED", "phase_f_file_poststate_rejected")
            return
        if operation in {"O01_STOP_RUNTIME_SERVICE", "O02_STOP_RUNTIME_SOCKET", "O03_STOP_CORE_SERVICE", "O13_START_CORE_SERVICE", "O14_START_RUNTIME_SOCKET", "O15_START_RUNTIME_SERVICE"}:
            self._apply_unit(operation)
            return
        if operation == "O12_DAEMON_RELOAD":
            _run(["/usr/bin/systemctl", "daemon-reload"])
            require(self.observe_operation(operation) == "DESIRED", "phase_f_daemon_reload_rejected")
            return
        if operation == "O04_STOP_OLD_CONTAINER":
            r5_resume.phase_f_stop_container_exact(self.old_container, name=r5_resume.CONTAINER, runner=self._runner)
            return
        if operation == "O05_ARCHIVE_OLD_CONTAINER":
            r5_resume.phase_f_rename_container_exact(
                self.old_container, source_name=r5_resume.CONTAINER,
                target_name=self.target_container.archive_name, runner=self._runner,
            )
            return
        if operation == "O16_CREATE_TARGET_STOPPED":
            archived = r5_resume.phase_f_container_projection(self.target_container.archive_name, runner=self._runner)
            require(archived is not None, "phase_f_archive_missing")
            self._target_observation = r5_resume.phase_f_create_target_stopped(
                self.target_container, expected_network=self.expected_network,
                archived_old=archived, runner=self._runner,
            )
            return
        if operation == "O17_SET_TARGET_RESTART_POLICY":
            require(self._target_observation is not None, "phase_f_target_observation_missing")
            self._target_observation = r5_resume.phase_f_set_restart_policy_exact(
                self._target_observation, runner=self._runner,
            )
            return
        if operation == "O18_START_TARGET_CONTAINER":
            require(self._target_observation is not None, "phase_f_target_observation_missing")
            self._target_observation = r5_resume.phase_f_start_container_exact(
                self._target_observation, runner=self._runner,
            )
            return
        raise Generation13ActivationRejected("phase_f_operation_rejected")

    def invoke_writer(self) -> None:
        self._writer()

    def _restore_unit_prestate(self, old: _PhaseFUnitState) -> None:
        should_be_active = old.active_state == "active"
        _run(["/usr/bin/systemctl", "start" if should_be_active else "stop", old.unit])
        require(_phase_f_unit_state(old.unit) == old, "phase_f_unit_rollback_rejected")

    def observe_compensation(self, operation: str) -> str:
        if operation.startswith(("O06_", "O07_", "O08_", "O09_", "O10_", "O11_")):
            current = _phase_f_file_state(self._file_contract(operation)[0].path)
            return "OLD" if current == self._file_contract(operation)[0] else ("DESIRED" if self._observe_file(operation) == "DESIRED" else "AMBIGUOUS")
        if operation == "O12_DAEMON_RELOAD":
            state = _run(["/usr/bin/systemctl", "show", "--property=NeedDaemonReload", "--value"])
            return "OLD" if state == "no" else ("DESIRED" if state == "yes" else "AMBIGUOUS")
        if operation in {"O01_STOP_RUNTIME_SERVICE", "O02_STOP_RUNTIME_SOCKET", "O03_STOP_CORE_SERVICE"}:
            old, _desired = self._unit_contract(operation)
            current = _phase_f_unit_state(old.unit)
            return "OLD" if current == old else ("DESIRED" if self._unit_is_desired(current, False) else "AMBIGUOUS")
        if operation in {"O13_START_CORE_SERVICE", "O14_START_RUNTIME_SOCKET", "O15_START_RUNTIME_SERVICE"}:
            old, _desired = self._unit_contract(operation)
            current = _phase_f_unit_state(old.unit)
            return "OLD" if current.active_state == "inactive" else ("DESIRED" if current.active_state == "active" else "AMBIGUOUS")
        canonical, archived = self._old_location()
        if operation == "O18_START_TARGET_CONTAINER":
            if canonical is None or not self._target_matches(canonical):
                return "AMBIGUOUS"
            return "OLD" if canonical.status in {"created", "exited"} else ("DESIRED" if canonical.status == "running" else "AMBIGUOUS")
        if operation == "O17_SET_TARGET_RESTART_POLICY":
            if canonical is None or not self._target_matches(canonical):
                return "AMBIGUOUS"
            return "OLD" if (canonical.restart_policy, canonical.restart_maximum_retry_count) == ("no", 0) else "DESIRED"
        if operation == "O16_CREATE_TARGET_STOPPED":
            if canonical is None and archived is not None:
                return "OLD"
            return "DESIRED" if self._target_matches(canonical) else "AMBIGUOUS"
        if operation == "O05_ARCHIVE_OLD_CONTAINER":
            old_canonical = r5_resume._phase_f_same_object(self.old_container, canonical, name=r5_resume.CONTAINER, allow_status_change=True, allow_network_runtime_change=True)
            old_archived = r5_resume._phase_f_same_object(self.old_container, archived, name=self.target_container.archive_name, allow_status_change=True, allow_network_runtime_change=True)
            return "OLD" if old_canonical and archived is None else ("DESIRED" if old_archived and canonical is None else "AMBIGUOUS")
        if operation == "O04_STOP_OLD_CONTAINER":
            if not r5_resume._phase_f_same_object(self.old_container, canonical, name=r5_resume.CONTAINER, allow_status_change=True, allow_network_runtime_change=True) or canonical is None:
                return "AMBIGUOUS"
            if canonical.status == self.old_container.status:
                return "OLD"
            return "DESIRED" if canonical.status in {"created", "exited"} else "AMBIGUOUS"
        raise Generation13ActivationRejected("phase_f_compensation_operation_rejected")

    def compensate_operation(self, operation: str) -> None:
        if operation.startswith(("O06_", "O07_", "O08_", "O09_", "O10_", "O11_")):
            _phase_f_restore_file(self._file_contract(operation)[0], self.prepared.plan_digest)
            return
        if operation == "O12_DAEMON_RELOAD":
            _run(["/usr/bin/systemctl", "daemon-reload"])
            return
        if operation in {"O13_START_CORE_SERVICE", "O14_START_RUNTIME_SOCKET", "O15_START_RUNTIME_SERVICE"}:
            old, _desired = self._unit_contract(operation)
            _run(["/usr/bin/systemctl", "stop", old.unit])
            return
        if operation in {"O01_STOP_RUNTIME_SERVICE", "O02_STOP_RUNTIME_SOCKET", "O03_STOP_CORE_SERVICE"}:
            self._restore_unit_prestate(self._unit_contract(operation)[0])
            return
        if operation == "O18_START_TARGET_CONTAINER":
            require(self._target_observation is not None, "phase_f_target_observation_missing")
            self._target_observation = r5_resume.phase_f_stop_container_exact(
                self._target_observation, name=r5_resume.CONTAINER, runner=self._runner,
            )
            return
        if operation == "O17_SET_TARGET_RESTART_POLICY":
            current = r5_resume.phase_f_container_projection(r5_resume.CONTAINER, runner=self._runner)
            require(current is not None and self._target_matches(current), "phase_f_target_policy_restore_identity_rejected")
            self._runner(["/usr/bin/docker", "container", "update", "--restart", "no", current.container_id])
            return
        if operation == "O16_CREATE_TARGET_STOPPED":
            current = r5_resume.phase_f_container_projection(r5_resume.CONTAINER, runner=self._runner)
            require(current is not None and self._target_matches(current), "phase_f_target_remove_identity_rejected")
            r5_resume.phase_f_remove_container_exact(current, expected_network=self.expected_network, runner=self._runner)
            self._target_observation = None
            return
        if operation == "O05_ARCHIVE_OLD_CONTAINER":
            r5_resume.phase_f_rename_container_exact(
                self.old_container, source_name=self.target_container.archive_name,
                target_name=r5_resume.CONTAINER, runner=self._runner,
            )
            return
        if operation == "O04_STOP_OLD_CONTAINER":
            r5_resume.phase_f_restore_old_running_exact(self.old_container, runner=self._runner)
            return
        raise Generation13ActivationRejected("phase_f_compensation_operation_rejected")

    def _old_release_set(self) -> P07DReleaseSet:
        payload = self._release_set_old.payload
        require(payload is not None, "phase_f_old_release_set_absent")
        try:
            parsed = json.loads(payload.decode("ascii"))
            value = P07DReleaseSet.from_payload(parsed)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise Generation13ActivationRejected("phase_f_old_release_set_rejected") from exc
        require(value.generation == PREVIOUS_GENERATION, "phase_f_old_release_set_generation_rejected")
        return value

    @staticmethod
    def _startup_result_is_typed(value: object) -> bool:
        if type(value) is not StartupRecoveryV3:
            return False
        assert isinstance(value, StartupRecoveryV3)
        return all(
            type(item) is int and item >= 0
            for item in (
                value.abandoned_deliveries,
                value.discarded_unprepared_turns,
                value.requeued_summary_jobs,
                value.blocked_summary_jobs,
            )
        )

    def _ordinary_startup_recover(self) -> StartupRecoveryV3:
        """Invoke the same concrete store recovery seam used by the gateway."""

        old = self._old_release_set()
        runtime = old.runtime_config
        epoch = old.epoch
        store = ExternalEpochV3Store(
            str(epoch["database_path"]),
            epoch_id=str(epoch["epoch_id"]),
            release_set_id=old.release_set_id,
            binding=ExternalEpochV3Binding(
                channel_kind=str(runtime["channel_kind"]),
                client_id="telegram-owner-private",
                principal_id=str(runtime["principal_id"]),
                namespace_id=str(runtime["namespace_id"]),
            ),
            projection_policy_version=old.projection_policy_version,
            expected_uid=int(epoch["uid"]),
            expected_gid=int(epoch["gid"]),
        )
        result = store.startup_recover()
        require(self._startup_result_is_typed(result), "phase_f_startup_recovery_result_rejected")
        return result

    def _observe_old_readiness(self) -> str:
        old = self._old_release_set()
        runtime_identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
        try:
            receipt = wait_for_runtime_readiness(
                path=readiness_path(str(old.epoch["database_path"])),
                expected_uid=runtime_identity.pw_uid,
                expected_gid=runtime_identity.pw_gid,
                expected_generation=old.generation,
                expected_release_set_id=old.release_set_id,
                expected_epoch_id=str(old.epoch["epoch_id"]),
                expected_database_path=str(old.epoch["database_path"]),
                expected_selector_digest=str(old.selector["digest"]),
                expected_runtime_config_digest=str(old.runtime_config["digest"]),
                observe_process=_runtime_process_observation,
                timeout_seconds=30,
                stable_seconds=5,
            )
        except (ExternalEpochV3Rejected, OSError, ValueError):
            return "AMBIGUOUS"
        return "DESIRED" if receipt.release_set_id == old.release_set_id else "AMBIGUOUS"

    def _observe_old_ingress(self) -> str:
        service = _phase_f_unit_state(TELEGRAM_SERVICE)
        socket = _phase_f_unit_state(TELEGRAM_SOCKET)
        canonical, archived = self._old_location()
        network = r5_resume.phase_f_network_projection(runner=self._runner)
        if (
            service != self._runtime_service_old
            or socket != self._runtime_socket_old
            or archived is not None
            or not r5_resume._phase_f_same_object(
                self.old_container,
                canonical,
                name=r5_resume.CONTAINER,
                allow_network_runtime_change=True,
            )
            or canonical is None
            or canonical.status != self.old_container.status
            or canonical.health != self.old_container.health
            or network != self.expected_network
        ):
            return "AMBIGUOUS"
        return "DESIRED"

    def observe_full_old(self) -> str:
        files = (
            self._release_set_old, self._selector_old, self._core_binding_old,
            self._core_selector_old, self._core_gate_old, self._runtime_dropin_old,
        )
        if any(_phase_f_file_state(item.path) != item for item in files):
            return "AMBIGUOUS"
        if (
            _phase_f_unit_state(CORE_SERVICE) != self._core_unit_old
            or _phase_f_unit_state(TELEGRAM_SOCKET) != self._runtime_socket_old
            or _phase_f_unit_state(TELEGRAM_SERVICE) != self._runtime_service_old
        ):
            return "AMBIGUOUS"
        canonical, archived = self._old_location()
        if archived is not None or not r5_resume._phase_f_same_object(
            self.old_container, canonical, name=r5_resume.CONTAINER,
            allow_network_runtime_change=True,
        ):
            return "AMBIGUOUS"
        network = r5_resume.phase_f_network_projection(runner=self._runner)
        if network != self.expected_network:
            return "AMBIGUOUS"
        return "OLD"

    @staticmethod
    def _forward_file_activation(operation: str) -> str | None:
        match operation:
            case "F04_RESTORE_RELEASE_SET":
                return "O06_PUBLISH_RELEASE_SET"
            case "F05_RESTORE_EPOCH_SELECTOR":
                return "O07_PUBLISH_EPOCH_SELECTOR"
            case "F06_RESTORE_CORE_BINDING":
                return "O08_PUBLISH_CORE_BINDING"
            case "F07_RESTORE_CORE_SELECTOR":
                return "O09_PUBLISH_CORE_SELECTOR"
            case "F08_RESTORE_CORE_GATE":
                return "O10_PUBLISH_CORE_GATE"
            case "F09_RESTORE_RUNTIME_DROPIN":
                return "O11_PUBLISH_RUNTIME_DROPIN"
            case _:
                return None

    def _forward_unit_prestate(self, operation: str) -> _PhaseFUnitState | None:
        match operation:
            case "F11_RESTORE_OLD_CORE_SERVICE":
                return self._core_unit_old
            case "F12_RESTORE_OLD_RUNTIME_SOCKET":
                return self._runtime_socket_old
            case "F13_RESTORE_OLD_RUNTIME_SERVICE":
                return self._runtime_service_old
            case _:
                return None

    def observe_forward_old(self, operation: str) -> str:
        file_operation = self._forward_file_activation(operation)
        if file_operation is not None:
            old, _desired = self._file_contract(file_operation)
            return "DESIRED" if _phase_f_file_state(old.path) == old else "OLD"
        canonical, archived = self._old_location()
        if operation == "F01_STOP_TARGET_CONTAINER":
            if canonical is None or not self._target_matches(canonical):
                return "DESIRED"
            return "DESIRED" if canonical.status in {"created", "exited"} else ("OLD" if canonical.status == "running" else "AMBIGUOUS")
        if operation == "F02_REMOVE_TARGET_CONTAINER":
            return "DESIRED" if canonical is None else ("OLD" if self._target_matches(canonical) else "AMBIGUOUS")
        if operation == "F03_RESTORE_OLD_CONTAINER_NAME":
            old_canonical = r5_resume._phase_f_same_object(self.old_container, canonical, name=r5_resume.CONTAINER, allow_status_change=True, allow_network_runtime_change=True)
            old_archived = r5_resume._phase_f_same_object(self.old_container, archived, name=self.target_container.archive_name, allow_status_change=True, allow_network_runtime_change=True)
            return "DESIRED" if old_canonical and archived is None else ("OLD" if old_archived and canonical is None else "AMBIGUOUS")
        if operation == "F10_DAEMON_RELOAD_OLD":
            state = _run(["/usr/bin/systemctl", "show", "--property=NeedDaemonReload", "--value"])
            return "DESIRED" if state == "no" else ("OLD" if state == "yes" else "AMBIGUOUS")
        unit_prestate = self._forward_unit_prestate(operation)
        if unit_prestate is not None:
            return "DESIRED" if _phase_f_unit_state(unit_prestate.unit) == unit_prestate else "OLD"
        if operation == "F14_VERIFY_OLD_RESTART_POLICY":
            return "DESIRED" if canonical is not None and canonical.restart_policy == self.old_container.restart_policy and canonical.restart_maximum_retry_count == self.old_container.restart_maximum_retry_count else "AMBIGUOUS"
        if operation == "F15_RESTORE_OLD_RUNNING_STATE":
            return "DESIRED" if canonical is not None and canonical.status == self.old_container.status else "OLD"
        if operation == "F16_ORDINARY_STARTUP_RECOVER":
            if self.observe_full_old() != "OLD":
                return "AMBIGUOUS"
            if self._startup_recovery_result is None:
                return "OLD"
            return "DESIRED" if self._startup_result_is_typed(self._startup_recovery_result) else "AMBIGUOUS"
        if operation in {"F17_READINESS_OBSERVATION_ONE", "F18_READINESS_OBSERVATION_TWO"}:
            return self._observe_old_readiness()
        if operation in {"F19_INGRESS_OBSERVATION_ONE", "F20_INGRESS_OBSERVATION_TWO"}:
            return self._observe_old_ingress()
        if operation in {"F21_FULL_OLD_OBSERVATION_ONE", "F22_FULL_OLD_OBSERVATION_TWO"}:
            return "DESIRED" if self.observe_full_old() == "OLD" else "AMBIGUOUS"
        raise Generation13ActivationRejected("phase_f_forward_operation_rejected")

    def apply_forward_old(self, operation: str) -> None:
        file_operation = self._forward_file_activation(operation)
        if file_operation is not None:
            _phase_f_restore_file(self._file_contract(file_operation)[0], self.prepared.plan_digest)
            return
        if operation == "F01_STOP_TARGET_CONTAINER":
            current = r5_resume.phase_f_container_projection(r5_resume.CONTAINER, runner=self._runner)
            require(current is not None and self._target_matches(current), "phase_f_forward_target_identity_rejected")
            self._target_observation = r5_resume.phase_f_stop_container_exact(current, name=r5_resume.CONTAINER, runner=self._runner)
            return
        if operation == "F02_REMOVE_TARGET_CONTAINER":
            current = r5_resume.phase_f_container_projection(r5_resume.CONTAINER, runner=self._runner)
            require(current is not None and self._target_matches(current), "phase_f_forward_target_identity_rejected")
            r5_resume.phase_f_remove_container_exact(current, expected_network=self.expected_network, runner=self._runner)
            return
        if operation == "F03_RESTORE_OLD_CONTAINER_NAME":
            r5_resume.phase_f_rename_container_exact(self.old_container, source_name=self.target_container.archive_name, target_name=r5_resume.CONTAINER, runner=self._runner)
            return
        if operation == "F10_DAEMON_RELOAD_OLD":
            _run(["/usr/bin/systemctl", "daemon-reload"])
            return
        unit_prestate = self._forward_unit_prestate(operation)
        if unit_prestate is not None:
            self._restore_unit_prestate(unit_prestate)
            return
        if operation == "F15_RESTORE_OLD_RUNNING_STATE":
            r5_resume.phase_f_restore_old_running_exact(self.old_container, runner=self._runner)
            return
        if operation == "F16_ORDINARY_STARTUP_RECOVER":
            self._startup_recovery_result = self._ordinary_startup_recover()
            require(self._startup_result_is_typed(self._startup_recovery_result), "phase_f_startup_recovery_result_rejected")
            return
        raise Generation13ActivationRejected("phase_f_forward_observation_not_mutable")


def activate(
    prepared: PreparedActivation,
    *,
    expected_plan_sha256: str | None,
    preflight_only: bool,
    coordinated: bool = False,
) -> dict[str, object]:
    _cross_identity_manifest_smoke(prepared)
    if expected_plan_sha256 is not None:
        require(prepared.plan_digest == expected_plan_sha256, "plan_digest_drifted")
    if preflight_only:
        return {
            "plan_sha256": prepared.plan_digest,
            "release_set_id": prepared.release_set.release_set_id,
            "status": "TARGET_ARTIFACT_VERIFIED_NOT_READY",
        }
    raise Generation13ActivationRejected("phase_f_stage2_bundle_required")


def controller_entry() -> int:
    """Verify the sealed artifact, enter the sole transaction, and stop pre-T2."""

    try:
        AtomicReleaseSetTransaction.enter_canonical_owner(
            release_root=Path(__file__).parent,
            selected_release_sha256=os.environ.get(CONTROLLER_RELEASE_ENV),
            selected_config_sha256=os.environ.get(CONTROLLER_CONFIG_ENV),
            selected_authority_sha256=os.environ.get(CONTROLLER_AUTHORITY_ENV),
            t2_receipts=None,
        )
    except (Generation13ActivationRejected, ReleaseSetActivationRejected) as exc:
        code = getattr(exc, "code", str(exc))
        print(
            json.dumps(
                {"failure_gate": code, "status": "NOT_READY_NO_MUTATION"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 75
    raise AssertionError("canonical owner admission returned unexpectedly")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-candidate", required=True, type=Path)
    parser.add_argument("--runtime-candidate", required=True, type=Path)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--deploy-commit", required=True)
    parser.add_argument("--expected-core-release", required=True)
    parser.add_argument("--expected-runtime-release", required=True)
    parser.add_argument("--expected-definition-release", required=True)
    parser.add_argument("--expected-previous-epoch-sha256", required=True)
    parser.add_argument("--expected-previous-release-set-id", required=True)
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
            expected_previous_epoch_sha256=arguments.expected_previous_epoch_sha256,
            expected_previous_release_set_id=arguments.expected_previous_release_set_id,
            expected_revision=arguments.expected_revision,
            expected_turns=arguments.expected_turns,
            expected_summaries=arguments.expected_summaries,
            expected_pending=arguments.expected_pending,
        )
        result = activate(prepared, expected_plan_sha256=arguments.expected_plan_sha256, preflight_only=arguments.preflight_only)
    except (
        CredentialBindingRejected,
        ExternalEpochBundleRejected,
        ExternalEpochV3Rejected,
        Generation13ActivationRejected,
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
