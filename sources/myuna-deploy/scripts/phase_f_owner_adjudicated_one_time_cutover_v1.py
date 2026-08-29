#!/usr/bin/env python3
"""One bounded, stateless Phase-F cutover with an explicit rollback mode.

The command deliberately owns no journal, attempt namespace, retry loop, or
semantic-success decision.  A successful cutover only establishes the exact
technical state needed for an Owner adjudication.  Any ambiguous observation
fails closed; rollback is a separate, explicit invocation.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import dataclass, replace
import fcntl
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Iterator, Mapping, Protocol

import telegram_r5_boot_resume as boot


SCHEMA = "myuna.phase-f.owner-adjudicated-one-time-cutover.v1"
EXPECTED_DEPLOY_PARENT = "cab0fcbc29c513fe17c9b68a7438ea424a349036"
_FIXED_PRODUCT_AUTHORITY_FIELDS = (
    "builder",
    "controller",
    "files",
    "image",
    "parent",
    "releases",
    "schema",
    "source",
)
_VERIFIED_CONTROLLER_AUTHORITY_FIELDS = frozenset(
    (*_FIXED_PRODUCT_AUTHORITY_FIELDS, "authority_sha256", "release_sha256")
)
_EXPECTED_CONTROLLER_AUTHORITY_FIELDS = frozenset(
    {
        "controller_config_sha256",
        "controller_release_sha256",
        "controller_static_authority_sha256",
    }
)
RELEASES_ROOT = Path("/opt/myuna/telegram-r5/releases")
LOCK_PATH = RELEASES_ROOT / ".myuna-phase-f.lock"
OLD_CONTROLLER_RELEASE = (
    "7ebc81cf25d047c49f4555c85e1e6b90db66cfef8c25e47904b56ec2146bd4fc"
)
CURRENT_CONTROLLER_RELEASE = (
    "b78ef052c838dc896f98cb9ef8d2a0c96ae55b2d1146ede39d8e8753a976aa69"
)
OLD_UNIT_SHA256 = "0cd6edb71096a7e9ceccc996e912e5d0836c871053e88f47e9611e918351ed76"
UNIT_PATH = Path("/etc/systemd/system/myuna-telegram-owner-r5-resume.service")
UNIT_TEMPLATE = "myuna-telegram-owner-r5-resume.service.in"
CUTOVER_MEMBER = "phase_f_owner_adjudicated_one_time_cutover_v1.py"
BUILDER_MEMBER = "source-authority/build_telegram_r5_controller_release_v1.py"
R5_SERVICE = "myuna-telegram-owner-r5-resume.service"
CORE_SERVICE = "myuna-core@qq.service"
RUNTIME_SERVICE = "myuna-telegram-owner-runtime-dev.service"
RUNTIME_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
SERVICES = (R5_SERVICE, RUNTIME_SERVICE, RUNTIME_SOCKET, CORE_SERVICE)
ROLE_ORDER = (
    ("/etc/myuna/core-release-selector/qq.binding.json", "core_binding_selector"),
    ("/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf", "core_release_selector_dropin"),
    ("/etc/systemd/system/myuna-core@qq.service.d/zzzzzzzzz-p07-hybrid-external-v1.conf", "core_provider_gate_dropin"),
    ("/etc/systemd/system/myuna-core@qq.service.d/90-p07-owner-private-memory-v1.conf", "core_memory_dropin"),
    ("/etc/myuna-telegram-gateway/r5-resume-v1.json", "telegram_runtime_config"),
    ("/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/zzzzzzzzzzz-p07-hybrid-external-v1.conf", "telegram_runtime_dropin"),
    ("/etc/myuna-telegram-gateway/p07-owner-private-memory-selector-v4.json", "memory_selector_v4"),
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")

_OLD_CONTAINER = {
    "command_digest": "d8b8f6ade2b40236d6eed993eca8737de5cdf8c1d9e1d7d0948c35a5cc9596a2",
    "container_id": "5e5d94df745c87652217f50619ff64023e9dacad2e875479d9a32e1c715f0940",
    "effect_digest": "1887d8181cb790d67d15c990d86171dd36bd00140202aca9bf0dafb1bf251fae",
    "effect_environment_digest": "0e1e530e72a07fc1282610268e2323d731242d64ea5ba91e9807921c7660cb1e",
    "effect_host_digest": "582df4975667930ca05cc8ac91690257acf3c1385bc4d6555624a6b0b810cc29",
    "effect_mounts_digest": "8a5bad38ad5987ba0ccba498848b6d2fce1abda9c76a1ac7ce068ae442f4575b",
    "health": "unhealthy",
    "host_config_digest": "6e2eff170fbf6ede9d24151223d2cfed4dfe0cde5e3249a1266bdae7e18b0fd1",
    "image": "myuna/astrbot-phase-f-deterministic@sha256:ef2d2f966745b6d2e05b3286698bf6601a9a2c478f762b6b0df9703eee48d214",
    "mounts_digest": "92fc4d7d4fac55effa4526777c283dddc7f1f8c6ef4de34afb7c6f5c7b93d025",
    "name": boot.CONTAINER,
    "network_names": (boot.NETWORK,),
    "networks_digest": "d0b4c55dae4b10d628c3eff4396a8323f21d7eea76c0ce39f80923dd5dd793ed",
    "plan_digest": "bed60d0c4f567e389d0c5aa54b0300944f668c577b70d07ad268c9cec653d21a",
    "project": boot.COMPOSE_PROJECT,
    "restart_maximum_retry_count": 0,
    "restart_policy": "no",
    "service": boot.COMPOSE_SERVICE,
    "status": "exited",
    "target_config_digest": "0710c79b11aa9bcdccb6c73c83b60ac05626d16e33344ce17225136d0fed281c",
    "user": "988:982",
}
_NETWORK = {
    "attachable": False,
    "driver": "bridge",
    "enable_ipv6": False,
    "ingress": False,
    "internal": False,
    "ipam_digest": "d5ba8385fa724614039fd861d48f2d830d7a131bae6c1eed39a9ee71ebedcbd6",
    "labels_digest": "30bf4ceb7f5d44dce2d4864ffc7012ac0a076da00af9ccc15bc3bd074dda1090",
    "member_container_ids": (),
    "name": boot.NETWORK,
    "network_id": "0e968ab6d47794e48047df327b7ba1b34f42a41b17b73c420a49ef8dc9f08284",
    "options_digest": "db3dbc0eac234ea1dd90df7b0f7453e5145e522f550d284b03f59e0ffe47344c",
}
_TARGET_CONTAINER_CAUSES = frozenset(
    {
        "archive_old_collision_rejected",
        "archive_old_command_rejected",
        "archive_old_identity_rejected",
        "archive_old_poststate_rejected",
        "archive_old_state_rejected",
        "archive_old_unclassified_rejected",
        "target_create_command_rejected",
        "target_create_identity_rejected",
        "target_create_poststate_rejected",
        "target_create_prestate_rejected",
        "target_create_unclassified_rejected",
        "target_container_unclassified_rejected",
        "target_policy_command_rejected",
        "target_policy_identity_rejected",
        "target_policy_poststate_rejected",
        "target_policy_state_rejected",
        "target_start_command_rejected",
        "target_start_health_timeout",
        "target_start_identity_rejected",
        "target_start_poststate_rejected",
        "target_start_state_rejected",
    }
)
_MANUAL_REQUIRED_UNCLASSIFIED_CAUSE = "manual_effect_unclassified_rejected"


class CutoverRejected(RuntimeError):
    """A typed precondition, effect, or convergence rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ManualRequired(CutoverRejected):
    """A stopped partial result safe to project at the JSON boundary."""

    def __init__(self, kind: str, boundary: str, code: str) -> None:
        super().__init__(kind)
        self.kind = kind
        self.boundary = boundary
        self.effect_code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CutoverRejected(code)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("ascii")


def _read_regular(path: Path, *, mode: int | None = None, uid: int | None = None) -> bytes:
    metadata = path.lstat()
    _require(
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_nlink == 1
        and (mode is None or stat.S_IMODE(metadata.st_mode) == mode)
        and (uid is None or metadata.st_uid == uid),
        "regular_member_rejected",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        payload = b""
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            payload += chunk
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    _require(
        (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns),
        "member_changed",
    )
    return payload


def _file_projection(path: Path) -> dict[str, object]:
    payload = _read_regular(path)
    metadata = path.lstat()
    return {
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "sha256": sha256(payload).hexdigest(),
        "size": len(payload),
        "uid": metadata.st_uid,
    }


def _atomic_file(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    _require(path.is_absolute() and path.parent.is_dir() and not path.parent.is_symlink(), "write_parent_rejected")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".phase-f-cutover-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        pending = memoryview(payload)
        while pending:
            written = os.write(descriptor, pending)
            _require(written > 0, "write_progress_rejected")
            pending = pending[written:]
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    _require(spec is not None and spec.loader is not None, "release_builder_rejected")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(name, None)
        raise CutoverRejected("release_builder_rejected") from exc
    return module


def _render_unit(
    release_root: Path,
    expected: Mapping[str, object],
    *,
    guard: bool,
    selection: ReleaseSelection | None = None,
) -> bytes:
    template = _read_regular(release_root / UNIT_TEMPLATE, mode=0o444).decode("utf-8")
    replacements = {
        "@CONTROLLER_RELEASE_ROOT@": release_root.as_posix(),
        "@CONTROLLER_RELEASE_DIGEST@": str(expected["controller_release_sha256"]),
        "@CONTROLLER_CONFIG_SHA256@": str(expected["controller_config_sha256"]),
        "@CONTROLLER_AUTHORITY_SHA256@": str(expected["controller_static_authority_sha256"]),
    }
    for marker, value in replacements.items():
        _require(template.count(marker) >= 1, "unit_template_rejected")
        template = template.replace(marker, value)
    _require("@CONTROLLER_" not in template, "unit_template_rejected")
    if guard:
        _require(selection is not None, "release_selection_rejected")
        old = f"ExecStart=/usr/bin/python3 {release_root.as_posix()}/telegram_r5_boot_resume.py"
        new = (
            f"ExecStart=/usr/bin/python3 {release_root.as_posix()}/{CUTOVER_MEMBER} preflight"
            f" --reviewed-deploy-commit {selection.deploy_commit}"
            f" --reviewed-deploy-tree {selection.deploy_tree}"
            f" --public-package-sha256 {selection.public_package_sha256}"
            f" --release-sha256 {selection.release_sha256}"
        )
        _require(template.count(old) == 1, "unit_template_rejected")
        template = template.replace(old, new)
    payload = template.encode("utf-8")
    _require(payload.endswith(b"\n") and b"\r" not in payload, "unit_template_rejected")
    return payload


@dataclass(frozen=True)
class SealedMember:
    path: Path
    payload: bytes
    mode: int
    uid: int
    gid: int
    role: str


@dataclass(frozen=True)
class ReleaseSelection:
    deploy_commit: str
    deploy_tree: str
    public_package_sha256: str
    release_sha256: str


@dataclass(frozen=True)
class Preflight:
    release_root: Path
    new_unit: bytes
    old_unit: bytes
    authority: Mapping[str, object]
    current: tuple[SealedMember, ...]
    target_members: tuple[SealedMember, ...]
    old: boot.PhaseFContainerProjection
    target_authority: boot.PhaseFTargetContainer
    target: boot.PhaseFContainerProjection | None
    archive: boot.PhaseFContainerProjection | None
    network: boot.PhaseFNetworkProjection
    topology: str


class Effects(Protocol):
    def preflight(self, mode: str) -> Preflight: ...
    def archive_old(self, state: Preflight) -> Preflight: ...
    def create_target(self, state: Preflight) -> Preflight: ...
    def write_member(self, member: SealedMember) -> None: ...
    def write_new_unit(self, state: Preflight) -> None: ...
    def daemon_reload(self) -> None: ...
    def start_service(self, unit: str) -> None: ...
    def start_target(self, state: Preflight) -> None: ...
    def stop_service(self, unit: str) -> None: ...
    def stop_target(self, state: Preflight) -> None: ...
    def restore_old_unit(self, state: Preflight) -> None: ...
    def restore_old_container(self, state: Preflight) -> None: ...
    def verify_new_running(self, state: Preflight) -> None: ...
    def verify_old_stopped(self, state: Preflight) -> None: ...


def _external_release_document(
    release_root: Path, selection: ReleaseSelection
) -> Mapping[str, object]:
    """Bind caller-selected reviewed source/public/release before packaged code."""

    _require(_COMMIT.fullmatch(selection.deploy_commit) is not None, "reviewed_source_rejected")
    _require(_COMMIT.fullmatch(selection.deploy_tree) is not None, "reviewed_source_rejected")
    _require(_DIGEST.fullmatch(selection.public_package_sha256) is not None, "public_package_rejected")
    _require(_DIGEST.fullmatch(selection.release_sha256) is not None, "release_selection_rejected")
    _require(release_root.name == selection.release_sha256, "release_selection_rejected")
    manifest_payload = _read_regular(release_root / "MANIFEST.json", mode=0o444)
    public_payload = _read_regular(release_root / "CORRESPONDING_SOURCE.json", mode=0o444)
    _require(sha256(manifest_payload).hexdigest() == selection.release_sha256, "release_selection_rejected")
    _require(sha256(public_payload).hexdigest() == selection.public_package_sha256, "public_package_rejected")
    try:
        document = json.loads(manifest_payload.decode("ascii"))
        public = json.loads(public_payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CutoverRejected("external_selection_rejected") from exc
    _require(
        type(document) is dict
        and type(public) is dict
        and manifest_payload == _canonical(document)
        and public_payload == _canonical(public),
        "external_selection_rejected",
    )
    source = document.get("source_receipt")
    _require(
        source == public
        and document.get("deploy_commit") == selection.deploy_commit
        and document.get("deploy_tree") == selection.deploy_tree
        and document.get("paired_source_package_sha256") == selection.public_package_sha256
        and document.get("paired_source_receipt_sha256") == selection.public_package_sha256
        and public.get("deploy_commit") == selection.deploy_commit
        and public.get("deploy_tree") == selection.deploy_tree,
        "reviewed_source_rejected",
    )
    return document


def _sealed_members(authority: Mapping[str, object]) -> tuple[SealedMember, ...]:
    """Decode the complete builder-sealed seven-role projection in literal order."""

    files = authority.get("files")
    _require(
        type(files) is dict and set(files) == {path for path, _role in ROLE_ORDER},
        "seven_role_authority_rejected",
    )
    result: list[SealedMember] = []
    for path, role in ROLE_ORDER:
        row = files[path]
        _require(type(row) is dict and row.get("role") == role, "seven_role_authority_rejected")
        try:
            payload = base64.b64decode(str(row["payload_b64"]), validate=True)
            mode = int(str(row["mode"]), 8)
            uid = row["uid"]
            gid = row["gid"]
        except (KeyError, TypeError, ValueError) as exc:
            raise CutoverRejected("seven_role_authority_rejected") from exc
        _require(
            type(uid) is int
            and type(gid) is int
            and uid >= 0
            and gid >= 0
            and str(row["mode"]) == f"{mode:04o}"
            and _DIGEST.fullmatch(str(row.get("payload_sha256"))) is not None
            and sha256(payload).hexdigest() == row["payload_sha256"],
            "seven_role_authority_rejected",
        )
        result.append(SealedMember(Path(path), payload, mode, uid, gid, role))
    _require(
        len(result) == 7
        and len({member.path for member in result}) == 7
        and len({member.role for member in result}) == 7,
        "seven_role_authority_rejected",
    )
    return tuple(result)


def _target_matches_authority(
    authority: boot.PhaseFTargetContainer,
    observed: boot.PhaseFContainerProjection | None,
) -> bool:
    """Admit a dynamic-ID TARGET only through its complete source projection."""

    effect = authority.effect
    if observed is None or type(effect) is not dict:
        return False
    expected = {
        "command_digest": effect.get("command_sha256"),
        "effect_digest": effect.get("effect_sha256"),
        "effect_environment_digest": effect.get("environment_sha256"),
        "effect_host_digest": effect.get("host_sha256"),
        "effect_mounts_digest": effect.get("mounts_sha256"),
        "image": authority.image,
        "name": boot.CONTAINER,
        "network_names": (boot.NETWORK,),
        "plan_digest": authority.plan_digest,
        "project": boot.COMPOSE_PROJECT,
        "service": boot.COMPOSE_SERVICE,
        "target_config_digest": authority.target_config_digest,
        "user": authority.user,
    }
    return (
        all(getattr(observed, key) == value for key, value in expected.items())
        and observed.status in {"created", "exited", "running"}
        and (
            observed.restart_policy,
            observed.restart_maximum_retry_count,
        )
        in {
            ("no", 0),
            (
                boot.EXPECTED_RESTART_POLICY,
                boot.EXPECTED_RESTART_MAXIMUM_RETRY_COUNT,
            ),
        }
    )


def _container_effect_cause(operation: str, exc: BaseException) -> str:
    lower = str(exc) if isinstance(exc, boot.ResumeRejected) else ""
    mappings = {
        "archive": {
            "phase_f_rename_collision_ambiguous": "archive_old_collision_rejected",
            "phase_f_rename_identity_rejected": "archive_old_identity_rejected",
            "phase_f_rename_poststate_rejected": "archive_old_poststate_rejected",
            "phase_f_rename_state_rejected": "archive_old_state_rejected",
        },
        "create": {
            "phase_f_create_archive_drift": "target_create_identity_rejected",
            "phase_f_create_canonical_collision": "target_create_identity_rejected",
            "phase_f_create_network_poststate_rejected": "target_create_poststate_rejected",
            "phase_f_create_network_prestate_rejected": "target_create_prestate_rejected",
            "phase_f_create_poststate_rejected": "target_create_poststate_rejected",
            "phase_f_external_network_not_ready": "target_create_prestate_rejected",
            "phase_f_runtime_access_rejected": "target_create_prestate_rejected",
            "phase_f_runtime_identity_model_rejected": "target_create_prestate_rejected",
            "phase_f_runtime_resource_acl_rejected": "target_create_prestate_rejected",
            "phase_f_runtime_resource_metadata_rejected": "target_create_prestate_rejected",
            "phase_f_target_effect_archive_rejected": "target_create_identity_rejected",
            "phase_f_target_effect_prestate_rejected": "target_create_prestate_rejected",
        },
    }
    cause = mappings[operation].get(lower)
    if cause is None and re.fullmatch(r"fixed_command_failed:docker:-?\d+", lower):
        cause = f"{'archive_old' if operation == 'archive' else 'target_create'}_command_rejected"
    return cause or f"{'archive_old' if operation == 'archive' else 'target_create'}_unclassified_rejected"


class HostEffects:
    """Exact host effects.  Tests replace this object; source tests never call it."""

    def __init__(self, selection: ReleaseSelection) -> None:
        self._builder = None
        self._selection = selection

    def _load_release(
        self,
    ) -> tuple[
        Path,
        Mapping[str, object],
        tuple[SealedMember, ...],
        tuple[SealedMember, ...],
        bytes,
        bytes,
    ]:
        release_root = Path(__file__).resolve().parent
        _require(release_root.parent == RELEASES_ROOT and _DIGEST.fullmatch(release_root.name) is not None, "release_path_rejected")
        external_document = _external_release_document(release_root, self._selection)
        builder = _load_module("_phase_f_cutover_release_builder", release_root / BUILDER_MEMBER)
        self._builder = builder
        authority = builder.verified_controller_authority(RELEASES_ROOT, release_root.name)
        expected = builder.expected_controller_authority(RELEASES_ROOT, release_root.name)
        authority_fields = set(authority) if type(authority) is dict else set()
        fixed_authority = (
            {key: authority[key] for key in _FIXED_PRODUCT_AUTHORITY_FIELDS}
            if all(key in authority_fields for key in _FIXED_PRODUCT_AUTHORITY_FIELDS)
            else None
        )
        manifest_authority = external_document.get("fixed_product_authority")
        source = authority.get("source") if type(authority) is dict else None
        release_sha256 = (
            authority.get("release_sha256") if type(authority) is dict else None
        )
        authority_sha256 = (
            authority.get("authority_sha256") if type(authority) is dict else None
        )
        expected_release_sha256 = (
            expected.get("controller_release_sha256")
            if type(expected) is dict
            else None
        )
        expected_config_sha256 = (
            expected.get("controller_config_sha256")
            if type(expected) is dict
            else None
        )
        expected_authority_sha256 = (
            expected.get("controller_static_authority_sha256")
            if type(expected) is dict
            else None
        )
        _require(
            type(authority) is dict
            and authority_fields == _VERIFIED_CONTROLLER_AUTHORITY_FIELDS
            and type(manifest_authority) is dict
            and set(manifest_authority) == set(_FIXED_PRODUCT_AUTHORITY_FIELDS)
            and all(
                type(authority[key]) is dict
                for key in _FIXED_PRODUCT_AUTHORITY_FIELDS
                if key != "schema"
            )
            and type(authority["schema"]) is str
            and type(expected) is dict
            and set(expected) == _EXPECTED_CONTROLLER_AUTHORITY_FIELDS
            and type(expected_config_sha256) is str
            and _DIGEST.fullmatch(expected_config_sha256) is not None
            and type(release_sha256) is str
            and _DIGEST.fullmatch(release_sha256) is not None
            and release_sha256 == self._selection.release_sha256 == release_root.name
            and type(expected_release_sha256) is str
            and expected_release_sha256 == release_sha256
            and type(authority_sha256) is str
            and _DIGEST.fullmatch(authority_sha256) is not None
            and type(expected_authority_sha256) is str
            and _DIGEST.fullmatch(expected_authority_sha256) is not None
            and authority_sha256 == expected_authority_sha256
            and type(source) is dict
            and source.get("deploy_parent") == EXPECTED_DEPLOY_PARENT
            and source.get("deploy_commit") == self._selection.deploy_commit
            and source.get("deploy_tree") == self._selection.deploy_tree
            and fixed_authority == manifest_authority,
            "source_authority_rejected",
        )
        _require(builder.verify_release(RELEASES_ROOT, release_root.name, expected), "release_verification_rejected")
        old_document, _old_authority = builder._fixed_historical_authority(
            RELEASES_ROOT / OLD_CONTROLLER_RELEASE
        )
        _current_document, current_authority = builder._fixed_historical_authority(
            RELEASES_ROOT / CURRENT_CONTROLLER_RELEASE
        )
        old_expected = builder._expected(old_document, OLD_CONTROLLER_RELEASE)
        current_members = _sealed_members(current_authority)
        target_members = _sealed_members(authority)
        new_unit = _render_unit(
            release_root,
            expected,
            guard=True,
            selection=self._selection,
        )
        old_unit = _render_unit(RELEASES_ROOT / OLD_CONTROLLER_RELEASE, old_expected, guard=False)
        _require(sha256(old_unit).hexdigest() == OLD_UNIT_SHA256, "old_unit_authority_rejected")
        return (
            release_root,
            authority,
            current_members,
            target_members,
            new_unit,
            old_unit,
        )

    @staticmethod
    def _service_state(unit: str) -> str:
        return boot.run(["/usr/bin/systemctl", "is-active", unit], check=False)

    @staticmethod
    def _governed_container_names() -> tuple[str, ...]:
        try:
            output = boot.run(
                [
                    "/usr/bin/docker",
                    "container",
                    "ls",
                    "--all",
                    "--format",
                    "{{.Names}}",
                ]
            )
        except Exception:
            raise CutoverRejected("container_census_rejected") from None
        names = tuple(sorted(line.strip() for line in output.splitlines() if line.strip()))
        _require(
            len(names) == len(set(names))
            and all("\x00" not in name and "\r" not in name for name in names),
            "container_census_rejected",
        )
        return tuple(
            name
            for name in names
            if name == boot.CONTAINER
            or re.fullmatch(re.escape(boot.ARCHIVE_PREFIX) + r"[0-9a-f]{16}", name)
            is not None
        )

    @staticmethod
    def _member_projection(member: SealedMember) -> dict[str, object]:
        return {
            "gid": member.gid,
            "mode": f"{member.mode:04o}",
            "sha256": sha256(member.payload).hexdigest(),
            "size": len(member.payload),
            "uid": member.uid,
        }

    def preflight(self, mode: str) -> Preflight:
        (
            release_root,
            authority,
            current,
            target_members,
            new_unit,
            old_unit,
        ) = self._load_release()
        target_matches = []
        current_matches = []
        for current_member, target_member in zip(current, target_members, strict=True):
            _require(
                current_member.path == target_member.path
                and current_member.role == target_member.role,
                "seven_role_authority_rejected",
            )
            observed = _file_projection(current_member.path)
            current_matches.append(observed == self._member_projection(current_member))
            target_matches.append(observed == self._member_projection(target_member))
        unit_sha = sha256(_read_regular(UNIT_PATH, mode=0o644, uid=0)).hexdigest()
        expected_old = boot.PhaseFContainerProjection(**_OLD_CONTAINER)
        expected_network = boot.PhaseFNetworkProjection(**_NETWORK)
        try:
            target_authority = self._builder.verified_target_container_authority(
                authority,
                expected_old,
                expected_network,
            )
        except Exception:
            raise CutoverRejected("target_container_authority_rejected") from None
        archive_name = target_authority.archive_name
        expected_archive = replace(expected_old, name=archive_name)
        target = boot.phase_f_container_projection(boot.CONTAINER)
        archive = boot.phase_f_container_projection(archive_name)
        network = boot.phase_f_network_projection()
        governed_names = self._governed_container_names()
        _require(network is not None, "container_topology_rejected")
        same_network = boot._phase_f_same_network_object(expected_network, network)
        old_only = (
            target == expected_old
            and archive is None
            and network == expected_network
            and governed_names == (boot.CONTAINER,)
        )
        archive_only = (
            target is None
            and archive == expected_archive
            and network == expected_network
            and governed_names == (archive_name,)
        )
        archive_target = (
            archive == expected_archive
            and _target_matches_authority(target_authority, target)
            and same_network
            and target is not None
            and network.member_container_ids in {(), (target.container_id,)}
            and governed_names == tuple(sorted((archive_name, boot.CONTAINER)))
        )
        topology = (
            "old_only"
            if old_only
            else "archive_only"
            if archive_only
            else "archive_target"
            if archive_target
            else "rejected"
        )
        if mode in {"preflight", "cutover"}:
            _require(all(current_matches) and unit_sha == OLD_UNIT_SHA256, "cutover_file_prestate_rejected")
            _require(topology == "old_only", "cutover_container_prestate_rejected")
            _require(all(self._service_state(unit) in {"inactive", "failed"} for unit in SERVICES), "cutover_service_prestate_rejected")
        elif mode == "rollback":
            _require(
                all(current_match or target_match for current_match, target_match in zip(current_matches, target_matches, strict=True)),
                "rollback_file_prestate_rejected",
            )
            _require(unit_sha in {OLD_UNIT_SHA256, sha256(new_unit).hexdigest()}, "rollback_unit_prestate_rejected")
            _require(
                topology in {"old_only", "archive_only", "archive_target"},
                "rollback_container_prestate_rejected",
            )
            if topology in {"old_only", "archive_only"}:
                _require(
                    network.member_container_ids == ()
                    and all(self._service_state(unit) in {"inactive", "failed"} for unit in SERVICES),
                    "rollback_stopped_topology_rejected",
                )
        else:
            raise CutoverRejected("mode_rejected")
        return Preflight(
            release_root,
            new_unit,
            old_unit,
            authority,
            current,
            target_members,
            expected_old,
            target_authority,
            target,
            archive,
            expected_network,
            topology,
        )

    def archive_old(self, state: Preflight) -> Preflight:
        _require(
            state.topology == "old_only"
            and state.target == state.old
            and state.archive is None,
            "archive_old_prestate_rejected",
        )
        try:
            archived = boot.phase_f_rename_container_exact(
                state.old,
                source_name=boot.CONTAINER,
                target_name=state.target_authority.archive_name,
            )
        except Exception as exc:
            raise CutoverRejected(_container_effect_cause("archive", exc)) from None
        return replace(
            state,
            target=None,
            archive=archived,
            topology="archive_only",
        )

    def create_target(self, state: Preflight) -> Preflight:
        _require(
            state.topology == "archive_only"
            and state.target is None
            and state.archive is not None,
            "target_create_prestate_rejected",
        )
        try:
            target = boot.phase_f_create_target_stopped(
                state.target_authority,
                expected_network=state.network,
                archived_old=state.archive,
            )
        except Exception as exc:
            raise CutoverRejected(_container_effect_cause("create", exc)) from None
        _require(
            _target_matches_authority(state.target_authority, target),
            "target_create_poststate_rejected",
        )
        return replace(state, target=target, topology="archive_target")

    def write_new_unit(self, state: Preflight) -> None:
        _atomic_file(UNIT_PATH, state.new_unit, mode=0o644, uid=0, gid=0)
        _require(sha256(_read_regular(UNIT_PATH, mode=0o644, uid=0)).hexdigest() == sha256(state.new_unit).hexdigest(), "new_unit_poststate_rejected")

    def daemon_reload(self) -> None:
        boot.run(["/usr/bin/systemctl", "daemon-reload"])

    def start_service(self, unit: str) -> None:
        _require(unit in {CORE_SERVICE, RUNTIME_SOCKET}, "service_start_rejected")
        _require(self._service_state(unit) in {"inactive", "failed"}, "service_start_prestate_rejected")
        boot.run(["/usr/bin/systemctl", "start", unit])
        _require(self._service_state(unit) == "active", "service_start_poststate_rejected")

    def start_target(self, state: Preflight) -> None:
        _require(state.target is not None, "target_container_missing")
        try:
            selected = boot.phase_f_set_restart_policy_exact(state.target)
        except boot.ResumeRejected as exc:
            lower = str(exc)
            cause = {
                "phase_f_policy_identity_rejected": "target_policy_identity_rejected",
                "phase_f_policy_poststate_rejected": "target_policy_poststate_rejected",
                "phase_f_policy_state_ambiguous": "target_policy_state_rejected",
            }.get(lower)
            if cause is None and re.fullmatch(r"fixed_command_failed:docker:-?\d+", lower):
                cause = "target_policy_command_rejected"
            raise CutoverRejected(cause or "target_container_unclassified_rejected") from None
        except Exception:
            raise CutoverRejected("target_container_unclassified_rejected") from None
        try:
            boot.phase_f_start_container_exact(selected)
        except boot.ResumeRejected as exc:
            lower = str(exc)
            cause = {
                "phase_f_start_health_timeout": "target_start_health_timeout",
                "phase_f_start_identity_rejected": "target_start_identity_rejected",
                "phase_f_start_poststate_rejected": "target_start_poststate_rejected",
                "phase_f_start_state_ambiguous": "target_start_state_rejected",
            }.get(lower)
            if cause is None and re.fullmatch(r"fixed_command_failed:docker:-?\d+", lower):
                cause = "target_start_command_rejected"
            raise CutoverRejected(cause or "target_container_unclassified_rejected") from None
        except Exception:
            raise CutoverRejected("target_container_unclassified_rejected") from None

    def stop_service(self, unit: str) -> None:
        _require(unit in SERVICES, "service_stop_rejected")
        observed = self._service_state(unit)
        if observed in {"inactive", "failed"}:
            return
        _require(observed in {"active", "activating", "deactivating"}, "service_stop_ambiguous")
        boot.run(["/usr/bin/systemctl", "stop", unit])
        _require(self._service_state(unit) in {"inactive", "failed"}, "service_stop_poststate_rejected")

    def stop_target(self, state: Preflight) -> None:
        if state.topology == "old_only":
            return
        observed = boot.phase_f_container_projection(boot.CONTAINER)
        if observed is None:
            return
        _require(
            _target_matches_authority(state.target_authority, observed),
            "rollback_target_identity_rejected",
        )
        boot.phase_f_stop_container_exact(observed, name=boot.CONTAINER)

    def write_member(self, member: SealedMember) -> None:
        _atomic_file(member.path, member.payload, mode=member.mode, uid=member.uid, gid=member.gid)
        _require(
            _file_projection(member.path) == self._member_projection(member),
            "sealed_member_poststate_rejected",
        )

    def restore_old_unit(self, state: Preflight) -> None:
        _atomic_file(UNIT_PATH, state.old_unit, mode=0o644, uid=0, gid=0)
        _require(sha256(_read_regular(UNIT_PATH, mode=0o644, uid=0)).hexdigest() == OLD_UNIT_SHA256, "old_unit_poststate_rejected")

    def restore_old_container(self, state: Preflight) -> None:
        observed = boot.phase_f_container_projection(boot.CONTAINER)
        archive = boot.phase_f_container_projection(
            state.target_authority.archive_name
        )
        expected_archive = replace(
            state.old,
            name=state.target_authority.archive_name,
        )
        if observed == state.old and archive is None:
            return
        _require(
            archive == expected_archive,
            "rollback_archive_identity_rejected",
        )
        if observed is not None:
            _require(
                _target_matches_authority(state.target_authority, observed),
                "rollback_target_identity_rejected",
            )
            boot.phase_f_remove_container_exact(observed, expected_network=state.network)
        boot.phase_f_rename_container_exact(
            expected_archive,
            source_name=state.target_authority.archive_name,
            target_name=boot.CONTAINER,
        )

    def verify_new_running(self, state: Preflight) -> None:
        _require(sha256(_read_regular(UNIT_PATH, mode=0o644, uid=0)).hexdigest() == sha256(state.new_unit).hexdigest(), "new_unit_convergence_rejected")
        _require(self._service_state(CORE_SERVICE) == "active" and self._service_state(RUNTIME_SOCKET) == "active", "new_service_convergence_rejected")
        target = boot.phase_f_container_projection(boot.CONTAINER)
        _require(
            _target_matches_authority(state.target_authority, target)
            and target is not None
            and target.container_id == state.target.container_id
            and target.status == "running"
            and target.health == "healthy",
            "new_container_convergence_rejected",
        )

    def verify_old_stopped(self, state: Preflight) -> None:
        _require(sha256(_read_regular(UNIT_PATH, mode=0o644, uid=0)).hexdigest() == OLD_UNIT_SHA256, "old_unit_convergence_rejected")
        _require(all(self._service_state(unit) in {"inactive", "failed"} for unit in SERVICES), "old_service_convergence_rejected")
        old = boot.phase_f_container_projection(boot.CONTAINER)
        archive = boot.phase_f_container_projection(
            state.target_authority.archive_name
        )
        network = boot.phase_f_network_projection()
        _require(
            old == state.old
            and archive is None
            and network == state.network
            and self._governed_container_names() == (boot.CONTAINER,)
            and old.status in {"created", "exited"},
            "old_container_convergence_rejected",
        )


def execute(mode: str, effects: Effects) -> dict[str, object]:
    """Run one finite mode.  No result is a semantic product-success claim."""

    state = effects.preflight(mode)
    if mode == "preflight":
        return {"mode": mode, "schema": SCHEMA, "status": "PREFLIGHT_ACCEPTED_ZERO_EFFECT"}
    if mode == "cutover":
        boundary = "preflight"
        try:
            boundary = "archive_old"
            state = effects.archive_old(state)
            boundary = "create_target"
            state = effects.create_target(state)
            for member in state.target_members:
                boundary = f"materialize:{member.role}"
                effects.write_member(member)
            boundary = "unit"
            effects.write_new_unit(state)
            boundary = "daemon_reload"
            effects.daemon_reload()
            boundary = "core_service"
            effects.start_service(CORE_SERVICE)
            boundary = "runtime_socket"
            effects.start_service(RUNTIME_SOCKET)
            boundary = "target_container"
            effects.start_target(state)
            boundary = "new_convergence"
            effects.verify_new_running(state)
        except Exception as exc:
            try:
                effects.stop_target(state)
            except Exception:
                pass
            for unit in (R5_SERVICE, RUNTIME_SERVICE, RUNTIME_SOCKET, CORE_SERVICE):
                try:
                    effects.stop_service(unit)
                except Exception:
                    pass
            code = exc.code if isinstance(exc, CutoverRejected) else "effect_exception"
            raise ManualRequired("cutover_manual_required", boundary, code) from exc
        return {
            "mode": mode,
            "schema": SCHEMA,
            "status": "OWNER_ADJUDICATION_REQUIRED",
            "technical_effect_complete": True,
            "semantic_success": False,
        }
    if mode == "rollback":
        boundary = "preflight"
        try:
            for unit in (R5_SERVICE, RUNTIME_SERVICE, RUNTIME_SOCKET, CORE_SERVICE):
                boundary = f"stop:{unit}"
                effects.stop_service(unit)
            boundary = "stop:target_container"
            effects.stop_target(state)
            for member in state.current:
                boundary = f"restore:{member.role}"
                effects.write_member(member)
            boundary = "restore:old_unit"
            effects.restore_old_unit(state)
            boundary = "daemon_reload"
            effects.daemon_reload()
            boundary = "restore:old_container"
            effects.restore_old_container(state)
            boundary = "old_convergence"
            effects.verify_old_stopped(state)
        except Exception as exc:
            code = exc.code if isinstance(exc, CutoverRejected) else "effect_exception"
            raise ManualRequired("rollback_manual_required", boundary, code) from exc
        return {
            "mode": mode,
            "schema": SCHEMA,
            "status": "EXACT_OLD_STOPPED_ROLLBACK_CONVERGED",
            "semantic_success": False,
        }
    raise CutoverRejected("mode_rejected")


@contextmanager
def releases_lock() -> Iterator[None]:
    metadata = LOCK_PATH.lstat()
    _require(stat.S_ISREG(metadata.st_mode) and not LOCK_PATH.is_symlink() and metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o644, "releases_lock_rejected")
    descriptor = os.open(LOCK_PATH, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        observed = os.fstat(descriptor)
        _require((metadata.st_dev, metadata.st_ino) == (observed.st_dev, observed.st_ino), "releases_lock_substituted")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CutoverRejected("competing_owner_rejected") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("preflight", "cutover", "rollback"))
    parser.add_argument("--reviewed-deploy-commit", required=True)
    parser.add_argument("--reviewed-deploy-tree", required=True)
    parser.add_argument("--public-package-sha256", required=True)
    parser.add_argument("--release-sha256", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        print(_canonical({"schema": SCHEMA, "status": "rejected"}).decode("ascii"), end="")
        return 1
    try:
        selection = ReleaseSelection(
            deploy_commit=args.reviewed_deploy_commit,
            deploy_tree=args.reviewed_deploy_tree,
            public_package_sha256=args.public_package_sha256,
            release_sha256=args.release_sha256,
        )
        with releases_lock():
            result = execute(args.mode, HostEffects(selection))
    except ManualRequired as exc:
        cause = (
            exc.effect_code
            if exc.effect_code in _TARGET_CONTAINER_CAUSES
            else _MANUAL_REQUIRED_UNCLASSIFIED_CAUSE
        )
        print(
            _canonical(
                {
                    "boundary": exc.boundary,
                    "cause": cause,
                    "mode": args.mode,
                    "schema": SCHEMA,
                    "status": exc.kind,
                }
            ).decode("ascii"),
            end="",
        )
        return 1
    except (CutoverRejected, OSError, UnicodeError, ValueError, KeyError):
        print(_canonical({"mode": args.mode, "schema": SCHEMA, "status": "rejected"}).decode("ascii"), end="")
        return 1
    print(_canonical(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
