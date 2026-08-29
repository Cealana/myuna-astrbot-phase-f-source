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
from dataclasses import dataclass
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
EXPECTED_DEPLOY_PARENT = "c172aad62030bdd8f319ae394afe9665c936eb7d"
RELEASES_ROOT = Path("/opt/myuna/telegram-r5/releases")
LOCK_PATH = RELEASES_ROOT / ".myuna-phase-f.lock"
CHECKPOINT_ROOT = (
    RELEASES_ROOT.parent
    / "attempt6-third-state-checkpoints-v1"
    / "2b2f1affaa383d922a6dfef96a666b181e3ab9af4eb8d2339fbf97cf2fcb7831"
)
CHECKPOINT_MANIFEST_SHA256 = (
    "be6f48094d1f2dab83213abdfa8c75221f967d7e60f4271d513f270466c6cb54"
)
OLD_CONTROLLER_RELEASE = (
    "7ebc81cf25d047c49f4555c85e1e6b90db66cfef8c25e47904b56ec2146bd4fc"
)
OLD_UNIT_SHA256 = "0cd6edb71096a7e9ceccc996e912e5d0836c871053e88f47e9611e918351ed76"
UNIT_PATH = Path("/etc/systemd/system/myuna-telegram-owner-r5-resume.service")
UNIT_TEMPLATE = "myuna-telegram-owner-r5-resume.service.in"
CUTOVER_MEMBER = "phase_f_owner_adjudicated_one_time_cutover_v1.py"
BUILDER_MEMBER = "source-authority/build_telegram_r5_controller_release_v1.py"
CHECKPOINT_SCHEMA = "myuna.phase-f.attempt6-third-state-checkpoint.v1"
FILE_IDENTITY_SCHEMA = "myuna.phase-f.file-continuity.v1"
R5_SERVICE = "myuna-telegram-owner-r5-resume.service"
CORE_SERVICE = "myuna-core@qq.service"
RUNTIME_SERVICE = "myuna-telegram-owner-runtime-dev.service"
RUNTIME_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
SERVICES = (R5_SERVICE, RUNTIME_SERVICE, RUNTIME_SOCKET, CORE_SERVICE)
ARCHIVE_NAME = "myuna-astrbot-telegram-dev.pre-source-command-20260826T045000Z"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")

_TARGET_CONTAINER = {
    "command_digest": "d8b8f6ade2b40236d6eed993eca8737de5cdf8c1d9e1d7d0948c35a5cc9596a2",
    "container_id": "7e58b9c7cb9f508bf4ab5f9401f86d0b1cfa0845b24fa2ac4beadcb8ae45f610",
    "effect_digest": "1887d8181cb790d67d15c990d86171dd36bd00140202aca9bf0dafb1bf251fae",
    "effect_environment_digest": "0e1e530e72a07fc1282610268e2323d731242d64ea5ba91e9807921c7660cb1e",
    "effect_host_digest": "be8fa2878126856ab5d48bed1466ceede49aae5231069fa77b70e93eb9fc1d9c",
    "effect_mounts_digest": "5fb29c83cdbd9f8bb90b9790ffb362579ab02d9cf2ee655472ef14d0579e05a4",
    "health": "unhealthy",
    "host_config_digest": "004ffd5437f59b2bc55ab3ca56a3227d318ad9fb962f2178b901de7b97be7bea",
    "image": "myuna/astrbot-phase-f-deterministic@sha256:ef2d2f966745b6d2e05b3286698bf6601a9a2c478f762b6b0df9703eee48d214",
    "mounts_digest": "f2a6cee29aefa34877187ede627fdd368b91719d8b4e6b8248c6a15a77864d4d",
    "name": boot.CONTAINER,
    "network_names": (boot.NETWORK,),
    "networks_digest": "d34dec791d65a71ca52282b02ef8ec28587d4845400e026ee153925b9eda9f45",
    "plan_digest": "bed60d0c4f567e389d0c5aa54b0300944f668c577b70d07ad268c9cec653d21a",
    "project": boot.COMPOSE_PROJECT,
    "restart_maximum_retry_count": 0,
    "restart_policy": "no",
    "service": boot.COMPOSE_SERVICE,
    "status": "exited",
    "target_config_digest": "0710c79b11aa9bcdccb6c73c83b60ac05626d16e33344ce17225136d0fed281c",
    "user": "988:982",
}
_ARCHIVE_CONTAINER = {
    **_TARGET_CONTAINER,
    "container_id": "5e5d94df745c87652217f50619ff64023e9dacad2e875479d9a32e1c715f0940",
    "effect_host_digest": "582df4975667930ca05cc8ac91690257acf3c1385bc4d6555624a6b0b810cc29",
    "effect_mounts_digest": "8a5bad38ad5987ba0ccba498848b6d2fce1abda9c76a1ac7ce068ae442f4575b",
    "host_config_digest": "6e2eff170fbf6ede9d24151223d2cfed4dfe0cde5e3249a1266bdae7e18b0fd1",
    "mounts_digest": "92fc4d7d4fac55effa4526777c283dddc7f1f8c6ef4de34afb7c6f5c7b93d025",
    "name": ARCHIVE_NAME,
    "networks_digest": "d0b4c55dae4b10d628c3eff4396a8323f21d7eea76c0ce39f80923dd5dd793ed",
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
class CheckpointMember:
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
    checkpoint: tuple[CheckpointMember, ...]
    target: boot.PhaseFContainerProjection | None
    archive: boot.PhaseFContainerProjection
    network: boot.PhaseFNetworkProjection


class Effects(Protocol):
    def preflight(self, mode: str) -> Preflight: ...
    def write_new_unit(self, state: Preflight) -> None: ...
    def daemon_reload(self) -> None: ...
    def start_service(self, unit: str) -> None: ...
    def start_target(self, state: Preflight) -> None: ...
    def stop_service(self, unit: str) -> None: ...
    def stop_target(self, state: Preflight) -> None: ...
    def restore_member(self, member: CheckpointMember) -> None: ...
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


class HostEffects:
    """Exact host effects.  Tests replace this object; source tests never call it."""

    def __init__(self, selection: ReleaseSelection) -> None:
        self._builder = None
        self._selection = selection

    def _load_release(self) -> tuple[Path, Mapping[str, object], bytes, bytes]:
        release_root = Path(__file__).resolve().parent
        _require(release_root.parent == RELEASES_ROOT and _DIGEST.fullmatch(release_root.name) is not None, "release_path_rejected")
        external_document = _external_release_document(release_root, self._selection)
        builder = _load_module("_phase_f_cutover_release_builder", release_root / BUILDER_MEMBER)
        self._builder = builder
        authority = builder.verified_controller_authority(RELEASES_ROOT, release_root.name)
        source = authority.get("source")
        _require(
            type(source) is dict
            and source.get("deploy_parent") == EXPECTED_DEPLOY_PARENT
            and source.get("deploy_commit") == self._selection.deploy_commit
            and source.get("deploy_tree") == self._selection.deploy_tree
            and external_document.get("fixed_product_authority") == authority,
            "source_authority_rejected",
        )
        expected = builder.expected_controller_authority(RELEASES_ROOT, release_root.name)
        _require(builder.verify_release(RELEASES_ROOT, release_root.name, expected), "release_verification_rejected")
        old_expected = builder.expected_controller_authority(RELEASES_ROOT, OLD_CONTROLLER_RELEASE)
        _require(builder.verify_release(RELEASES_ROOT, OLD_CONTROLLER_RELEASE, old_expected), "old_release_verification_rejected")
        new_unit = _render_unit(
            release_root,
            expected,
            guard=True,
            selection=self._selection,
        )
        old_unit = _render_unit(RELEASES_ROOT / OLD_CONTROLLER_RELEASE, old_expected, guard=False)
        _require(sha256(old_unit).hexdigest() == OLD_UNIT_SHA256, "old_unit_authority_rejected")
        return release_root, authority, new_unit, old_unit

    def _checkpoint(self) -> tuple[CheckpointMember, ...]:
        root = CHECKPOINT_ROOT
        metadata = root.lstat()
        _require(stat.S_ISDIR(metadata.st_mode) and not root.is_symlink() and stat.S_IMODE(metadata.st_mode) == 0o700 and metadata.st_uid == 0, "checkpoint_root_rejected")
        payload = _read_regular(root / "MANIFEST.json", mode=0o400, uid=0)
        _require(sha256(payload).hexdigest() == CHECKPOINT_MANIFEST_SHA256 and payload.endswith(b"\n") and b"\r" not in payload, "checkpoint_manifest_rejected")
        try:
            document = json.loads(payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CutoverRejected("checkpoint_manifest_rejected") from exc
        fence = document.get("attempt_fence")
        _require(
            document.get("schema") == CHECKPOINT_SCHEMA
            and document.get("checkpoint_sha256") == root.name
            and document.get("rollback_only") is True
            and document.get("target_truth_from_checkpoint") is False
            and type(fence) is dict
            and fence.get("attempt5_immutable") is True
            and fence.get("attempt6_created") is False
            and fence.get("attempt7_allowed") is False
            and fence.get("one_shot") is True,
            "checkpoint_contract_rejected",
        )
        rows = document.get("members")
        order = document.get("member_order")
        _require(type(rows) is list and len(rows) == 7 and order == [row.get("member") for row in rows], "checkpoint_members_rejected")
        result: list[CheckpointMember] = []
        for index, row in enumerate(rows):
            _require(
                type(row) is dict
                and row.get("index") == index
                and row.get("prestate_identity_schema") == FILE_IDENTITY_SCHEMA
                and _DIGEST.fullmatch(str(row.get("prestate_identity_sha256"))) is not None,
                "checkpoint_member_rejected",
            )
            member_path = root / str(row["member"])
            member_payload = _read_regular(member_path, mode=0o400, uid=0)
            _require(len(member_payload) == row.get("size") and sha256(member_payload).hexdigest() == row.get("sha256"), "checkpoint_member_rejected")
            result.append(
                CheckpointMember(
                    path=Path(str(row["path_category"])),
                    payload=member_payload,
                    mode=int(str(row["mode"]), 8),
                    uid=int(row["uid"]),
                    gid=int(row["gid"]),
                    role=str(row["role"]),
                )
            )
        _require(len({item.path for item in result}) == 7 and len({item.role for item in result}) == 7, "checkpoint_members_rejected")
        actual = {item.name for item in root.iterdir()}
        _require(actual == {"MANIFEST.json", *[str(row["member"]) for row in rows]}, "checkpoint_member_set_rejected")
        return tuple(result)

    @staticmethod
    def _service_state(unit: str) -> str:
        return boot.run(["/usr/bin/systemctl", "is-active", unit], check=False)

    def preflight(self, mode: str) -> Preflight:
        release_root, authority, new_unit, old_unit = self._load_release()
        checkpoint = self._checkpoint()
        files = authority.get("files")
        _require(type(files) is dict and set(files) == {item.path.as_posix() for item in checkpoint}, "seven_role_authority_rejected")
        target_matches = []
        old_matches = []
        for member in checkpoint:
            observed = _file_projection(member.path)
            target = files[member.path.as_posix()]
            _require(target.get("role") == member.role, "seven_role_authority_rejected")
            target_matches.append(
                observed == {
                    "gid": target["gid"],
                    "mode": str(target["mode"]),
                    "sha256": target["payload_sha256"],
                    "size": len(base64.b64decode(target["payload_b64"], validate=True)),
                    "uid": target["uid"],
                }
            )
            old_matches.append(
                observed == {
                    "gid": member.gid,
                    "mode": f"{member.mode:04o}",
                    "sha256": sha256(member.payload).hexdigest(),
                    "size": len(member.payload),
                    "uid": member.uid,
                }
            )
        unit_sha = sha256(_read_regular(UNIT_PATH, mode=0o644, uid=0)).hexdigest()
        target = boot.phase_f_container_projection(boot.CONTAINER)
        archive = boot.phase_f_container_projection(ARCHIVE_NAME)
        network = boot.phase_f_network_projection()
        _require(archive is not None and network is not None, "container_topology_rejected")
        expected_target = boot.PhaseFContainerProjection(**_TARGET_CONTAINER)
        expected_archive = boot.PhaseFContainerProjection(**_ARCHIVE_CONTAINER)
        expected_network = boot.PhaseFNetworkProjection(**_NETWORK)
        if mode in {"preflight", "cutover"}:
            _require(all(target_matches) and unit_sha == OLD_UNIT_SHA256, "cutover_file_prestate_rejected")
            _require(target == expected_target and archive == expected_archive and network == expected_network, "cutover_container_prestate_rejected")
            _require(all(self._service_state(unit) in {"inactive", "failed"} for unit in SERVICES), "cutover_service_prestate_rejected")
        elif mode == "rollback":
            _require(all(new or old for new, old in zip(target_matches, old_matches, strict=True)), "rollback_file_prestate_rejected")
            _require(unit_sha in {OLD_UNIT_SHA256, sha256(new_unit).hexdigest()}, "rollback_unit_prestate_rejected")
            _require(
                archive == expected_archive
                and boot._phase_f_same_network_object(expected_network, network)
                and network.member_container_ids
                in {(), (expected_target.container_id,)},
                "rollback_container_prestate_rejected",
            )
            if target is not None:
                _require(
                    boot._phase_f_same_object(
                        expected_target,
                        target,
                        name=boot.CONTAINER,
                        allow_status_change=True,
                        allow_policy_change=True,
                        allow_network_runtime_change=True,
                    ),
                    "rollback_target_identity_rejected",
                )
            else:
                _require(
                    network.member_container_ids == ()
                    and all(self._service_state(unit) in {"inactive", "failed"} for unit in SERVICES),
                    "rollback_missing_target_manual_required",
                )
        else:
            raise CutoverRejected("mode_rejected")
        return Preflight(
            release_root,
            new_unit,
            old_unit,
            authority,
            checkpoint,
            target,
            archive,
            expected_network,
        )

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
        selected = boot.phase_f_set_restart_policy_exact(state.target)
        boot.phase_f_start_container_exact(selected)

    def stop_service(self, unit: str) -> None:
        _require(unit in SERVICES, "service_stop_rejected")
        observed = self._service_state(unit)
        if observed in {"inactive", "failed"}:
            return
        _require(observed in {"active", "activating", "deactivating"}, "service_stop_ambiguous")
        boot.run(["/usr/bin/systemctl", "stop", unit])
        _require(self._service_state(unit) in {"inactive", "failed"}, "service_stop_poststate_rejected")

    def stop_target(self, state: Preflight) -> None:
        observed = boot.phase_f_container_projection(boot.CONTAINER)
        if observed is None:
            return
        boot.phase_f_stop_container_exact(observed, name=boot.CONTAINER)

    def restore_member(self, member: CheckpointMember) -> None:
        _atomic_file(member.path, member.payload, mode=member.mode, uid=member.uid, gid=member.gid)
        _require(
            _file_projection(member.path)
            == {
                "gid": member.gid,
                "mode": f"{member.mode:04o}",
                "sha256": sha256(member.payload).hexdigest(),
                "size": len(member.payload),
                "uid": member.uid,
            },
            "rollback_member_poststate_rejected",
        )

    def restore_old_unit(self, state: Preflight) -> None:
        _atomic_file(UNIT_PATH, state.old_unit, mode=0o644, uid=0, gid=0)
        _require(sha256(_read_regular(UNIT_PATH, mode=0o644, uid=0)).hexdigest() == OLD_UNIT_SHA256, "old_unit_poststate_rejected")

    def restore_old_container(self, state: Preflight) -> None:
        observed = boot.phase_f_container_projection(boot.CONTAINER)
        if observed is not None:
            boot.phase_f_remove_container_exact(observed, expected_network=state.network)
        boot.phase_f_rename_container_exact(state.archive, source_name=ARCHIVE_NAME, target_name=boot.CONTAINER)

    def verify_new_running(self, state: Preflight) -> None:
        _require(sha256(_read_regular(UNIT_PATH, mode=0o644, uid=0)).hexdigest() == sha256(state.new_unit).hexdigest(), "new_unit_convergence_rejected")
        _require(self._service_state(CORE_SERVICE) == "active" and self._service_state(RUNTIME_SOCKET) == "active", "new_service_convergence_rejected")
        target = boot.phase_f_container_projection(boot.CONTAINER)
        _require(target is not None and target.status == "running" and target.health == "healthy", "new_container_convergence_rejected")

    def verify_old_stopped(self, state: Preflight) -> None:
        _require(sha256(_read_regular(UNIT_PATH, mode=0o644, uid=0)).hexdigest() == OLD_UNIT_SHA256, "old_unit_convergence_rejected")
        _require(all(self._service_state(unit) in {"inactive", "failed"} for unit in SERVICES), "old_service_convergence_rejected")
        old = boot.phase_f_container_projection(boot.CONTAINER)
        _require(old is not None and old.container_id == state.archive.container_id and old.status in {"created", "exited"}, "old_container_convergence_rejected")


def execute(mode: str, effects: Effects) -> dict[str, object]:
    """Run one finite mode.  No result is a semantic product-success claim."""

    state = effects.preflight(mode)
    if mode == "preflight":
        return {"mode": mode, "schema": SCHEMA, "status": "PREFLIGHT_ACCEPTED_ZERO_EFFECT"}
    if mode == "cutover":
        boundary = "preflight"
        try:
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
            for member in state.checkpoint:
                boundary = f"restore:{member.role}"
                effects.restore_member(member)
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
        print(
            _canonical(
                {
                    "boundary": exc.boundary,
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
