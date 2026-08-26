#!/usr/bin/env python3
"""One fixed supervised owner for the real Phase-F memory activation.

The sequence is deliberately linear. Fresh resource observations are the only
effect truth. The target-container restart policy is the durable dispatch
fence: policy no is reversible pre-writer state; on-failure:3 means a
supervised start was authorized and no automatic retry or reverse is allowed.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import fcntl
import grp
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Mapping

import p07_owner_private_memory_production_plan as product
import telegram_r5_boot_resume as resume


SCHEMA = "myuna.phase-f.fixed-product-supervised-activation.v1"
CORE_SERVICE = "myuna-core@qq.service"
RUNTIME_SERVICE = "myuna-telegram-owner-runtime-dev.service"
RUNTIME_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
UNIT_PATH = Path("/etc/systemd/system/myuna-telegram-owner-r5-resume.service")
CONTROLLER_RELEASES_ROOT = Path("/opt/myuna/telegram-r5/releases")
DEPLOY_REPOSITORY = Path("/srv/myuna/repos/deploy")
PARENT_MANIFEST_PATH = Path("/etc/myuna-telegram-gateway/p07-d-release-set-v1.json")
PARENT_SELECTOR_PATH = Path("/etc/myuna-telegram-gateway/external-epoch-selector-v2.json")
ACCEPTED_OLD_UNIT_SHA256 = (
    "10c9a9e106c78de12ab5c68bb51a604dfe58e4dd0131f0714b47e5ee25ddeed5"
)
PRE_DISPATCH_POLICY = "no"
DISPATCH_FENCE_POLICY = "on-failure:3"
ATTEMPT5_FAILED_TARGET_USER_EVIDENCE = "1000:1000"
ATTEMPT5_FAILED_TARGET_EFFECT_SHA256 = (
    "cfac33dc9efe7d0c9a44e3b667267827af8d26587b6205fb03047dedb8694985"
)
ATTEMPT5_FAILED_TARGET_TERMINAL_IDENTITY_SHA256 = (
    "58f466509a22426217327f6764c6885c266db2504272db8c359b88e5c3aa1bf4"
)


class MemoryActivationRejected(RuntimeError):
    """A typed fixed-product activation rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise MemoryActivationRejected(code)


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _directory_identity(metadata: os.stat_result) -> str:
    return sha256(
        canonical(
            {
                "dev": metadata.st_dev,
                "gid": metadata.st_gid,
                "ino": metadata.st_ino,
                "mode": stat.S_IMODE(metadata.st_mode),
                "nlink": metadata.st_nlink,
                "uid": metadata.st_uid,
            }
        )
    ).hexdigest()


def _private_root_handle_count(root: Path) -> int:
    """Count foreign descriptors bound to the fixed root without reading content."""

    count = 0
    current_pid = os.getpid()
    try:
        processes = tuple(Path("/proc").iterdir())
    except OSError as exc:
        raise MemoryActivationRejected("fixed_private_handle_scan_rejected") from exc
    prefix = root.as_posix() + "/"
    for process in processes:
        if not process.name.isdecimal() or int(process.name) == current_pid:
            continue
        try:
            descriptors = tuple((process / "fd").iterdir())
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as exc:
            raise MemoryActivationRejected(
                "fixed_private_handle_scan_rejected"
            ) from exc
        except OSError as exc:
            raise MemoryActivationRejected(
                "fixed_private_handle_scan_rejected"
            ) from exc
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError as exc:
                raise MemoryActivationRejected(
                    "fixed_private_handle_scan_rejected"
                ) from exc
            except OSError as exc:
                raise MemoryActivationRejected(
                    "fixed_private_handle_scan_rejected"
                ) from exc
            normalized = target.removesuffix(" (deleted)")
            if normalized == root.as_posix() or normalized.startswith(prefix):
                count += 1
    return count


def _result(
    status: str,
    *,
    plan_sha256: str,
    reason: str,
    writer_boundary: bool,
    callbacks: int,
) -> dict[str, object]:
    return {
        "callbacks": callbacks,
        "plan_sha256": plan_sha256,
        "private_content_read": False,
        "reason": reason,
        "schema": product.RESULT_SCHEMA,
        "status": status,
        "writer_boundary": writer_boundary,
    }


def _command(arguments: tuple[str, ...]) -> str:
    completed = subprocess.run(
        list(arguments),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise MemoryActivationRejected("fixed_effect_command_rejected")
    return completed.stdout.strip()


def _file_observation(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {
            "gid": None,
            "identity": None,
            "kind": "absent",
            "mode": None,
            "payload_b64": None,
            "sha256": None,
            "uid": None,
        }
    except OSError as exc:
        raise MemoryActivationRejected("fixed_file_observation_rejected") from exc
    require(
        not path.is_symlink()
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1,
        "fixed_file_observation_rejected",
    )
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                total += len(chunk)
                require(total <= 1024 * 1024, "fixed_file_observation_rejected")
                chunks.append(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise MemoryActivationRejected("fixed_file_observation_rejected") from exc
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_ctime_ns,
        before.st_mtime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_ctime_ns,
        after.st_mtime_ns,
    )
    require(before_identity == after_identity, "fixed_file_observation_rejected")
    named = path.lstat()
    require(
        (named.st_dev, named.st_ino, named.st_mode, named.st_nlink, named.st_size)
        == (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_size),
        "fixed_file_observation_rejected",
    )
    identity = sha256(
        canonical(
            {
                "dev": after.st_dev,
                "gid": after.st_gid,
                "ino": after.st_ino,
                "mode": stat.S_IMODE(after.st_mode),
                "size": after.st_size,
                "uid": after.st_uid,
            }
        )
    ).hexdigest()
    return {
        "gid": after.st_gid,
        "identity": identity,
        "kind": "regular",
        "mode": f"0{stat.S_IMODE(after.st_mode):03o}",
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "sha256": sha256(payload).hexdigest(),
        "uid": after.st_uid,
    }


def _tree_member_set(
    root: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    directory_mode: int,
    file_mode: int,
) -> str:
    rows: list[dict[str, object]] = []
    for selected in sorted((root, *root.rglob("*")), key=lambda item: item.as_posix()):
        metadata = selected.lstat()
        require(not stat.S_ISLNK(metadata.st_mode), "fixed_release_member_rejected")
        relative = "." if selected == root else selected.relative_to(root).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            descriptor = os.open(
                selected,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                opened = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            require(
                opened.st_dev == metadata.st_dev
                and opened.st_ino == metadata.st_ino
                and metadata.st_uid == expected_uid
                and metadata.st_gid == expected_gid
                and stat.S_IMODE(metadata.st_mode) == directory_mode,
                "fixed_release_member_rejected",
            )
            rows.append(
                {
                    "kind": "directory",
                    "mode": f"0{stat.S_IMODE(metadata.st_mode):03o}",
                    "path": relative,
                }
            )
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            descriptor = os.open(
                selected,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                opened = os.fstat(descriptor)
                require(
                    opened.st_dev == metadata.st_dev
                    and opened.st_ino == metadata.st_ino
                    and metadata.st_uid == expected_uid
                    and metadata.st_gid == expected_gid
                    and stat.S_IMODE(metadata.st_mode) == file_mode,
                    "fixed_release_member_rejected",
                )
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                payload = b"".join(chunks)
                after = os.fstat(descriptor)
                require(
                    after.st_dev == opened.st_dev
                    and after.st_ino == opened.st_ino
                    and after.st_size == opened.st_size == len(payload)
                    and after.st_mtime_ns == opened.st_mtime_ns
                    and after.st_ctime_ns == opened.st_ctime_ns,
                    "fixed_release_member_rejected",
                )
            finally:
                os.close(descriptor)
            rows.append(
                {
                    "kind": "file",
                    "mode": f"0{stat.S_IMODE(metadata.st_mode):03o}",
                    "path": relative,
                    "sha256": sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
        else:
            raise MemoryActivationRejected("fixed_release_member_rejected")
    return sha256(product.canonical(rows)).hexdigest()


def _release_observation(release: Mapping[str, object]) -> dict[str, object]:
    root = str(release["root"])
    digest = str(release["digest"])
    member_set_sha256 = str(release["member_set_sha256"])
    selected = Path(root) / digest
    try:
        metadata = selected.lstat()
    except FileNotFoundError:
        return {"identity": None, "state": "OLD"}
    except OSError as exc:
        raise MemoryActivationRejected("fixed_release_observation_rejected") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return {"identity": None, "state": "THIRD_STATE"}
    parts = str(release["bundle_prefix"]).split("/")
    require(
        len(parts) >= 4 and parts[:2] == ["staging", "releases"],
        "fixed_release_observation_rejected",
    )
    expected_uid, expected_gid = _release_owner(parts[2])
    actual_member_set = _tree_member_set(
        selected,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        directory_mode=int(str(release["directory_mode"]), 8),
        file_mode=int(str(release["file_mode"]), 8),
    )
    try:
        after = selected.lstat()
    except OSError as exc:
        raise MemoryActivationRejected("fixed_release_observation_rejected") from exc
    require(
        not stat.S_ISLNK(after.st_mode)
        and stat.S_ISDIR(after.st_mode)
        and after.st_dev == metadata.st_dev
        and after.st_ino == metadata.st_ino
        and after.st_uid == metadata.st_uid
        and after.st_gid == metadata.st_gid
        and stat.S_IMODE(after.st_mode) == stat.S_IMODE(metadata.st_mode)
        and after.st_nlink == metadata.st_nlink,
        "fixed_release_observation_rejected",
    )
    if actual_member_set != member_set_sha256:
        return {"identity": actual_member_set, "state": "THIRD_STATE"}
    return {
        "identity": actual_member_set,
        "state": "TARGET",
    }


def _image_observation(image: Mapping[str, object]) -> dict[str, object]:
    reference = str(image["reference"])
    member_set_sha256 = str(image["member_set_sha256"])
    receipt = image["receipt"]
    assert isinstance(receipt, Mapping)
    try:
        projection = _command(
            (
                "/usr/bin/docker",
                "image",
                "inspect",
                reference,
                "--format",
                "{{json .}}",
            )
        )
    except MemoryActivationRejected:
        return {"identity": None, "state": "OLD"}
    try:
        document = json.loads(projection)
    except json.JSONDecodeError:
        return {"identity": None, "state": "THIRD_STATE"}
    repo_digests = document.get("RepoDigests") if type(document) is dict else None
    rootfs = document.get("RootFS") if type(document) is dict else None
    platform = receipt.get("platform")
    expected_diff_ids = [row.get("diff_id") for row in receipt.get("layers", [])]
    if (
        type(repo_digests) is not list
        or reference not in repo_digests
        or document.get("Id") != receipt.get("image_id")
        or type(platform) is not dict
        or document.get("Architecture") != platform.get("architecture")
        or document.get("Os") != platform.get("os")
        or type(rootfs) is not dict
        or rootfs.get("Layers") != expected_diff_ids
        or product.image_member_set_sha256(receipt) != member_set_sha256
    ):
        return {
            "identity": sha256(product.canonical(document)).hexdigest(),
            "state": "THIRD_STATE",
        }
    return {"identity": member_set_sha256, "state": "TARGET"}


def _parent_observation() -> dict[str, object]:
    manifest = _file_observation(PARENT_MANIFEST_PATH)
    selector = _file_observation(PARENT_SELECTOR_PATH)
    if manifest["kind"] == selector["kind"] == "absent":
        return {"manifest_sha256": None, "selector_sha256": None, "state": "OLD"}
    if (
        manifest["kind"] == selector["kind"] == "regular"
        and manifest["sha256"] == product.PARENT_MANIFEST_SHA256
        and selector["sha256"] == product.PARENT_SELECTOR_SHA256
    ):
        return {
            "manifest_sha256": product.PARENT_MANIFEST_SHA256,
            "selector_sha256": product.PARENT_SELECTOR_SHA256,
            "state": "TARGET",
        }
    return {
        "manifest_sha256": manifest["sha256"],
        "selector_sha256": selector["sha256"],
        "state": "THIRD_STATE",
    }


def _service_observation(unit: str) -> dict[str, object]:
    output = _command(
        (
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=ActiveState,FragmentPath,InvocationID",
        )
    ).splitlines()
    expected = {"ActiveState", "FragmentPath", "InvocationID"}
    properties: dict[str, str] = {}
    for row in output:
        key, separator, value = row.partition("=")
        require(
            separator == "="
            and key in expected
            and key not in properties,
            "fixed_service_observation_rejected",
        )
        properties[key] = value
    require(set(properties) == expected, "fixed_service_observation_rejected")
    active_state = properties["ActiveState"]
    fragment = properties["FragmentPath"]
    invocation = properties["InvocationID"]
    require(
        active_state in {"active", "inactive", "failed"}
        and fragment.startswith("/")
        and (active_state != "active" or bool(invocation)),
        "fixed_service_observation_rejected",
    )
    return {
        "active": active_state == "active",
        "identity": sha256(canonical([unit, fragment])).hexdigest(),
    }


def _network_observation() -> dict[str, object]:
    projection = resume.phase_f_network_projection()
    require(projection is not None, "fixed_network_observation_rejected")
    assert projection is not None
    return {
        "identity": projection.network_id,
        "member_ids": list(projection.member_container_ids),
        "name": projection.name,
        "projection_sha256": resume.phase_f_network_identity_sha256(projection),
        "state": (
            "TARGET"
            if projection.name == product.NETWORK_NAME
            and projection.driver == "bridge"
            and not projection.internal
            and not projection.ingress
            else "THIRD_STATE"
        ),
    }


def _container_or_absent(name: str) -> dict[str, object]:
    projection = resume.phase_f_container_projection(name)
    if projection is None:
        return {
            "projection_sha256": None,
            "active": False,
            "identity": None,
            "name": name,
            "policy": "absent",
            "state": "OLD",
        }
    policy = (
        f"{projection.restart_policy}:{projection.restart_maximum_retry_count}"
        if projection.restart_policy == "on-failure"
        else projection.restart_policy
    )
    return {
        "active": projection.status == "running",
        "command_digest": projection.command_digest,
        "health": projection.health,
        "host_config_digest": projection.host_config_digest,
        "identity": projection.container_id,
        "image": projection.image,
        "mounts_digest": projection.mounts_digest,
        "name": projection.name,
        "network_names": list(projection.network_names),
        "networks_digest": projection.networks_digest,
        "plan_digest": projection.plan_digest,
        "policy": policy,
        "project": projection.project,
        "projection_sha256": resume.phase_f_container_identity_sha256(projection),
        "service": projection.service,
        "state": "TARGET",
        "target_config_digest": projection.target_config_digest,
        "user": projection.user,
    }


def _old_container_role_observation(name: str) -> dict[str, object]:
    row = _container_or_absent(name)
    if row["identity"] is None:
        return {
            "active": False,
            "identity": None,
            "name": name,
            "policy": "absent",
            "state": "THIRD_STATE",
        }
    configuration_sha256 = product.digest(
        "phase_f_attempt5_old_container_configuration",
        {
            key: row.get(key)
            for key in (
                "command_digest",
                "host_config_digest",
                "image",
                "mounts_digest",
                "network_names",
                "networks_digest",
                "plan_digest",
                "policy",
                "project",
                "service",
                "target_config_digest",
                "user",
            )
        },
    )
    exact_projection = (
        row["identity"] == product.ATTEMPT5_OLD_CONTAINER_ID
        and row["name"] == name
        and row.get("network_names") == [product.NETWORK_NAME]
        and row.get("networks_digest")
        == product.ATTEMPT5_OLD_CONTAINER_NETWORKS_SHA256
        and configuration_sha256
        == product.ATTEMPT5_OLD_CONTAINER_CONFIGURATION_SHA256
    )
    return {
        "active": row["active"],
        "identity": row["identity"],
        "name": row["name"],
        "policy": row["policy"],
        "projection_sha256": row.get("projection_sha256"),
        "state": "TARGET" if exact_projection else "THIRD_STATE",
    }


def _old_container_observation() -> dict[str, object]:
    phase = product._selected_root_phase_authority()
    if phase["phase"] == "POST_WRITER":
        rollback = _container_or_absent(
            product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_NAME
        )
        if rollback["identity"] is not None:
            exact_rollback = (
                rollback["identity"]
                == product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_CONTAINER_ID
                and rollback["name"]
                == product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_NAME
                and rollback.get("projection_sha256")
                == product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_PROJECTION_SHA256
                and not rollback["active"]
                and rollback["policy"] == PRE_DISPATCH_POLICY
            )
            return {
                "active": rollback["active"],
                "identity": rollback["identity"],
                "name": rollback["name"],
                "policy": rollback["policy"],
                "state": "TARGET" if exact_rollback else "THIRD_STATE",
            }
    row = _old_container_role_observation(product.CONTAINER_NAME)
    row.pop("projection_sha256", None)
    return row


def _target_container_observation(
    authority: Mapping[str, object],
) -> dict[str, object]:
    image = authority["image"]
    files = authority["files"]
    assert isinstance(image, Mapping)
    assert isinstance(files, Mapping)
    target_config = str(
        files["/etc/myuna-telegram-gateway/r5-resume-v1.json"][
            "payload_sha256"
        ]
    )
    candidate_names: set[str] = set()
    for selector in (
        f"label=myuna.phase-f.target-config-digest={target_config}",
        f"ancestor={image['reference']}",
    ):
        output = _command(
            (
                "/usr/bin/docker",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                selector,
                "--format",
                "{{.Names}}",
            )
        )
        names = output.splitlines() if output else []
        require(
            len(names) == len(set(names))
            and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) for name in names),
            "fixed_target_role_inventory_rejected",
        )
        candidate_names.update(names)
    allowed_names = {
        product.CONTAINER_NAME,
        product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_NAME,
    }
    if candidate_names - allowed_names:
        return {
            "active": False,
            "identity": None,
            "name": product.CONTAINER_NAME,
            "policy": "ambiguous",
            "state": "THIRD_STATE",
        }
    if product.CONTAINER_NAME not in candidate_names:
        return {
            "active": False,
            "identity": None,
            "name": product.CONTAINER_NAME,
            "policy": "absent",
            "state": "OLD",
        }
    candidate_name = product.CONTAINER_NAME
    row = _container_or_absent(candidate_name)
    rollback = _container_or_absent(
        product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_NAME
    )
    exact_rollback = (
        candidate_names == allowed_names
        and rollback["identity"]
        == product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_CONTAINER_ID
        and rollback["name"] == product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_NAME
        and rollback.get("projection_sha256")
        == product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_PROJECTION_SHA256
        and not rollback["active"]
        and rollback["policy"] == PRE_DISPATCH_POLICY
    )
    exact_target = (
        row["identity"] == product.ATTEMPT5_DURABILITY_TARGET_CONTAINER_ID
        and row["name"] == product.CONTAINER_NAME
        and row.get("projection_sha256")
        == product.ATTEMPT5_DURABILITY_TARGET_PROJECTION_SHA256
        and row.get("image") == image["reference"]
        and row.get("target_config_digest") == target_config
        and bool(row.get("plan_digest"))
        and row.get("project") == resume.COMPOSE_PROJECT
        and row.get("service") == resume.COMPOSE_SERVICE
        and row.get("user") == product.TARGET_USER
        and row.get("network_names") == [product.NETWORK_NAME]
        and exact_rollback
    )
    return {
        "active": row["active"],
        "identity": row["identity"],
        "name": candidate_name,
        "policy": row["policy"],
        "state": "TARGET" if exact_target else "THIRD_STATE",
    }


def _archive_observation(name: str) -> dict[str, object]:
    row = _old_container_role_observation(name)
    if row["identity"] is None:
        return {
            "identity": None,
            "name": name,
            "projection_sha256": None,
            "state": "OLD",
        }
    if row["state"] == "TARGET":
        return {
            "identity": row["identity"],
            "name": name,
            "projection_sha256": row.get("projection_sha256"),
            "state": "TARGET",
        }
    return {
        "identity": row["identity"],
        "name": name,
        "projection_sha256": row.get("projection_sha256"),
        "state": "THIRD_STATE",
    }


def _archive_root_observation(
    authority: Mapping[str, object],
    *,
    parent_state: Mapping[str, object] | None = None,
    network_state: Mapping[str, object] | None = None,
) -> dict[str, object]:
    phase = product._selected_root_phase_authority()
    require(
        set(phase)
        == {
            "archive_parent_identity",
            "attempt",
            "attempt6_absent",
            "attempt_consumed",
            "domain",
            "network_projection_sha256",
            "phase",
            "product_authority_sha256",
            "product_controller_release",
            "product_plan_sha256",
            "schema",
            "selected_root_identity",
            "version",
            "writer_bound",
        },
        "fixed_selected_root_phase_authority_rejected",
    )
    if parent_state is None:
        parent_state = _parent_observation()
    if network_state is None:
        network_state = _network_observation()
    pre_writer_authority = (
        phase["schema"]
        == "myuna.phase-f.post-writer-selected-root-authority.v1"
        and phase["domain"]
        == "phase-f.fixed-product-supervised-activation"
        and phase["version"] == 1
        and phase["phase"] == "PRE_WRITER"
        and phase["attempt"] == 5
        and phase["attempt_consumed"] is False
        and phase["writer_bound"] is False
        and phase["attempt6_absent"] is True
    )
    post_writer_authority = (
        phase["schema"]
        == "myuna.phase-f.post-writer-selected-root-authority.v1"
        and phase["domain"]
        == "phase-f.fixed-product-supervised-activation"
        and phase["version"] == 1
        and phase["phase"] == "POST_WRITER"
        and phase["attempt"] == 5
        and phase["attempt_consumed"] is True
        and phase["writer_bound"] is True
        and phase["attempt6_absent"] is True
        and phase["product_authority_sha256"]
        == product.ATTEMPT5_PRODUCT_AUTHORITY_SHA256
        and phase["product_controller_release"]
        == product.ATTEMPT5_PRODUCT_CONTROLLER_RELEASE
        and phase["product_plan_sha256"]
        == product.ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256
        and phase["archive_parent_identity"]
        == product.ATTEMPT5_ARCHIVE_PARENT_IDENTITY
        and phase["selected_root_identity"]
        == product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY
        and parent_state.get("state") == "TARGET"
        and parent_state.get("manifest_sha256")
        == product.PARENT_MANIFEST_SHA256
        and parent_state.get("selector_sha256")
        == product.PARENT_SELECTOR_SHA256
        and network_state.get("state") == "TARGET"
        and network_state.get("name") == product.NETWORK_NAME
        and network_state.get("projection_sha256")
        == phase["network_projection_sha256"]
    )
    require(
        pre_writer_authority or post_writer_authority,
        "fixed_selected_root_phase_authority_rejected",
    )
    root = Path(product.MEMORY_RUNTIME_ROOT)
    selected = product.selected_memory_runtime(authority)
    selected_name = str(selected["archive_id"])
    rejected = {
        "handle_count": None,
        "identity": None,
        "legacy_identity": None,
        "legacy_name": product.LEGACY_MEMORY_ARCHIVE_ID,
        "path": root.as_posix(),
        "selected_identity": None,
        "selected_name": selected_name,
        "selected_state": "THIRD_STATE",
        "state": "THIRD_STATE",
    }
    try:
        if root.resolve(strict=True) != root:
            return rejected
        parent = os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except FileNotFoundError:
        return rejected
    except OSError as exc:
        raise MemoryActivationRejected("fixed_archive_observation_rejected") from exc
    legacy_descriptor: int | None = None
    selected_descriptor: int | None = None
    try:
        before = os.fstat(parent)
        names = sorted(os.listdir(parent))
        prior_candidates = [
            name
            for name in names
            if name.isascii()
            and sha256(name.encode("ascii")).hexdigest()
            == product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_NAME_SHA256
        ]
        prior_name = ""
        if prior_candidates:
            require(
                len(prior_candidates) == 1,
                "fixed_archive_child_lineage_rejected",
            )
            prior_name = _prior_attempt_archive_child_name()
            require(
                prior_name == prior_candidates[0],
                "fixed_archive_child_lineage_rejected",
            )
        allowed_names = (
            {product.LEGACY_MEMORY_ARCHIVE_ID},
            {product.LEGACY_MEMORY_ARCHIVE_ID, selected_name},
            {product.LEGACY_MEMORY_ARCHIVE_ID, prior_name},
        )
        valid = (
            stat.S_ISDIR(before.st_mode)
            and before.st_uid == product.MEMORY_RUNTIME_UID
            and before.st_gid == product.MEMORY_RUNTIME_GID
            and stat.S_IMODE(before.st_mode) == 0o700
            and _directory_identity(before)
            == product.ATTEMPT5_ARCHIVE_PARENT_IDENTITY
            and set(names) in allowed_names
            and before.st_nlink == 2 + len(names)
        )
        try:
            legacy_descriptor = os.open(
                product.LEGACY_MEMORY_ARCHIVE_ID,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            legacy = os.fstat(legacy_descriptor)
            valid = valid and (
                stat.S_ISDIR(legacy.st_mode)
                and legacy.st_dev == before.st_dev
                and legacy.st_uid == product.MEMORY_RUNTIME_UID
                and legacy.st_gid == product.MEMORY_RUNTIME_GID
                and stat.S_IMODE(legacy.st_mode) == 0o700
                and legacy.st_nlink == 2
                and os.listdir(legacy_descriptor) == []
            )
            legacy_identity = _directory_identity(legacy)
        except OSError:
            valid = False
            legacy_identity = None
        if selected_name in names or prior_name in names:
            selected_entry = selected_name if selected_name in names else prior_name
            try:
                selected_descriptor = os.open(
                    selected_entry,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
                selected_metadata = os.fstat(selected_descriptor)
                selected_contents_valid = (
                    os.listdir(selected_descriptor) == []
                    if selected_entry == prior_name or pre_writer_authority
                    else True
                )
                selected_valid = (
                    stat.S_ISDIR(selected_metadata.st_mode)
                    and selected_metadata.st_dev == before.st_dev
                    and selected_metadata.st_uid == product.MEMORY_RUNTIME_UID
                    and selected_metadata.st_gid == product.MEMORY_RUNTIME_GID
                    and stat.S_IMODE(selected_metadata.st_mode) == 0o700
                    and selected_metadata.st_nlink == 2
                    and selected_contents_valid
                )
                selected_identity = _directory_identity(selected_metadata)
                if selected_entry == prior_name:
                    old = _old_container_observation()
                    target = _target_container_observation(authority)
                    selected_valid = selected_valid and (
                        selected_identity
                        == product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY
                        and old["identity"] == product.ATTEMPT5_OLD_CONTAINER_ID
                        and old["state"] == "TARGET"
                        and not old["active"]
                        and target["state"] == "OLD"
                        and target["identity"] is None
                        and product.TRANSITIONAL_ATTEMPT_UNCONSUMED is False
                        and product.TRANSITIONAL_WRITER_BOUNDARY is False
                    )
                    selected_state = "OLD" if selected_valid else "THIRD_STATE"
                else:
                    selected_valid = selected_valid and (
                        selected_identity
                        == product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY
                    )
                    selected_state = "TARGET" if selected_valid else "THIRD_STATE"
                    os.fsync(parent)
                valid = valid and selected_valid
            except OSError:
                selected_identity = None
                selected_state = "THIRD_STATE"
                valid = False
        else:
            selected_identity = None
            selected_state = "OLD"
        handle_count = _private_root_handle_count(root)
        after = os.fstat(parent)
        valid = valid and (
            (before.st_dev, before.st_ino, before.st_mode, before.st_nlink)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_nlink)
            and sorted(os.listdir(parent)) == names
            and handle_count == 0
        )
        return {
            "handle_count": handle_count,
            "identity": _directory_identity(after),
            "legacy_identity": legacy_identity,
            "legacy_name": product.LEGACY_MEMORY_ARCHIVE_ID,
            "path": root.as_posix(),
            "selected_identity": selected_identity,
            "selected_name": selected_name,
            "selected_state": selected_state,
            "state": "TARGET" if valid else "THIRD_STATE",
        }
    finally:
        if selected_descriptor is not None:
            os.close(selected_descriptor)
        if legacy_descriptor is not None:
            os.close(legacy_descriptor)
        os.close(parent)


def _create_selected_runtime_root(
    authority: Mapping[str, object],
    captured: Mapping[str, object],
) -> str | None:
    if captured["selected_state"] == "TARGET":
        return None
    require(
        captured["state"] == "TARGET"
        and captured["selected_state"] == "OLD"
        and captured["handle_count"] == 0,
        "fixed_archive_create_prestate_rejected",
    )
    root = Path(product.MEMORY_RUNTIME_ROOT)
    selected = product.selected_memory_runtime(authority)
    parent = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    created = False
    try:
        require(
            _directory_identity(os.fstat(parent)) == captured["identity"],
            "fixed_archive_create_prestate_drifted",
        )
        os.mkdir(str(selected["archive_id"]), 0o700, dir_fd=parent)
        created = True
        child = os.open(
            str(selected["archive_id"]),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        try:
            os.fchown(child, int(selected["expected_uid"]), int(selected["expected_gid"]))
            os.fchmod(child, 0o700)
            os.fsync(child)
            identity = _directory_identity(os.fstat(child))
        finally:
            os.close(child)
        os.fsync(parent)
    except Exception:
        if created:
            try:
                os.rmdir(str(selected["archive_id"]), dir_fd=parent)
                os.fsync(parent)
            except OSError as exc:
                raise MemoryActivationRejected(
                    "fixed_archive_create_ambiguous"
                ) from exc
        raise
    finally:
        os.close(parent)
    fresh = _archive_root_observation(authority)
    require(
        fresh["state"] == "TARGET"
        and fresh["selected_state"] == "TARGET"
        and fresh["selected_identity"] == identity
        and fresh["handle_count"] == 0,
        "fixed_archive_create_poststate_rejected",
    )
    return identity


def _remove_created_runtime_root(
    authority: Mapping[str, object],
    identity: str,
) -> None:
    before = _archive_root_observation(authority)
    require(
        before["state"] == "TARGET"
        and before["selected_state"] == "TARGET"
        and before["selected_identity"] == identity
        and before["handle_count"] == 0
        and not _service_observation(RUNTIME_SERVICE)["active"],
        "fixed_reverse_archive_drifted",
    )
    root = Path(product.MEMORY_RUNTIME_ROOT)
    selected = product.selected_memory_runtime(authority)
    parent = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    child = None
    try:
        require(
            _directory_identity(os.fstat(parent)) == before["identity"],
            "fixed_reverse_archive_drifted",
        )
        child = os.open(
            str(selected["archive_id"]),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        require(
            _directory_identity(os.fstat(child)) == identity
            and os.listdir(child) == [],
            "fixed_reverse_archive_drifted",
        )
        os.close(child)
        child = None
        os.rmdir(str(selected["archive_id"]), dir_fd=parent)
        os.fsync(parent)
    finally:
        if child is not None:
            os.close(child)
        os.close(parent)
    after = _archive_root_observation(authority)
    require(
        after["state"] == "TARGET"
        and after["selected_state"] == "OLD"
        and after["legacy_identity"] == before["legacy_identity"]
        and after["handle_count"] == 0,
        "fixed_reverse_archive_poststate_rejected",
    )


def _rename_noreplace(
    parent_descriptor: int,
    old_name: str,
    new_name: str,
) -> None:
    """Perform Linux renameat2(RENAME_NOREPLACE) inside one held parent."""

    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    require(renameat2 is not None, "fixed_archive_converge_platform_rejected")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_descriptor,
        old_name.encode("ascii"),
        parent_descriptor,
        new_name.encode("ascii"),
        1,
    )
    if result != 0:
        failure = ctypes.get_errno()
        raise OSError(failure, os.strerror(failure))


def _converge_archive_child_name(
    authority: Mapping[str, object],
    captured: Mapping[str, object],
) -> str:
    """Rename the exact prior Attempt-5 child to its stable source-owned name."""

    before = _archive_root_observation(authority)
    require(
        before == captured
        and before["state"] == "TARGET"
        and before["selected_state"] == "OLD"
        and before["selected_identity"]
        == product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY
        and before["handle_count"] == 0,
        "fixed_archive_converge_prestate_rejected",
    )
    prior_name = _prior_attempt_archive_child_name()
    stable_name = product.stable_attempt_archive_child_name()
    root = Path(product.MEMORY_RUNTIME_ROOT)
    parent = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    child: int | None = None
    stable: int | None = None
    try:
        parent_before = os.fstat(parent)
        require(
            _directory_identity(parent_before)
            == product.ATTEMPT5_ARCHIVE_PARENT_IDENTITY
            and set(os.listdir(parent))
            == {product.LEGACY_MEMORY_ARCHIVE_ID, prior_name}
            and stable_name not in os.listdir(parent)
            and _private_root_handle_count(root) == 0,
            "fixed_archive_converge_prestate_drifted",
        )
        child = os.open(
            prior_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        child_before = os.fstat(child)
        require(
            _directory_identity(child_before)
            == product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY
            and child_before.st_dev == parent_before.st_dev
            and child_before.st_uid == product.MEMORY_RUNTIME_UID
            and child_before.st_gid == product.MEMORY_RUNTIME_GID
            and stat.S_IMODE(child_before.st_mode) == 0o700
            and child_before.st_nlink == 2
            and os.listdir(child) == [],
            "fixed_archive_converge_prestate_drifted",
        )
        _rename_noreplace(parent, prior_name, stable_name)
        os.fsync(parent)
        stable = os.open(
            stable_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        child_after = os.fstat(stable)
        require(
            (child_after.st_dev, child_after.st_ino)
            == (child_before.st_dev, child_before.st_ino)
            and _directory_identity(child_after)
            == product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY
            and prior_name not in os.listdir(parent),
            "fixed_archive_converge_poststate_rejected",
        )
    finally:
        if stable is not None:
            os.close(stable)
        if child is not None:
            os.close(child)
        os.close(parent)
    fresh = _archive_root_observation(authority)
    require(
        fresh["state"] == "TARGET"
        and fresh["selected_state"] == "TARGET"
        and fresh["selected_identity"]
        == product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY
        and fresh["handle_count"] == 0,
        "fixed_archive_converge_poststate_rejected",
    )
    return str(fresh["selected_identity"])


def observe_fixed_product(authority: Mapping[str, object]) -> dict[str, object]:
    files = {
        item: _file_observation(Path(item))
        for item in sorted(product.FILE_ROLES)
    }
    releases = authority["releases"]
    assert isinstance(releases, Mapping)
    release_observations = {
        key: _release_observation(releases[key])
        for key in ("core", "plugin", "runtime")
    }
    image = authority["image"]
    assert isinstance(image, Mapping)
    release_observations["image"] = _image_observation(image)
    parent_state = _parent_observation()
    network_state = _network_observation()
    archive_root = _archive_root_observation(
        authority,
        parent_state=parent_state,
        network_state=network_state,
    )
    authority_sha = product.digest(
        "phase_f_fixed_source",
        {
            key: authority[key]
            for key in (
                "builder",
                "controller",
                "files",
                "image",
                "parent",
                "releases",
                "schema",
                "source",
            )
        },
    )
    archive_name = product.ARCHIVE_PREFIX + authority_sha[:16]
    return {
        "archive_name": _archive_observation(archive_name),
        "archive_root": archive_root,
        "files": files,
        "network": network_state,
        "old_container": _old_container_observation(),
        "parent": parent_state,
        "releases": release_observations,
        "schema": product.OBSERVATION_SCHEMA,
        "services": {
            "core": _service_observation(CORE_SERVICE),
            "runtime": _service_observation(RUNTIME_SERVICE),
            "socket": _service_observation(RUNTIME_SOCKET),
        },
        "target_container": _target_container_observation(authority),
    }


def _atomic_file(path: Path, payload: bytes, mode: int, uid: int, gid: int) -> None:
    parent = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            os.fchmod(descriptor, mode)
            os.fchown(descriptor, uid, gid)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                require(written > 0, "fixed_file_write_rejected")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        temporary = ""
        os.fsync(parent)
    except OSError as exc:
        raise MemoryActivationRejected("fixed_file_write_rejected") from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        os.close(parent)


def _install_target_file(path: str, row: Mapping[str, object]) -> None:
    payload = base64.b64decode(str(row["payload_b64"]), validate=True)
    _atomic_file(
        Path(path),
        payload,
        int(str(row["mode"]), 8),
        int(row["uid"]),
        int(row["gid"]),
    )


def _remove_target_file(path: str) -> None:
    try:
        Path(path).unlink()
        parent = os.open(
            Path(path).parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError as exc:
        raise MemoryActivationRejected("fixed_file_remove_rejected") from exc


def _stop_service(unit: str) -> None:
    _command(("/usr/bin/systemctl", "stop", unit))


def _start_service(unit: str) -> None:
    _command(("/usr/bin/systemctl", "start", unit))


def _daemon_reload_and_verify() -> None:
    _command(("/usr/bin/systemctl", "daemon-reload"))
    output = _command(
        (
            "/usr/bin/systemctl",
            "show",
            CORE_SERVICE,
            RUNTIME_SERVICE,
            "--property=FragmentPath,DropInPaths,ExecStart",
        )
    )
    require(
        output.count("ExecStart=") >= 2
        and output.count("DropInPaths=") >= 2
        and all(
            path in output
            for path in product.FILE_ROLES
            if path.endswith(".conf")
        ),
        "fixed_unit_reopen_rejected",
    )


def _readiness_observation() -> dict[str, object]:
    return {
        "core": _service_observation(CORE_SERVICE),
        "runtime": _service_observation(RUNTIME_SERVICE),
        "socket": _service_observation(RUNTIME_SOCKET),
    }


def _exact_container_projection(
    name: str,
    identity: str,
    projection_sha256: str | None = None,
) -> resume.PhaseFContainerProjection:
    projection = resume.phase_f_container_projection(name)
    require(
        projection is not None
        and projection.container_id == identity
        and projection.name == name
        and (
            projection_sha256 is None
            or resume.phase_f_container_identity_sha256(projection)
            == projection_sha256
        ),
        "fixed_container_identity_rejected",
    )
    assert projection is not None
    return projection


def _exact_network_projection(
    effect: Mapping[str, object],
) -> resume.PhaseFNetworkProjection:
    projection = resume.phase_f_network_projection()
    require(
        projection is not None
        and projection.name == effect["network_name"]
        and resume.phase_f_network_identity_sha256(projection)
        == effect["network_projection_sha256"],
        "fixed_network_identity_rejected",
    )
    assert projection is not None
    return projection


def _stop_old_container(identity: str) -> None:
    projection = _exact_container_projection(product.CONTAINER_NAME, identity)
    resume.phase_f_stop_container_exact(projection, name=product.CONTAINER_NAME)


def _archive_old_container(identity: str, archive_name: str) -> None:
    projection = _exact_container_projection(product.CONTAINER_NAME, identity)
    resume.phase_f_rename_container_exact(
        projection,
        source_name=product.CONTAINER_NAME,
        target_name=archive_name,
    )


def _restore_old_container(identity: str, archive_name: str) -> None:
    projection = _exact_container_projection(archive_name, identity)
    resume.phase_f_rename_container_exact(
        projection,
        source_name=archive_name,
        target_name=product.CONTAINER_NAME,
    )


def _restore_old_running(identity: str) -> None:
    before = _container_or_absent(product.CONTAINER_NAME)
    require(
        before["identity"] == identity and not before["active"],
        "fixed_reverse_old_container_drifted",
    )
    _command(("/usr/bin/docker", "container", "start", identity))
    after = _container_or_absent(product.CONTAINER_NAME)
    require(
        after["identity"] == identity and after["active"],
        "fixed_reverse_old_container_drifted",
    )


def _target_container_from_plan(plan: Mapping[str, object]) -> resume.PhaseFTargetContainer:
    effect = plan["target_effect"]
    require(isinstance(effect, Mapping), "fixed_target_effect_rejected")
    assert isinstance(effect, Mapping)
    mounts = effect["mounts"]
    require(isinstance(mounts, list), "fixed_target_effect_rejected")
    by_destination = {
        str(row["destination"]): row
        for row in mounts
        if isinstance(row, Mapping)
    }
    require(len(by_destination) == len(mounts), "fixed_target_effect_rejected")
    return resume.PhaseFTargetContainer(
        plan_digest=str(effect["plan_digest"]),
        target_config_digest=str(effect["target_config_digest"]),
        image=str(effect["image"]),
        user=str(effect["user"]),
        channel_root=Path(str(by_destination["/AstrBot/data"]["source"])).parent,
        plugin_root=Path(str(by_destination["/AstrBot/data/plugins/astrbot_plugin_myuna_telegram_gateway"]["source"])),
        signing_secret=Path(str(by_destination["/run/secrets/myuna-telegram-channel-signing-v1"]["source"])),
        runtime_root=Path(str(by_destination["/run/myuna-telegram-gateway"]["source"])),
        media_auth_runtime_root=Path(str(by_destination["/run/myuna-telegram-media-auth"]["source"])),
        archive_name=str(effect["archive_name"]),
        effect=effect,
    )


def _create_target_container(plan: Mapping[str, object]) -> None:
    target = _target_container_from_plan(plan)
    effect = target.effect
    assert isinstance(effect, Mapping)
    network = _exact_network_projection(effect)
    archived = _exact_container_projection(
        str(effect["archive_name"]),
        str(effect["archive_container_id"]),
        str(effect["archive_projection_sha256"]),
    )
    resume.phase_f_create_target_stopped(
        target,
        expected_network=network,
        archived_old=archived,
    )


def _set_target_policy(plan: Mapping[str, object], identity: str, policy: str) -> None:
    require(policy == DISPATCH_FENCE_POLICY, "fixed_policy_request_rejected")
    target = _target_container_from_plan(plan)
    resume._phase_f_require_runtime_compatibility(target)
    projection = _exact_container_projection(product.CONTAINER_NAME, identity)
    resume.phase_f_set_restart_policy_exact(projection)


def _start_target_once(plan: Mapping[str, object], identity: str) -> None:
    target = _target_container_from_plan(plan)
    resume._phase_f_require_runtime_compatibility(target)
    projection = _exact_container_projection(product.CONTAINER_NAME, identity)
    resume.phase_f_start_container_exact(projection)


def _remove_target(identity: str) -> None:
    projection = _exact_container_projection(product.CONTAINER_NAME, identity)
    network = _exact_network_projection()
    resume.phase_f_remove_container_exact(projection, expected_network=network)


def _sealed_bundle_member(relative: str, expected: Mapping[str, object]) -> bytes:
    payload, metadata = resume._release_member(Path(__file__).resolve().parent, relative)
    require(
        stat.S_IMODE(metadata.st_mode) == 0o444
        and len(payload) == expected["size"]
        and sha256(payload).hexdigest() == expected["sha256"],
        "fixed_bundle_member_rejected",
    )
    return payload


def _release_owner(key: str) -> tuple[int, int]:
    group = "myuna" if key == "core" else "myuna-gateway-telegram"
    try:
        return pwd.getpwnam("root").pw_uid, grp.getgrnam(group).gr_gid
    except KeyError as exc:
        raise MemoryActivationRejected("fixed_release_owner_rejected") from exc


def _publish_release(key: str, release: Mapping[str, object]) -> None:
    before = _release_observation(release)
    if before["state"] == "TARGET":
        return
    require(before["state"] == "OLD", "fixed_release_publication_rejected")
    root = Path(str(release["root"]))
    digest = str(release["digest"])
    destination = root / digest
    metadata = root.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode) and not root.is_symlink(),
        "fixed_release_root_rejected",
    )
    uid, gid = _release_owner(key)
    temporary = Path(tempfile.mkdtemp(prefix=f".{digest}.", dir=root))
    try:
        for row in release["members"]:
            relative = str(row["path"])
            payload = _sealed_bundle_member(
                f"{release['bundle_prefix']}/{relative}", row
            )
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            os.chown(target, uid, gid)
            os.chmod(target, 0o440)
            descriptor = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        directories = [temporary, *[item for item in temporary.rglob("*") if item.is_dir()]]
        for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            os.chown(directory, uid, gid)
            descriptor = os.open(
                directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.chmod(directory, 0o550)
        moved: subprocess.CompletedProcess[bytes] | None = None
        publication_error: BaseException | None = None
        try:
            moved = subprocess.run(
                [
                    "/usr/bin/mv",
                    "--no-clobber",
                    "--",
                    temporary.as_posix(),
                    destination.as_posix(),
                ],
                check=False,
                capture_output=True,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            publication_error = exc
        after = _release_observation(release)
        require(after["state"] == "TARGET", "fixed_release_publication_rejected")
        if temporary.exists():
            require(
                publication_error is not None
                or (moved is not None and moved.returncode != 0),
                "fixed_release_publication_rejected",
            )
        else:
            require(
                publication_error is not None
                or (moved is not None and moved.returncode == 0),
                "fixed_release_publication_rejected",
            )
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if temporary.exists():
            for selected in sorted(
                (temporary, *temporary.rglob("*")),
                key=lambda item: len(item.parts),
                reverse=True,
            ):
                if not selected.is_symlink():
                    try:
                        os.chmod(selected, 0o755 if selected.is_dir() else 0o644)
                    except OSError:
                        pass
            shutil.rmtree(temporary, ignore_errors=True)


def _publish_image(image: Mapping[str, object]) -> None:
    before = _image_observation(image)
    if before["state"] == "TARGET":
        return
    require(before["state"] == "OLD", "fixed_image_publication_rejected")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".phase-f-image.",
        dir=CONTROLLER_RELEASES_ROOT,
    )
    temporary = Path(temporary_name)
    digest = sha256()
    total = 0
    try:
        for row in image["archive_members"]:
            payload = _sealed_bundle_member(str(row["path"]), row)
            digest.update(payload)
            total += len(payload)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                require(written > 0, "fixed_image_staging_rejected")
                offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        require(
            total == image["archive_size"]
            and digest.hexdigest() == image["archive_sha256"],
            "fixed_image_staging_rejected",
        )
        try:
            _command(("/usr/bin/docker", "image", "load", "--input", temporary.as_posix()))
        except (MemoryActivationRejected, OSError, subprocess.SubprocessError):
            require(
                _image_observation(image)["state"] == "TARGET",
                "fixed_image_publication_rejected",
            )
        require(
            _image_observation(image)["state"] == "TARGET",
            "fixed_image_publication_rejected",
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _converge_immutable_artifacts(authority: Mapping[str, object]) -> int:
    callbacks = 0
    releases = authority["releases"]
    assert isinstance(releases, Mapping)
    for key in ("core", "plugin", "runtime"):
        state = _release_observation(releases[key])["state"]
        require(state != "THIRD_STATE", "fixed_release_publication_rejected")
        if state == "OLD":
            callbacks += 1
            _publish_release(key, releases[key])
    image = authority["image"]
    assert isinstance(image, Mapping)
    state = _image_observation(image)["state"]
    require(state != "THIRD_STATE", "fixed_image_publication_rejected")
    if state == "OLD":
        callbacks += 1
        _publish_image(image)
    return callbacks


def _manual_reason(plan: Mapping[str, object]) -> str | None:
    observation = plan["observation"]
    assert isinstance(observation, Mapping)
    releases = observation["releases"]
    files = observation["files"]
    assert isinstance(releases, Mapping)
    assert isinstance(files, Mapping)
    for row in releases.values():
        if row["state"] == "THIRD_STATE":
            return "immutable_authority_ambiguous"
    if observation["parent"]["state"] != "TARGET":
        return "parent_authority_not_target"
    for row in files.values():
        if row["state"] == "THIRD_STATE":
            return "file_third_state"
    if observation["network"]["state"] != "TARGET":
        return "network_ambiguous"
    target = observation["target_container"]
    if target["active"] or target["policy"] == DISPATCH_FENCE_POLICY:
        return "writer_boundary_already_crossed_or_armed"
    if observation["archive_root"]["state"] != "TARGET":
        return "private_writer_state_ambiguous"
    for key in ("archive_name", "old_container", "target_container"):
        if observation[key]["state"] == "THIRD_STATE":
            return f"{key}_ambiguous"
    if observation["archive_name"]["state"] == "TARGET":
        return "archive_name_collision"
    return None


def _reverse_pre_writer(
    plan: Mapping[str, object],
    completed: list[str],
) -> None:
    observation = plan["observation"]
    authority = plan["authority"]
    assert isinstance(observation, Mapping)
    assert isinstance(authority, Mapping)
    created_roots = [
        value.removeprefix("selected-root-created:")
        for value in completed
        if value.startswith("selected-root-created:")
    ]
    require(len(created_roots) <= 1, "fixed_reverse_archive_drifted")
    safe_root = _archive_root_observation(authority)
    expected_selected_state = (
        "TARGET"
        if created_roots or observation["archive_root"]["selected_state"] == "TARGET"
        else "OLD"
    )
    require(
        safe_root["state"] == "TARGET"
        and safe_root["selected_state"] == expected_selected_state
        and safe_root["handle_count"] == 0
        and not _service_observation(RUNTIME_SERVICE)["active"],
        "fixed_reverse_archive_drifted",
    )
    target = _container_or_absent(product.CONTAINER_NAME)
    if "target_create_dispatched" in completed:
        if target["identity"] is not None:
            require(
                not target["active"]
                and target["policy"] == PRE_DISPATCH_POLICY,
                "fixed_reverse_target_drifted",
            )
            _remove_target(str(target["identity"]))
    if created_roots:
        _remove_created_runtime_root(authority, created_roots[0])
    old = observation["old_container"]
    if "old_archive_dispatched" in completed:
        archived = _container_or_absent(str(plan["archive_name"]))
        canonical_old = _container_or_absent(product.CONTAINER_NAME)
        if archived["identity"] == old["identity"]:
            require(
                canonical_old["identity"] is None,
                "fixed_reverse_old_container_drifted",
            )
            _restore_old_container(str(old["identity"]), str(plan["archive_name"]))
        else:
            require(
                archived["identity"] is None
                and canonical_old["identity"] == old["identity"],
                "fixed_reverse_old_container_drifted",
            )
    changed_files = [
        value.removeprefix("file-dispatched:")
        for value in completed
        if value.startswith("file-dispatched:")
    ]
    if changed_files:
        for item in reversed(changed_files):
            current = _file_observation(Path(item))
            target_row = authority["files"][item]
            old_row = observation["files"][item]
            if current["sha256"] == target_row["payload_sha256"]:
                if old_row["kind"] == "absent":
                    _remove_target_file(item)
                else:
                    _install_target_file(
                        item,
                        {
                            "gid": old_row["gid"],
                            "mode": old_row["mode"],
                            "payload_b64": old_row["payload_b64"],
                            "uid": old_row["uid"],
                        },
                    )
            else:
                expected_old = {
                    key: old_row[key]
                    for key in (
                        "gid", "identity", "kind", "mode", "payload_b64", "sha256", "uid"
                    )
                }
                require(current == expected_old, "fixed_reverse_file_drifted")
            restored_file = _file_observation(Path(item))
            require(
                all(
                    restored_file[key] == old_row[key]
                    for key in ("gid", "kind", "mode", "payload_b64", "sha256", "uid")
                ),
                "fixed_reverse_file_poststate_rejected",
            )
        _daemon_reload_and_verify()
    for key, unit in (
        ("core", CORE_SERVICE),
        ("socket", RUNTIME_SOCKET),
        ("runtime", RUNTIME_SERVICE),
    ):
        expected = observation["services"][key]["active"]
        current_row = _service_observation(unit)
        require(
            current_row["identity"] == observation["services"][key]["identity"],
            "fixed_reverse_service_drifted",
        )
        current = current_row["active"]
        if expected and not current:
            _start_service(unit)
        elif not expected and current:
            _stop_service(unit)
        restored_service = _service_observation(unit)
        require(
            restored_service["active"] == expected
            and restored_service["identity"]
            == observation["services"][key]["identity"],
            "fixed_reverse_service_poststate_rejected",
        )
    if old["active"]:
        restored = _container_or_absent(product.CONTAINER_NAME)
        require(
            restored["identity"] == old["identity"],
            "fixed_reverse_old_container_drifted",
        )
        _restore_old_running(str(old["identity"]))


def run_fixed_product_activation(
    plan_value: object,
    *,
    supervised_start: bool,
) -> dict[str, object]:
    require(type(supervised_start) is bool, "fixed_supervised_decision_rejected")
    plan = product.validate_fixed_plan(plan_value)
    plan_sha = str(plan["plan_sha256"])
    try:
        fresh_plan = product.build_fixed_plan(
            plan["authority"],
            observe_fixed_product(plan["authority"]),
        )
    except (
        MemoryActivationRejected,
        product.ProductionPlanRejected,
        resume.ResumeRejected,
    ) as exc:
        return _result(
            "SUPERVISED_MANUAL_REQUIRED",
            plan_sha256=plan_sha,
            reason=getattr(exc, "code", "fixed_complete_preflight_unavailable"),
            writer_boundary=False,
            callbacks=0,
        )
    if fresh_plan["plan_sha256"] != plan_sha:
        return _result(
            "SUPERVISED_MANUAL_REQUIRED",
            plan_sha256=plan_sha,
            reason="fixed_complete_preflight_drifted",
            writer_boundary=False,
            callbacks=0,
        )
    reason = _manual_reason(plan)
    if reason is not None:
        return _result(
            "SUPERVISED_MANUAL_REQUIRED",
            plan_sha256=plan_sha,
            reason=reason,
            writer_boundary=reason == "writer_boundary_already_crossed_or_armed",
            callbacks=0,
        )
    callbacks = 0
    completed: list[str] = []
    writer_fence = False
    private_state_ambiguous = False
    observation = plan["observation"]
    authority = plan["authority"]
    assert isinstance(observation, Mapping)
    assert isinstance(authority, Mapping)
    try:
        for key, unit in (
            ("runtime", RUNTIME_SERVICE),
            ("socket", RUNTIME_SOCKET),
            ("core", CORE_SERVICE),
        ):
            captured_service = observation["services"][key]
            fresh_service = _service_observation(unit)
            require(
                fresh_service == captured_service,
                "fixed_service_prestate_drifted",
            )
            if captured_service["active"]:
                callbacks += 1
                _stop_service(unit)
                require(
                    not _service_observation(unit)["active"],
                    "fixed_quiescence_poststate_rejected",
                )
        completed.append("services_quiesced")
        quiesced_root = _archive_root_observation(authority)
        require(
            quiesced_root == observation["archive_root"],
            "fixed_archive_post_quiescence_drifted",
        )
        created_root_identity = _create_selected_runtime_root(
            authority,
            quiesced_root,
        )
        if created_root_identity is not None:
            callbacks += 1
            completed.append("selected-root-created:" + created_root_identity)
        callbacks += _converge_immutable_artifacts(authority)
        require(
            all(
                _release_observation(authority["releases"][key])["state"]
                == "TARGET"
                for key in ("core", "plugin", "runtime")
            )
            and _image_observation(authority["image"])["state"] == "TARGET",
            "fixed_immutable_convergence_drifted",
        )
        old = observation["old_container"]
        if old["identity"] is not None:
            require(
                _old_container_observation() == old
                and _archive_observation(str(plan["archive_name"]))
                == observation["archive_name"],
                "fixed_old_container_prestate_drifted",
            )
            if old["active"]:
                callbacks += 1
                _stop_old_container(str(old["identity"]))
            callbacks += 1
            completed.append("old_archive_dispatched")
            _archive_old_container(str(old["identity"]), str(plan["archive_name"]))
        for item in sorted(product.FILE_ROLES):
            state = observation["files"][item]["state"]
            fresh_before = _file_observation(Path(item))
            captured_file = {
                key: observation["files"][item][key]
                for key in ("gid", "identity", "kind", "mode", "payload_b64", "sha256", "uid")
            }
            require(
                fresh_before == captured_file,
                "fixed_file_prestate_drifted",
            )
            if state == "OLD":
                callbacks += 1
                completed.append("file-dispatched:" + item)
                _install_target_file(item, authority["files"][item])
            fresh = _file_observation(Path(item))
            require(
                fresh["sha256"] == authority["files"][item]["payload_sha256"]
                and fresh["mode"] == authority["files"][item]["mode"]
                and fresh["uid"] == authority["files"][item]["uid"]
                and fresh["gid"] == authority["files"][item]["gid"],
                "fixed_file_target_poststate_rejected",
            )
        callbacks += 1
        _daemon_reload_and_verify()
        target = _container_or_absent(product.CONTAINER_NAME)
        require(
            _network_observation()["identity"] == observation["network"]["identity"],
            "fixed_network_prestate_drifted",
        )
        if target["identity"] is None:
            callbacks += 1
            completed.append("target_create_dispatched")
            _create_target_container(plan)
            target = _container_or_absent(product.CONTAINER_NAME)
        require(
            target["identity"] is not None
            and not target["active"]
            and target["policy"] == PRE_DISPATCH_POLICY,
            "fixed_target_pre_dispatch_rejected",
        )
        for unit in (CORE_SERVICE, RUNTIME_SOCKET):
            before_start = _service_observation(unit)
            if not before_start["active"]:
                callbacks += 1
                _start_service(unit)
                after_start = _service_observation(unit)
                require(
                    after_start["active"]
                    and after_start["identity"] == before_start["identity"],
                    "fixed_service_target_poststate_rejected",
                )
        readiness = _readiness_observation()
        if bool(readiness["runtime"]["active"]):
            private_state_ambiguous = True
            raise MemoryActivationRejected(
                "fixed_writer_boundary_crossed_or_ambiguous"
            )
        require(
            bool(readiness["core"]["active"])
            and bool(readiness["socket"]["active"])
            and not bool(readiness["runtime"]["active"]),
            "fixed_readiness_rejected",
        )
        completed.append("core_and_socket_ready")
        fresh_root = _archive_root_observation(authority)
        expected_selected_identity = (
            created_root_identity
            if created_root_identity is not None
            else observation["archive_root"]["selected_identity"]
        )
        runtime = _service_observation(RUNTIME_SERVICE)
        if not (
            not runtime["active"]
            and fresh_root["state"] == "TARGET"
            and fresh_root["selected_state"] == "TARGET"
            and fresh_root["selected_identity"] == expected_selected_identity
            and fresh_root["handle_count"] == 0
        ):
            private_state_ambiguous = True
            raise MemoryActivationRejected(
                "fixed_writer_boundary_crossed_or_ambiguous"
            )
        if not supervised_start:
            return _result(
                "SUPERVISED_START_REQUIRED",
                plan_sha256=plan_sha,
                reason="explicit_supervised_decision_required",
                writer_boundary=False,
                callbacks=callbacks,
            )
        fresh_network = _network_observation()
        fresh_target = _container_or_absent(product.CONTAINER_NAME)
        require(
            fresh_network["state"] == "TARGET"
            and fresh_network["identity"] == observation["network"]["identity"]
            and fresh_network["member_ids"]
            == sorted(
                [
                    *observation["network"]["member_ids"],
                    str(target["identity"]),
                ]
            )
            and fresh_target == target
            and not fresh_target["active"]
            and fresh_target["policy"] == PRE_DISPATCH_POLICY,
            "fixed_supervised_gate_rejected",
        )
        writer_fence = True
        callbacks += 1
        _set_target_policy(plan, str(target["identity"]), DISPATCH_FENCE_POLICY)
        armed = _container_or_absent(product.CONTAINER_NAME)
        require(
            armed["identity"] == target["identity"]
            and not armed["active"]
            and armed["policy"] == DISPATCH_FENCE_POLICY,
            "fixed_writer_fence_rejected",
        )
        callbacks += 1
        _start_target_once(plan, str(target["identity"]))
    except Exception as exc:
        if writer_fence or private_state_ambiguous:
            return _result(
                "SUPERVISED_MANUAL_REQUIRED",
                plan_sha256=plan_sha,
                reason=(
                    "writer_dispatch_lost_or_failed"
                    if writer_fence
                    else "fixed_writer_boundary_crossed_or_ambiguous"
                ),
                writer_boundary=True,
                callbacks=callbacks,
            )
        if callbacks == 0:
            return _result(
                "SUPERVISED_MANUAL_REQUIRED",
                plan_sha256=plan_sha,
                reason=getattr(exc, "code", "fixed_pre_effect_observation_rejected"),
                writer_boundary=False,
                callbacks=0,
            )
        try:
            _reverse_pre_writer(plan, completed)
        except Exception as rollback_exc:
            raise MemoryActivationRejected(
                "fixed_pre_writer_reverse_unsafe"
            ) from rollback_exc
        if isinstance(exc, MemoryActivationRejected):
            raise
        raise MemoryActivationRejected(
            "fixed_pre_writer_activation_rejected"
        ) from exc
    first = _container_or_absent(product.CONTAINER_NAME)
    second = _container_or_absent(product.CONTAINER_NAME)
    return _result(
        "SUPERVISED_MANUAL_REQUIRED",
        plan_sha256=plan_sha,
        reason=(
            "writer_dispatched_terminal_observation_requires_owner"
            if first == second
            else "writer_terminal_observation_ambiguous"
        ),
        writer_boundary=True,
        callbacks=callbacks,
    )


def load_installed_source_authority() -> dict[str, object]:
    current_root = Path(__file__).resolve().parent
    current = resume.verify_fixed_controller_release(current_root)
    current_release = current.get("release_sha256")
    current_body = {
        key: current[key]
        for key in (
            "builder",
            "controller",
            "files",
            "image",
            "parent",
            "releases",
            "schema",
            "source",
        )
    }
    current_authority = product.validate_source_authority(current_body)
    current_source = current_authority["source"]
    require(
        current_release == current_root.name
        and current_authority["authority_sha256"]
        == current.get("authority_sha256")
        and current_source.get("core_commit") == product.ACCEPTED_CORE_COMMIT
        and current_source.get("core_tree") == product.ACCEPTED_CORE_TREE
        and current_source.get("deploy_parent") == product.ACCEPTED_DEPLOY_PARENT,
        "fixed_logic_controller_authority_rejected",
    )

    frozen_root = (
        CONTROLLER_RELEASES_ROOT / product.ATTEMPT5_PRODUCT_CONTROLLER_RELEASE
    )
    frozen_envelope = _historical_controller_authority(frozen_root)
    require(
        frozen_envelope.get("release_sha256")
        == product.ATTEMPT5_PRODUCT_CONTROLLER_RELEASE,
        "fixed_attempt5_product_authority_rejected",
    )
    frozen = {
        key: frozen_envelope[key]
        for key in (
            "builder",
            "controller",
            "files",
            "image",
            "parent",
            "releases",
            "schema",
            "source",
        )
    }
    authority = product.validate_source_authority(frozen)
    source = authority["source"]
    assert isinstance(source, Mapping)
    require(
        authority["authority_sha256"]
        == product.ATTEMPT5_PRODUCT_AUTHORITY_SHA256
        and (
            source["core_commit"],
            source["core_tree"],
            source["deploy_commit"],
            source["deploy_parent"],
            source["deploy_tree"],
        )
        == (
            product.ATTEMPT5_PRODUCT_CORE_COMMIT,
            product.ATTEMPT5_PRODUCT_CORE_TREE,
            product.ATTEMPT5_PRODUCT_DEPLOY_COMMIT,
            product.ATTEMPT5_PRODUCT_DEPLOY_PARENT,
            product.ATTEMPT5_PRODUCT_DEPLOY_TREE,
        ),
        "fixed_attempt5_product_authority_rejected",
    )
    return authority


def _retired_monolithic_owner_entry(*, supervised_start: bool = False) -> int:
    try:
        lock_descriptor = os.open(
            CONTROLLER_RELEASES_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError:
        print(
            json.dumps(
                {
                    "reason": "fixed_owner_lock_rejected",
                    "schema": SCHEMA,
                    "status": "SUPERVISED_MANUAL_REQUIRED",
                },
                sort_keys=True,
            )
        )
        return 75
    try:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(
                json.dumps(
                    {
                        "reason": "fixed_owner_concurrent",
                        "schema": SCHEMA,
                        "status": "SUPERVISED_MANUAL_REQUIRED",
                    },
                    sort_keys=True,
                )
            )
            return 75
        except OSError:
            print(
                json.dumps(
                    {
                        "reason": "fixed_owner_lock_rejected",
                        "schema": SCHEMA,
                        "status": "SUPERVISED_MANUAL_REQUIRED",
                    },
                    sort_keys=True,
                )
            )
            return 75
        try:
            authority = load_installed_source_authority()
            observation = observe_fixed_product(authority)
            plan = product.build_fixed_plan(authority, observation)
            raise MemoryActivationRejected("fixed_monolithic_owner_retired")
        except (
            MemoryActivationRejected,
            product.ProductionPlanRejected,
            resume.ResumeRejected,
        ) as exc:
            code = getattr(exc, "code", "fixed_product_rejected")
            print(
                json.dumps(
                    {"reason": code, "schema": SCHEMA, "status": "rejected"},
                    sort_keys=True,
                )
            )
            return 1
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return (
            75
            if result["status"]
            in {"SUPERVISED_START_REQUIRED", "SUPERVISED_MANUAL_REQUIRED"}
            else 0
        )
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)


def _content_free_observation_digest(observation: Mapping[str, object]) -> str:
    projected = json.loads(canonical(observation))
    for row in projected["files"].values():
        row.pop("payload_b64", None)
    return product.digest("phase_f_checkpoint_observation", projected)


def _effective_units_state() -> str:
    output = _command(
        (
            "/usr/bin/systemctl",
            "show",
            CORE_SERVICE,
            RUNTIME_SERVICE,
            "--property=FragmentPath,DropInPaths,ExecStart",
        )
    )
    expected = tuple(
        path for path in product.FILE_ROLES if path.endswith(".conf")
    )
    present = tuple(path in output for path in expected)
    if all(present):
        return "TARGET"
    if not any(present):
        return "OLD"
    return "THIRD_STATE"


def _attempt5_failed_target_recovery_projection(
    plan: Mapping[str, object],
) -> resume.PhaseFContainerProjection | None:
    """Admit only the frozen failed Attempt-5 target as recovery evidence."""

    projection = resume.phase_f_container_projection(product.CONTAINER_NAME)
    if projection is None:
        return None
    if (
        resume.phase_f_container_identity_sha256(projection)
        != ATTEMPT5_FAILED_TARGET_TERMINAL_IDENTITY_SHA256
        or projection.user != ATTEMPT5_FAILED_TARGET_USER_EVIDENCE
        or projection.effect_digest != ATTEMPT5_FAILED_TARGET_EFFECT_SHA256
        or projection.status != "exited"
        or projection.health != "unhealthy"
        or projection.restart_policy != "on-failure"
        or projection.restart_maximum_retry_count != 3
    ):
        return None
    target = _target_container_from_plan(plan)
    effect = target.effect
    assert isinstance(effect, Mapping)
    old_host = dict(effect["host"])
    old_host["tmpfs"] = "/tmp:rw,nosuid,nodev,noexec,size=128m,uid=1000,gid=1000"
    old_host["restart"] = {
        "maximum_retry_count": 3,
        "name": "on-failure",
    }
    if (
        projection.command_digest != effect["command_sha256"]
        or projection.effect_environment_digest != effect["environment_sha256"]
        or projection.effect_host_digest
        != resume._phase_f_digest("phase_f_attempt5_target_host_v1", old_host)
        or projection.effect_mounts_digest != effect["mounts_sha256"]
    ):
        return None
    output = _command(
        (
            "/usr/bin/docker",
            "container",
            "inspect",
            "--format",
            "{{json .RestartCount}}\n{{json .State.ExitCode}}\n"
            "{{json .State.OOMKilled}}\n{{json .State.Error}}\n"
            "{{json .HostConfig.GroupAdd}}",
            product.CONTAINER_NAME,
        )
    )
    rows = output.splitlines()
    try:
        facts = tuple(json.loads(row) for row in rows)
    except json.JSONDecodeError as exc:
        raise MemoryActivationRejected("fixed_recovery_state_rejected") from exc
    if facts != (3, 1, False, "", []):
        return None
    socket_output = _command(
        (
            "/usr/bin/systemctl",
            "show",
            RUNTIME_SOCKET,
            "--property=NConnections,NAccepted,NRefused",
        )
    )
    socket_rows: dict[str, int] = {}
    for row in socket_output.splitlines():
        key, separator, value = row.partition("=")
        if not separator or key in socket_rows or not value.isdecimal():
            raise MemoryActivationRejected("fixed_recovery_socket_rejected")
        socket_rows[key] = int(value)
    if socket_rows != {"NConnections": 0, "NAccepted": 0, "NRefused": 0}:
        return None
    old_access = resume._phase_f_runtime_access_projection(
        target,
        probe_uid=1000,
        probe_gid=1000,
    )
    if any(old_access.values()):
        return None
    return projection


def _checkpoint_prefix(plan_value: object) -> str:
    plan = product.validate_fixed_plan(plan_value)
    observation = plan["observation"]
    assert isinstance(observation, Mapping)
    require(
        observation["parent"]["state"] == "TARGET"
        and observation["network"]["state"] == "TARGET"
        and observation["archive_root"]["state"] == "TARGET"
        and observation["archive_root"]["handle_count"] == 0,
        "fixed_checkpoint_common_authority_rejected",
    )
    files = observation["files"]
    releases = observation["releases"]
    services = observation["services"]
    assert isinstance(files, Mapping)
    assert isinstance(releases, Mapping)
    assert isinstance(services, Mapping)
    file_states = tuple(files[path]["state"] for path in sorted(files))
    release_states = tuple(
        releases[key]["state"] for key in ("core", "plugin", "runtime", "image")
    )
    require(
        "THIRD_STATE" not in file_states
        and "THIRD_STATE" not in release_states
        and all(state in {"OLD", "TARGET"} for state in file_states)
        and all(state in {"OLD", "TARGET"} for state in release_states),
        "fixed_checkpoint_third_state_rejected",
    )
    immutable_prefix = product.immutable_subset_prefix(release_states)
    old = observation["old_container"]
    target = observation["target_container"]
    archive = observation["archive_name"]
    root = observation["archive_root"]
    network_members = observation["network"]["member_ids"]
    runtime_active = bool(services["runtime"]["active"])
    socket_active = bool(services["socket"]["active"])
    core_active = bool(services["core"]["active"])
    selected_state = root["selected_state"]
    require(
        selected_state in {"OLD", "TARGET"},
        "fixed_checkpoint_root_rejected",
    )

    durability_roles = (
        target["state"] == "TARGET"
        and target["identity"] == product.ATTEMPT5_DURABILITY_TARGET_CONTAINER_ID
        and target["name"] == product.CONTAINER_NAME
        and target["policy"] == "no"
        and old["state"] == "TARGET"
        and old["identity"]
        == product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_CONTAINER_ID
        and old["name"] == product.ATTEMPT5_SOURCE_COMMAND_ROLLBACK_NAME
        and not old["active"]
        and old["policy"] == "no"
    )
    if durability_roles:
        phase = product._selected_root_phase_authority()
        require(
            phase["attempt"] == product.TRANSITIONAL_INSTALL_ATTEMPT
            and phase["attempt_consumed"] is True
            and phase["writer_bound"] is True
            and phase["attempt6_absent"] is True
            and archive["state"] == "OLD"
            and archive["identity"] is None
            and selected_state == "TARGET"
            and all(state == "TARGET" for state in release_states)
            and all(state == "TARGET" for state in file_states)
            and _effective_units_state(plan) == "TARGET"
            and not runtime_active
            and core_active,
            "fixed_checkpoint_post_writer_authority_rejected",
        )
        expected_members = [target["identity"]] if target["active"] else []
        require(
            network_members == expected_members,
            "fixed_checkpoint_post_writer_network_rejected",
        )
        if target["active"]:
            require(
                socket_active,
                "fixed_checkpoint_post_writer_service_rejected",
            )
            return "POST_WRITER_DURABILITY_TARGET"
        if not socket_active:
            return "POST_WRITER_DURABILITY_SOCKET_REQUIRED"
        return "POST_WRITER_DURABILITY_TARGET_START_REQUIRED"

    if any(state == "OLD" for state in release_states):
        require(
            target["state"] == "OLD"
            and target["identity"] is None
            and not target["active"]
            and target["policy"] == "absent",
            "fixed_checkpoint_immutable_container_rejected",
        )
        service_state = (runtime_active, socket_active, core_active)
        if archive["state"] == "OLD":
            expected_old_members = [old["identity"]] if old["active"] else []
            require(
                old["identity"] is not None
                and old["state"] == "TARGET"
                and all(state == "OLD" for state in file_states)
                and network_members == expected_old_members
                and (
                    old["active"]
                    and service_state
                    in {
                        (True, True, True),
                        (False, True, True),
                        (False, False, True),
                        (False, False, False),
                    }
                    or not old["active"]
                    and service_state == (False, False, False)
                ),
                "fixed_checkpoint_immutable_container_rejected",
            )
        else:
            archived = _old_container_role_observation(str(plan["archive_name"]))
            require(
                archive["state"] == "TARGET"
                and old["identity"] is None
                and archived["state"] == "TARGET"
                and archived["identity"] == archive["identity"]
                and not archived["active"]
                and selected_state == "TARGET"
                and service_state == (False, False, False)
                and network_members == [],
                "fixed_checkpoint_immutable_container_rejected",
            )
        return immutable_prefix

    if target["identity"] is not None:
        if target["state"] == "THIRD_STATE":
            failed = _attempt5_failed_target_recovery_projection(plan)
            archived = _old_container_role_observation(str(plan["archive_name"]))
            require(
                failed is not None
                and failed.container_id == target["identity"]
                and target["name"] == product.CONTAINER_NAME
                and not target["active"]
                and target["policy"] == DISPATCH_FENCE_POLICY
                and old["state"] == "THIRD_STATE"
                and old["identity"] == target["identity"]
                and archive["state"] == "TARGET"
                and archived["identity"] == archive["identity"]
                and archived["state"] == "TARGET"
                and not archived["active"]
                and selected_state == "TARGET"
                and all(state == "TARGET" for state in release_states)
                and all(state == "TARGET" for state in file_states)
                and _effective_units_state() == "TARGET"
                and (runtime_active, socket_active, core_active)
                == (False, True, True)
                and network_members == [],
                "fixed_recovery_terminal_rejected",
            )
            return "POST_WRITER_RECOVERY_REQUIRED"
        archived = _old_container_role_observation(str(plan["archive_name"]))
        require(
            target["state"] == "TARGET"
            and target["name"] == product.CONTAINER_NAME
            and old["state"] == "THIRD_STATE"
            and old["identity"] == target["identity"]
            and archive["state"] == "TARGET"
            and archived["identity"] == archive["identity"]
            and not archived["active"]
            and archived["state"] == "TARGET"
            and selected_state == "TARGET"
            and all(state == "TARGET" for state in release_states)
            and all(state == "TARGET" for state in file_states)
            and _effective_units_state() == "TARGET",
            "fixed_checkpoint_target_prefix_rejected",
        )
        expected_members = [str(target["identity"])] if target["active"] else []
        require(
            network_members == expected_members,
            "fixed_checkpoint_target_network_rejected",
        )
        if target["active"] or target["policy"] == DISPATCH_FENCE_POLICY:
            require(
                core_active and socket_active and not runtime_active,
                "fixed_checkpoint_post_writer_rejected",
            )
            return "POST_WRITER_MANUAL"
        require(
            not target["active"] and target["policy"] == PRE_DISPATCH_POLICY,
            "fixed_checkpoint_target_prefix_rejected",
        )
        service_state = (runtime_active, socket_active, core_active)
        if service_state == (False, False, False):
            return "TARGET_CONTAINER_STOPPED"
        if service_state == (False, False, True):
            return "CORE_SERVICE_TARGET"
        if service_state == (False, True, True):
            return "READY_FOR_SUPERVISED_GATE"
        raise MemoryActivationRejected("fixed_checkpoint_service_order_rejected")

    require(
        target["state"] == "OLD"
        and not target["active"]
        and target["policy"] == "absent",
        "fixed_checkpoint_target_prefix_rejected",
    )
    require(
        all(state == "TARGET" for state in release_states),
        "fixed_checkpoint_release_rejected",
    )
    if archive["state"] == "OLD":
        expected_old_members = [old["identity"]] if old["active"] else []
        require(
            old["identity"] is not None
            and old["state"] == "TARGET"
            and all(state == "OLD" for state in file_states)
            and network_members == expected_old_members,
            "fixed_checkpoint_old_container_rejected",
        )
        service_state = (runtime_active, socket_active, core_active)
        if service_state == (True, True, True):
            require(old["active"], "fixed_checkpoint_old_container_rejected")
            return "IMMUTABLE_TARGET"
        if service_state == (False, True, True):
            require(old["active"], "fixed_checkpoint_old_container_rejected")
            return "RUNTIME_SERVICE_QUIESCED"
        if service_state == (False, False, True):
            require(old["active"], "fixed_checkpoint_old_container_rejected")
            return "RUNTIME_SOCKET_QUIESCED"
        require(
            service_state == (False, False, False),
            "fixed_checkpoint_service_order_rejected",
        )
        if selected_state == "OLD":
            if root["selected_identity"] is not None:
                require(
                    not old["active"]
                    and root["selected_identity"]
                    == product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_IDENTITY,
                    "fixed_checkpoint_archive_child_rejected",
                )
                return "ARCHIVE_CHILD_NAME_CONVERGENCE_REQUIRED"
            require(old["active"], "fixed_checkpoint_old_container_rejected")
            return "CORE_SERVICE_QUIESCED"
        if old["active"]:
            return "SELECTED_ROOT_TARGET"
        return "OLD_CONTAINER_STOPPED"

    archived = _old_container_role_observation(str(plan["archive_name"]))
    require(
        archive["state"] == "TARGET"
        and old["identity"] is None
        and target["state"] == "OLD"
        and target["identity"] is None
        and archived["identity"] == archive["identity"]
        and archived["state"] == "TARGET"
        and not archived["active"]
        and selected_state == "TARGET"
        and (runtime_active, socket_active, core_active) == (False, False, False)
        and network_members == [],
        "fixed_checkpoint_archive_prefix_rejected",
    )
    if any(state == "OLD" for state in file_states):
        return (
            "OLD_CONTAINER_ARCHIVED"
            if all(state == "OLD" for state in file_states)
            else "FILES_PARTIAL"
        )
    unit_state = _effective_units_state()
    require(unit_state != "THIRD_STATE", "fixed_checkpoint_unit_state_rejected")
    return (
        "FILES_AND_UNITS_TARGET" if unit_state == "TARGET" else "FILES_PARTIAL"
    )


def _checkpoint_result(
    plan: Mapping[str, object],
    *,
    status: str,
    reason: str,
    stage: str,
    prefix_before: str,
    prefix_after: str,
    before_observation: Mapping[str, object],
    after_observation: Mapping[str, object],
    callbacks: int,
    local_reverse: str,
    writer_boundary: bool,
) -> dict[str, object]:
    authority = plan["authority"]
    assert isinstance(authority, Mapping)
    return {
        "authority_sha256": authority["authority_sha256"],
        "callbacks": callbacks,
        "local_reverse": local_reverse,
        "next_stage": product.CHECKPOINT_NEXT_STAGE[prefix_after],
        "observation_after_sha256": _content_free_observation_digest(after_observation),
        "observation_before_sha256": _content_free_observation_digest(before_observation),
        "plan_sha256": plan["plan_sha256"],
        "prefix_after": prefix_after,
        "prefix_before": prefix_before,
        "private_content_read": False,
        "reason": reason,
        "schema": product.RESULT_SCHEMA,
        "stage": stage,
        "status": status,
        "writer_boundary": writer_boundary,
    }


def _checkpoint_unestablished_result(
    plan: Mapping[str, object],
    *,
    reason: str,
    stage: str,
    prefix_before: str,
    before_observation: Mapping[str, object],
    callbacks: int,
    local_reverse: str,
    writer_boundary: bool,
) -> dict[str, object]:
    """Return a truthful terminal receipt when the poststate is not authority."""
    authority = plan["authority"]
    assert isinstance(authority, Mapping)
    return {
        "authority_sha256": authority["authority_sha256"],
        "callbacks": callbacks,
        "local_reverse": local_reverse,
        "next_stage": None,
        "observation_before_sha256": _content_free_observation_digest(
            before_observation
        ),
        "plan_sha256": plan["plan_sha256"],
        "prefix_before": prefix_before,
        "private_content_read": False,
        "reason": reason,
        "schema": product.RESULT_SCHEMA,
        "stage": stage,
        "status": "SUPERVISED_MANUAL_REQUIRED",
        "writer_boundary": writer_boundary,
    }


def _fresh_checkpoint_plan(authority: Mapping[str, object]) -> dict[str, object]:
    source = authority.get("source")
    require(
        product.TRANSITIONAL_INSTALL_ATTEMPT == 5
        and product.TRANSITIONAL_ATTEMPT_UNCONSUMED is False
        and product.TRANSITIONAL_WRITER_BOUNDARY is False
        and product.ATTEMPT5_PRODUCT_ENTRY_PLAN_SHA256
        == "bed60d0c4f567e389d0c5aa54b0300944f668c577b70d07ad268c9cec653d21a"
        and authority.get("authority_sha256")
        == product.ATTEMPT5_PRODUCT_AUTHORITY_SHA256
        and type(source) is dict
        and (
            source.get("core_commit"),
            source.get("core_tree"),
            source.get("deploy_commit"),
            source.get("deploy_parent"),
            source.get("deploy_tree"),
        )
        == (
            product.ATTEMPT5_PRODUCT_CORE_COMMIT,
            product.ATTEMPT5_PRODUCT_CORE_TREE,
            product.ATTEMPT5_PRODUCT_DEPLOY_COMMIT,
            product.ATTEMPT5_PRODUCT_DEPLOY_PARENT,
            product.ATTEMPT5_PRODUCT_DEPLOY_TREE,
        ),
        "fixed_attempt5_product_authority_rejected",
    )
    return product.build_fixed_plan(authority, observe_fixed_product(authority))


def _restore_stage_files(
    authority: Mapping[str, object],
    before_files: Mapping[str, object],
    changed: list[str],
    callback_counter: list[int],
) -> None:
    for path in reversed(changed):
        row = before_files[path]
        current = _file_observation(Path(path))
        target = authority["files"][path]
        require(
            current["sha256"] == target["payload_sha256"],
            "fixed_checkpoint_file_reverse_drifted",
        )
        callback_counter[0] += 1
        if row["kind"] == "absent":
            _remove_target_file(path)
        else:
            _install_target_file(path, row)
    if changed:
        callback_counter[0] += 1
        _daemon_reload_and_verify()


def _run_attempt5_stopped_recovery(
    plan: Mapping[str, object],
    *,
    prefix_before: str,
) -> dict[str, object]:
    authority = plan["authority"]
    before_observation = plan["observation"]
    assert isinstance(authority, Mapping)
    assert isinstance(before_observation, Mapping)
    callbacks = 0
    try:
        if prefix_before == "POST_WRITER_RECOVERY_REQUIRED":
            failed = _attempt5_failed_target_recovery_projection(plan)
            require(failed is not None, "fixed_recovery_terminal_rejected")
            callbacks += 1
            _remove_target(failed.container_id)
        else:
            require(
                prefix_before == "FILES_AND_UNITS_TARGET"
                and before_observation["target_container"]["identity"] is None,
                "fixed_recovery_prefix_rejected",
            )
        create_plan = _fresh_checkpoint_plan(authority)
        require(
            _checkpoint_prefix(create_plan) == "FILES_AND_UNITS_TARGET",
            "fixed_recovery_removed_state_rejected",
        )
        callbacks += 1
        _create_target_container(create_plan)
    except Exception as exc:
        try:
            after_plan = _fresh_checkpoint_plan(authority)
            prefix_after = _checkpoint_prefix(after_plan)
            after_observation = after_plan["observation"]
            assert isinstance(after_observation, Mapping)
        except Exception:
            return _checkpoint_unestablished_result(
                plan,
                reason="recovery_poststate_unestablished",
                stage="RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED",
                prefix_before=prefix_before,
                before_observation=before_observation,
                callbacks=callbacks,
                local_reverse="FORBIDDEN_POST_WRITER",
                writer_boundary=True,
            )
        if prefix_after == "TARGET_CONTAINER_STOPPED":
            return _checkpoint_result(
                plan,
                status="SUPERVISED_MANUAL_REQUIRED",
                reason="recovery_lost_return_reobserved_corrected_stopped",
                stage="RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED",
                prefix_before=prefix_before,
                prefix_after=prefix_after,
                before_observation=before_observation,
                after_observation=after_observation,
                callbacks=callbacks,
                local_reverse="FORBIDDEN_POST_WRITER",
                writer_boundary=True,
            )
        if prefix_after in {
            "FILES_AND_UNITS_TARGET",
            "POST_WRITER_RECOVERY_REQUIRED",
        }:
            return _checkpoint_result(
                plan,
                status="SUPERVISED_MANUAL_REQUIRED",
                reason=getattr(exc, "code", "recovery_callback_failed"),
                stage="RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED",
                prefix_before=prefix_before,
                prefix_after=prefix_after,
                before_observation=before_observation,
                after_observation=after_observation,
                callbacks=callbacks,
                local_reverse="FORBIDDEN_POST_WRITER",
                writer_boundary=True,
            )
        return _checkpoint_unestablished_result(
            plan,
            reason="recovery_poststate_ambiguous",
            stage="RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED",
            prefix_before=prefix_before,
            before_observation=before_observation,
            callbacks=callbacks,
            local_reverse="FORBIDDEN_POST_WRITER",
            writer_boundary=True,
        )
    after_plan = _fresh_checkpoint_plan(authority)
    prefix_after = _checkpoint_prefix(after_plan)
    after_observation = after_plan["observation"]
    assert isinstance(after_observation, Mapping)
    require(
        prefix_after == "TARGET_CONTAINER_STOPPED",
        "fixed_recovery_stopped_poststate_rejected",
    )
    return _checkpoint_result(
        plan,
        status="SUPERVISED_MANUAL_REQUIRED",
        reason="corrected_stopped_recovery_verified",
        stage="RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED",
        prefix_before=prefix_before,
        prefix_after=prefix_after,
        before_observation=before_observation,
        after_observation=after_observation,
        callbacks=callbacks,
        local_reverse="FORBIDDEN_POST_WRITER",
        writer_boundary=True,
    )


def run_checkpointed_stage(
    plan_value: object,
    *,
    requested_stage: str | None,
    supervised_start: bool,
) -> dict[str, object]:
    require(type(supervised_start) is bool, "fixed_supervised_decision_rejected")
    plan = product.validate_fixed_plan(plan_value)
    authority = plan["authority"]
    before_observation = plan["observation"]
    assert isinstance(authority, Mapping)
    assert isinstance(before_observation, Mapping)
    prefix_before = _checkpoint_prefix(plan)
    expected_stage = product.CHECKPOINT_NEXT_STAGE[prefix_before]
    if requested_stage is None:
        recovery_prefix = prefix_before in {
            "FILES_AND_UNITS_TARGET",
            "POST_WRITER_RECOVERY_REQUIRED",
            "TARGET_CONTAINER_STOPPED",
            "POST_WRITER_DURABILITY_SOCKET_REQUIRED",
            "POST_WRITER_DURABILITY_TARGET_START_REQUIRED",
            "POST_WRITER_DURABILITY_TARGET",
        }
        return _checkpoint_result(
            plan,
            status=(
                "SUPERVISED_MANUAL_REQUIRED"
                if prefix_before == "POST_WRITER_MANUAL" or recovery_prefix
                else "SUPERVISED_START_REQUIRED"
                if prefix_before == "READY_FOR_SUPERVISED_GATE"
                else "CHECKPOINT_READY"
            ),
            reason=(
                "post_writer_manual_terminal"
                if prefix_before == "POST_WRITER_MANUAL"
                else "corrected_stopped_recovery_terminal"
                if prefix_before == "TARGET_CONTAINER_STOPPED"
                else "exact_stopped_recovery_stage_observed"
                if recovery_prefix
                else "explicit_supervised_decision_required"
                if prefix_before == "READY_FOR_SUPERVISED_GATE"
                else "exact_next_stage_observed"
            ),
            stage="OBSERVE_ONLY",
            prefix_before=prefix_before,
            prefix_after=prefix_before,
            before_observation=before_observation,
            after_observation=before_observation,
            callbacks=0,
            local_reverse="NOT_REQUIRED",
            writer_boundary=prefix_before == "POST_WRITER_MANUAL" or recovery_prefix,
        )
    require(
        requested_stage == expected_stage and requested_stage in product.FIXED_STAGES,
        "fixed_checkpoint_stage_request_rejected",
    )
    require(
        (
            requested_stage
            in {"ARM_AND_START_TARGET_ONCE", "RESUME_ATTEMPT5_TARGET_ONCE"}
        )
        == supervised_start,
        "fixed_supervised_decision_rejected",
    )
    if requested_stage == "RECOVER_ATTEMPT5_FAILED_TARGET_TO_CORRECTED_STOPPED":
        return _run_attempt5_stopped_recovery(
            plan,
            prefix_before=prefix_before,
        )
    immutable_after_states: tuple[str, ...] | None = None
    immutable_stable_projection: str | None = None
    if requested_stage in product.IMMUTABLE_STAGES:
        before_releases = before_observation["releases"]
        assert isinstance(before_releases, Mapping)
        before_states = tuple(
            before_releases[key]["state"] for key in product.IMMUTABLE_ARTIFACTS
        )
        selected_index = product.IMMUTABLE_STAGES.index(requested_stage)
        require(
            before_states[selected_index] == "OLD"
            and all(
                before_states[index] == "TARGET"
                for index in range(selected_index)
            ),
            "fixed_checkpoint_immutable_stage_rejected",
        )
        after_states = list(before_states)
        after_states[selected_index] = "TARGET"
        immutable_after_states = tuple(after_states)
        immutable_stable_projection = canonical(
            {
                key: value
                for key, value in before_observation.items()
                if key != "releases"
            }
        )
        expected_after = product.immutable_subset_prefix(tuple(after_states))
    else:
        expected_after = product.CHECKPOINT_STAGE_TARGET[requested_stage]
        if (
            requested_stage == "START_RUNTIME_SOCKET"
            and prefix_before == "POST_WRITER_DURABILITY_SOCKET_REQUIRED"
        ):
            expected_after = "POST_WRITER_DURABILITY_TARGET_START_REQUIRED"
    callbacks = 0
    changed_files: list[str] = []
    writer_boundary = False
    try:
        if requested_stage in {
            "STAGE_CORE_RELEASE",
            "STAGE_PLUGIN_RELEASE",
            "STAGE_RUNTIME_RELEASE",
        }:
            key = {
                "STAGE_CORE_RELEASE": "core",
                "STAGE_PLUGIN_RELEASE": "plugin",
                "STAGE_RUNTIME_RELEASE": "runtime",
            }[requested_stage]
            callbacks += 1
            _publish_release(key, authority["releases"][key])
        elif requested_stage == "STAGE_DERIVATIVE_IMAGE":
            callbacks += 1
            _publish_image(authority["image"])
        elif requested_stage in {
            "QUIESCE_RUNTIME_SERVICE",
            "QUIESCE_RUNTIME_SOCKET",
            "QUIESCE_CORE_SERVICE",
        }:
            key, unit = {
                "QUIESCE_RUNTIME_SERVICE": ("runtime", RUNTIME_SERVICE),
                "QUIESCE_RUNTIME_SOCKET": ("socket", RUNTIME_SOCKET),
                "QUIESCE_CORE_SERVICE": ("core", CORE_SERVICE),
            }[requested_stage]
            captured = before_observation["services"][key]
            require(
                _service_observation(unit) == captured and captured["active"],
                "fixed_checkpoint_service_prestate_rejected",
            )
            callbacks += 1
            _stop_service(unit)
            after_service = _service_observation(unit)
            require(
                not after_service["active"]
                and after_service["identity"] == captured["identity"],
                "fixed_checkpoint_service_poststate_rejected",
            )
        elif requested_stage == "CREATE_SELECTED_RUNTIME_ROOT":
            callbacks += 1
            created = _create_selected_runtime_root(
                authority, before_observation["archive_root"]
            )
            require(created is not None, "fixed_checkpoint_root_poststate_rejected")
        elif requested_stage == "STOP_EXACT_OLD_CONTAINER":
            identity = str(before_observation["old_container"]["identity"])
            callbacks += 1
            _stop_old_container(identity)
            stopped = _old_container_observation()
            require(
                stopped["identity"] == identity and not stopped["active"],
                "fixed_checkpoint_old_stop_poststate_rejected",
            )
        elif requested_stage == "CONVERGE_ARCHIVE_CHILD_NAME":
            require(
                not before_observation["old_container"]["active"],
                "fixed_archive_converge_prestate_rejected",
            )
            callbacks += 1
            _converge_archive_child_name(authority, before_observation["archive_root"])
        elif requested_stage == "ARCHIVE_EXACT_OLD_CONTAINER":
            identity = str(before_observation["old_container"]["identity"])
            callbacks += 1
            _archive_old_container(identity, str(plan["archive_name"]))
        elif requested_stage == "INSTALL_SEVEN_TARGET_FILES_AND_RELOAD":
            before_files = before_observation["files"]
            assert isinstance(before_files, Mapping)
            for path in sorted(product.FILE_ROLES):
                if before_files[path]["state"] == "OLD":
                    changed_files.append(path)
                    callbacks += 1
                    _install_target_file(path, authority["files"][path])
                    current = _file_observation(Path(path))
                    require(
                        current["sha256"]
                        == authority["files"][path]["payload_sha256"],
                        "fixed_checkpoint_file_poststate_rejected",
                    )
            callbacks += 1
            _daemon_reload_and_verify()
        elif requested_stage == "CREATE_EXACT_STOPPED_TARGET":
            callbacks += 1
            _create_target_container(plan)
        elif requested_stage in {"START_CORE_SERVICE", "START_RUNTIME_SOCKET"}:
            key, unit = (
                ("core", CORE_SERVICE)
                if requested_stage == "START_CORE_SERVICE"
                else ("socket", RUNTIME_SOCKET)
            )
            captured = before_observation["services"][key]
            require(
                _service_observation(unit) == captured and not captured["active"],
                "fixed_checkpoint_service_prestate_rejected",
            )
            callbacks += 1
            _start_service(unit)
            after_service = _service_observation(unit)
            require(
                after_service["active"]
                and after_service["identity"] == captured["identity"],
                "fixed_checkpoint_service_poststate_rejected",
            )
        elif requested_stage == "RESUME_ATTEMPT5_TARGET_ONCE":
            target = before_observation["target_container"]
            require(
                target["state"] == "TARGET"
                and target["identity"]
                == product.ATTEMPT5_DURABILITY_TARGET_CONTAINER_ID
                and target["name"] == product.CONTAINER_NAME
                and not target["active"]
                and target["policy"] == "no",
                "fixed_durability_target_prestate_rejected",
            )
            writer_boundary = True
            callbacks += 1
            _start_target_once(plan, str(target["identity"]))
        else:
            require(
                requested_stage == "ARM_AND_START_TARGET_ONCE",
                "fixed_checkpoint_stage_request_rejected",
            )
            target = before_observation["target_container"]
            writer_boundary = True
            callbacks += 1
            _set_target_policy(plan, str(target["identity"]), DISPATCH_FENCE_POLICY)
            armed = _container_or_absent(product.CONTAINER_NAME)
            require(
                armed["identity"] == target["identity"]
                and not armed["active"]
                and armed["policy"] == DISPATCH_FENCE_POLICY,
                "fixed_writer_fence_rejected",
            )
            callbacks += 1
            _start_target_once(plan, str(target["identity"]))
    except Exception as exc:
        if requested_stage == "RESUME_ATTEMPT5_TARGET_ONCE":
            try:
                after_plan = _fresh_checkpoint_plan(authority)
                prefix_after = _checkpoint_prefix(after_plan)
                after_observation = after_plan["observation"]
            except Exception:
                return _checkpoint_unestablished_result(
                    plan,
                    reason="durability_target_observation_unestablished",
                    stage=requested_stage,
                    prefix_before=prefix_before,
                    before_observation=before_observation,
                    callbacks=callbacks,
                    local_reverse="FORBIDDEN_POST_WRITER",
                    writer_boundary=True,
                )
            if prefix_after == "POST_WRITER_DURABILITY_TARGET":
                return _checkpoint_result(
                    plan,
                    status="SUPERVISED_MANUAL_REQUIRED",
                    reason="durability_lost_return_reobserved_target",
                    stage=requested_stage,
                    prefix_before=prefix_before,
                    prefix_after=prefix_after,
                    before_observation=before_observation,
                    after_observation=after_observation,
                    callbacks=callbacks,
                    local_reverse="FORBIDDEN_POST_WRITER",
                    writer_boundary=True,
                )
            return _checkpoint_unestablished_result(
                plan,
                reason="durability_target_start_failed_no_redispatch",
                stage=requested_stage,
                prefix_before=prefix_before,
                before_observation=before_observation,
                callbacks=callbacks,
                local_reverse="FORBIDDEN_POST_WRITER",
                writer_boundary=True,
            )
        if writer_boundary:
            try:
                after_plan = _fresh_checkpoint_plan(authority)
                prefix_after = _checkpoint_prefix(after_plan)
                after_observation = after_plan["observation"]
                require(
                    prefix_after == "POST_WRITER_MANUAL",
                    "fixed_checkpoint_writer_poststate_unestablished",
                )
            except Exception:
                return _checkpoint_unestablished_result(
                    plan,
                    reason="writer_terminal_observation_unestablished",
                    stage=requested_stage,
                    prefix_before=prefix_before,
                    before_observation=before_observation,
                    callbacks=callbacks,
                    local_reverse="FORBIDDEN_POST_WRITER",
                    writer_boundary=True,
                )
            return _checkpoint_result(
                plan,
                status="SUPERVISED_MANUAL_REQUIRED",
                reason="writer_dispatch_lost_or_failed",
                stage=requested_stage,
                prefix_before=prefix_before,
                prefix_after=prefix_after,
                before_observation=before_observation,
                after_observation=after_observation,
                callbacks=callbacks,
                local_reverse="FORBIDDEN_POST_WRITER",
                writer_boundary=True,
            )
        reverse_counter = [0]
        if requested_stage == "INSTALL_SEVEN_TARGET_FILES_AND_RELOAD" and changed_files:
            try:
                _restore_stage_files(
                    authority,
                    before_observation["files"],
                    changed_files,
                    reverse_counter,
                )
            except Exception:
                callbacks += reverse_counter[0]
                return _checkpoint_unestablished_result(
                    plan,
                    reason="local_reverse_failed_poststate_unestablished",
                    stage=requested_stage,
                    prefix_before=prefix_before,
                    before_observation=before_observation,
                    callbacks=callbacks,
                    local_reverse="FAILED_OR_UNESTABLISHED",
                    writer_boundary=False,
                )
            callbacks += reverse_counter[0]
        try:
            after_plan = _fresh_checkpoint_plan(authority)
            prefix_after = _checkpoint_prefix(after_plan)
            after_observation = after_plan["observation"]
            assert isinstance(after_observation, Mapping)
        except Exception:
            return _checkpoint_unestablished_result(
                plan,
                reason="post_effect_observation_unestablished",
                stage=requested_stage,
                prefix_before=prefix_before,
                before_observation=before_observation,
                callbacks=callbacks,
                local_reverse=(
                    "REVERSE_COMPLETED_POSTSTATE_UNESTABLISHED"
                    if reverse_counter[0]
                    else "NO_AUTOMATIC_REVERSE"
                ),
                writer_boundary=False,
            )
        stage_target_established = prefix_after == expected_after
        if immutable_after_states is not None:
            after_releases = after_observation["releases"]
            assert isinstance(after_releases, Mapping)
            stage_target_established = (
                tuple(
                    after_releases[key]["state"]
                    for key in product.IMMUTABLE_ARTIFACTS
                )
                == immutable_after_states
                and canonical(
                    {
                        key: value
                        for key, value in after_observation.items()
                        if key != "releases"
                    }
                )
                == immutable_stable_projection
            )
        if stage_target_established:
            return _checkpoint_result(
                plan,
                status="STAGE_TARGET",
                reason="lost_return_reobserved_target",
                stage=requested_stage,
                prefix_before=prefix_before,
                prefix_after=prefix_after,
                before_observation=before_observation,
                after_observation=after_observation,
                callbacks=callbacks,
                local_reverse="NOT_REQUIRED",
                writer_boundary=False,
            )
        predecessor_established = prefix_after == prefix_before
        if immutable_after_states is not None:
            predecessor_established = (
                canonical(after_observation) == canonical(before_observation)
            )
        if predecessor_established:
            return _checkpoint_result(
                plan,
                status="STAGE_FAILED_CHECKPOINT_RESTORED",
                reason=getattr(exc, "code", "fixed_checkpoint_stage_failed"),
                stage=requested_stage,
                prefix_before=prefix_before,
                prefix_after=prefix_after,
                before_observation=before_observation,
                after_observation=after_observation,
                callbacks=callbacks,
                local_reverse=(
                    "RESTORED_PRECEDING_CHECKPOINT"
                    if reverse_counter[0]
                    else "NO_EFFECT_OR_REOBSERVED_PREDECESSOR"
                ),
                writer_boundary=False,
            )
        return _checkpoint_unestablished_result(
            plan,
            reason="post_effect_state_ambiguous",
            stage=requested_stage,
            prefix_before=prefix_before,
            before_observation=before_observation,
            callbacks=callbacks,
            local_reverse=(
                "FAILED_OR_UNESTABLISHED"
                if reverse_counter[0]
                else "NO_AUTOMATIC_REVERSE"
            ),
            writer_boundary=False,
        )

    try:
        after_plan = _fresh_checkpoint_plan(authority)
        prefix_after = _checkpoint_prefix(after_plan)
        after_observation = after_plan["observation"]
        assert isinstance(after_observation, Mapping)
        stage_target_established = prefix_after == expected_after
        if immutable_after_states is not None:
            after_releases = after_observation["releases"]
            assert isinstance(after_releases, Mapping)
            stage_target_established = (
                tuple(
                    after_releases[key]["state"]
                    for key in product.IMMUTABLE_ARTIFACTS
                )
                == immutable_after_states
                and canonical(
                    {
                        key: value
                        for key, value in after_observation.items()
                        if key != "releases"
                    }
                )
                == immutable_stable_projection
            )
        require(
            stage_target_established,
            "fixed_checkpoint_stage_poststate_rejected",
        )
    except Exception:
        return _checkpoint_unestablished_result(
            plan,
            reason=(
                "writer_terminal_observation_unestablished"
                if writer_boundary
                else "post_effect_observation_unestablished"
            ),
            stage=requested_stage,
            prefix_before=prefix_before,
            before_observation=before_observation,
            callbacks=callbacks,
            local_reverse=(
                "FORBIDDEN_POST_WRITER"
                if writer_boundary
                else "NO_AUTOMATIC_REVERSE"
            ),
            writer_boundary=writer_boundary,
        )
    return _checkpoint_result(
        plan,
        status=(
            "SUPERVISED_MANUAL_REQUIRED"
            if writer_boundary
            else "STAGE_TARGET"
        ),
        reason=(
            "durability_target_verified"
            if requested_stage == "RESUME_ATTEMPT5_TARGET_ONCE"
            else "writer_dispatched_terminal_observation_requires_owner"
            if writer_boundary
            else "stage_target_verified"
        ),
        stage=requested_stage,
        prefix_before=prefix_before,
        prefix_after=prefix_after,
        before_observation=before_observation,
        after_observation=after_observation,
        callbacks=callbacks,
        local_reverse=("FORBIDDEN_POST_WRITER" if writer_boundary else "NOT_REQUIRED"),
        writer_boundary=writer_boundary,
    )


def fixed_owner_entry(
    *,
    stage: str | None = None,
    supervised_start: bool = False,
) -> int:
    try:
        lock_descriptor = os.open(
            CONTROLLER_RELEASES_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError:
        print(json.dumps({"callbacks": 0, "reason": "fixed_owner_lock_rejected", "schema": product.RESULT_SCHEMA, "status": "SUPERVISED_MANUAL_REQUIRED"}, sort_keys=True))
        return 75
    try:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            print(json.dumps({"callbacks": 0, "reason": "fixed_owner_concurrent", "schema": product.RESULT_SCHEMA, "status": "SUPERVISED_MANUAL_REQUIRED"}, sort_keys=True))
            return 75
        try:
            authority = load_installed_source_authority()
            plan = _fresh_checkpoint_plan(authority)
            result = run_checkpointed_stage(
                plan,
                requested_stage=stage,
                supervised_start=supervised_start,
            )
        except (MemoryActivationRejected, product.ProductionPlanRejected, resume.ResumeRejected) as exc:
            print(json.dumps({"callbacks": 0, "reason": getattr(exc, "code", "fixed_product_rejected"), "schema": product.RESULT_SCHEMA, "status": "rejected"}, sort_keys=True))
            return 1
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 75 if result["status"] in {"SUPERVISED_START_REQUIRED", "SUPERVISED_MANUAL_REQUIRED"} else 0
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)


def _git_bytes(repository: Path, arguments: tuple[str, ...]) -> bytes:
    environment = dict(os.environ)
    environment.update(GIT_NO_REPLACE_OBJECTS="1", LC_ALL="C")
    try:
        completed = subprocess.run(
            [
                "/usr/bin/git",
                "-c",
                f"safe.directory={repository.as_posix()}",
                "-C",
                repository.as_posix(),
                *arguments,
            ],
            check=False,
            capture_output=True,
            env=environment,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_git_rejected") from exc
    require(
        completed.returncode == 0,
        "fixed_unit_lineage_git_rejected",
    )
    return completed.stdout


def _git_auxiliary_path(repository: Path, name: str) -> Path:
    try:
        value = _git_bytes(
            repository,
            ("rev-parse", "--git-path", name),
        ).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_git_rejected") from exc
    require(
        bool(value) and "\n" not in value and "\r" not in value,
        "fixed_unit_lineage_git_rejected",
    )
    selected = Path(value)
    return selected if selected.is_absolute() else repository / selected


def _git_commit(repository: Path, commit: str) -> tuple[str, str]:
    require(
        re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
        "fixed_unit_lineage_git_rejected",
    )
    try:
        resolved = _git_bytes(
            repository,
            ("rev-parse", "--verify", f"{commit}^{{commit}}"),
        ).decode("ascii").strip()
        payload = _git_bytes(repository, ("cat-file", "commit", commit)).decode(
            "utf-8"
        )
    except UnicodeDecodeError as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_git_rejected") from exc
    require(resolved == commit, "fixed_unit_lineage_git_rejected")
    header = payload.split("\n\n", 1)[0].splitlines()
    trees = [line[5:] for line in header if line.startswith("tree ")]
    parents = [line[7:] for line in header if line.startswith("parent ")]
    require(
        len(trees) == 1
        and re.fullmatch(r"[0-9a-f]{40}", trees[0]) is not None
        and len(parents) == 1
        and re.fullmatch(r"[0-9a-f]{40}", parents[0]) is not None,
        "fixed_unit_lineage_git_rejected",
    )
    return trees[0], parents[0]


def _bounded_transitional_pairs(
    repository: Path = DEPLOY_REPOSITORY,
    *, upper: str | None = None,
) -> tuple[tuple[str, str], ...]:
    try:
        metadata = repository.lstat()
        resolved = repository.resolve(strict=True)
    except OSError as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_git_rejected") from exc
    require(
        not stat.S_ISLNK(metadata.st_mode)
        and stat.S_ISDIR(metadata.st_mode)
        and resolved == repository,
        "fixed_unit_lineage_git_rejected",
    )
    require(
        _git_bytes(repository, ("rev-parse", "--show-object-format"))
        == b"sha1\n"
        and not _git_bytes(
            repository,
            ("for-each-ref", "--format=%(refname)", "refs/replace"),
        ),
        "fixed_unit_lineage_git_rejected",
    )
    for auxiliary in ("info/grafts", "shallow"):
        selected = _git_auxiliary_path(repository, auxiliary)
        require(
            not selected.exists() and not selected.is_symlink(),
            "fixed_unit_lineage_git_rejected",
        )
    lower = product.TRANSITIONAL_LINEAGE_LOWER
    upper = product.TRANSITIONAL_LINEAGE_UPPER if upper is None else upper
    require(
        re.fullmatch(r"[0-9a-f]{40}", upper) is not None
        and re.fullmatch(r"[0-9a-f]{40}", lower) is not None
        and lower != upper,
        "fixed_unit_lineage_git_rejected",
    )
    pairs: list[tuple[str, str]] = []
    selected = upper
    seen: set[str] = set()
    while selected != lower:
        require(
            selected not in seen and len(pairs) < 128,
            "fixed_unit_lineage_git_rejected",
        )
        seen.add(selected)
        _tree, parent = _git_commit(repository, selected)
        pairs.append((selected, parent))
        selected = parent
    _git_bytes(repository, ("rev-parse", "--verify", f"{lower}^{{commit}}"))
    require(bool(pairs), "fixed_unit_lineage_git_rejected")
    return tuple(pairs)


def _canonical_release_json(
    path: Path,
    *,
    code: str,
) -> dict[str, object]:
    observed = _file_observation(path)
    require(
        observed["kind"] == "regular"
        and observed["mode"] == "0444"
        and observed["uid"] == 0
        and observed["gid"] == 0,
        code,
    )
    try:
        payload = base64.b64decode(str(observed["payload_b64"]), validate=True)
        value = json.loads(payload.decode("ascii"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MemoryActivationRejected(code) from exc
    require(type(value) is dict and canonical(value) == payload, code)
    return value


def _verified_deploy_source_binding(
    release_root: Path,
    document: Mapping[str, object],
    repository: Path = DEPLOY_REPOSITORY,
) -> None:
    receipt = _canonical_release_json(
        release_root / "CORRESPONDING_SOURCE.json",
        code="fixed_unit_lineage_source_rejected",
    )
    require(
        set(receipt)
        == {
            "core_commit",
            "core_members",
            "core_tree",
            "deploy_commit",
            "deploy_members",
            "deploy_tree",
            "member_count",
            "schema",
        }
        and receipt["schema"]
        == "myuna.telegram.r5-controller-corresponding-source.v2"
        and receipt == document.get("source_receipt")
        and sha256(canonical(receipt)).hexdigest()
        == document.get("paired_source_receipt_sha256")
        and receipt["deploy_commit"] == document.get("deploy_commit")
        and receipt["deploy_tree"] == document.get("deploy_tree")
        and type(receipt["deploy_members"]) is list
        and type(receipt["core_members"]) is list
        and receipt["member_count"]
        == len(receipt["deploy_members"]) + len(receipt["core_members"]),
        "fixed_unit_lineage_source_rejected",
    )
    commit = str(receipt["deploy_commit"])
    tree = str(receipt["deploy_tree"])
    try:
        actual_tree = _git_bytes(
            repository,
            ("rev-parse", "--verify", f"{commit}^{{tree}}"),
        ).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_source_rejected") from exc
    require(actual_tree == tree, "fixed_unit_lineage_source_rejected")
    manifest_files = document.get("files")
    require(type(manifest_files) is list, "fixed_unit_lineage_source_rejected")
    by_destination: dict[str, Mapping[str, object]] = {}
    for row in manifest_files:
        require(type(row) is dict, "fixed_unit_lineage_source_rejected")
        destination = row.get("destination")
        require(
            type(destination) is str and destination not in by_destination,
            "fixed_unit_lineage_source_rejected",
        )
        by_destination[destination] = row
    required_sources = {
        "scripts/activate_p07_owner_private_memory_v1.py",
        "scripts/build_p07_hybrid_live_releases_v1.py",
        "scripts/build_telegram_r5_controller_release_v1.py",
        "scripts/p07_owner_private_memory_production_plan.py",
        "scripts/telegram_r5_boot_resume.py",
    }
    observed_sources: set[str] = set()
    observed_destinations: set[str] = set()
    deploy_members = receipt["deploy_members"]
    assert isinstance(deploy_members, list)
    for row in deploy_members:
        require(
            type(row) is dict
            and set(row)
            == {
                "blob",
                "bytes",
                "content_sha256",
                "destination",
                "installed_mode",
                "mode",
                "source",
            },
            "fixed_unit_lineage_source_rejected",
        )
        assert isinstance(row, dict)
        source = row["source"]
        destination = row["destination"]
        require(
            type(source) is str
            and type(destination) is str
            and not source.startswith("/")
            and ".." not in Path(source).parts
            and re.fullmatch(r"[A-Za-z0-9._/-]+", source) is not None
            and destination not in observed_destinations
            and source not in observed_sources
            and by_destination.get(destination) == row,
            "fixed_unit_lineage_source_rejected",
        )
        observed_sources.add(source)
        observed_destinations.add(destination)
        listing = _git_bytes(
            repository,
            ("ls-tree", "-z", commit, "--", source),
        )
        require(
            listing.endswith(b"\0") and listing.count(b"\0") == 1,
            "fixed_unit_lineage_source_rejected",
        )
        try:
            header, named = listing[:-1].split(b"\t", 1)
            mode, kind, blob = header.decode("ascii").split(" ")
            named_source = named.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise MemoryActivationRejected(
                "fixed_unit_lineage_source_rejected"
            ) from exc
        require(
            named_source == source
            and kind == "blob"
            and mode == row["mode"]
            and blob == row["blob"],
            "fixed_unit_lineage_source_rejected",
        )
        source_payload = _git_bytes(repository, ("cat-file", "blob", blob))
        installed = _file_observation(release_root / destination)
        try:
            installed_payload = base64.b64decode(
                str(installed["payload_b64"]), validate=True
            )
        except ValueError as exc:
            raise MemoryActivationRejected(
                "fixed_unit_lineage_source_rejected"
            ) from exc
        require(
            len(source_payload) == row["bytes"]
            and sha256(source_payload).hexdigest() == row["content_sha256"]
            and source_payload == installed_payload
            and installed["mode"] == row["installed_mode"]
            and installed["uid"] == 0
            and installed["gid"] == 0,
            "fixed_unit_lineage_source_rejected",
        )
    require(
        required_sources.issubset(observed_sources),
        "fixed_unit_lineage_source_rejected",
    )
    for field, sha_field in (
        ("controller_builder", "controller_builder_sha256"),
        ("paired_builder", "paired_builder_sha256"),
    ):
        selected = document.get(field)
        require(
            type(selected) is dict
            and selected == by_destination.get(str(selected.get("destination")))
            and selected.get("content_sha256") == document.get(sha_field),
            "fixed_unit_lineage_source_rejected",
        )


def _historical_controller_authority(
    release_root: Path,
) -> dict[str, object]:
    prior_product_path = release_root / "p07_owner_private_memory_production_plan.py"
    prior_spec = importlib.util.spec_from_file_location(
        "p07_owner_private_memory_production_plan",
        prior_product_path,
    )
    require(
        prior_spec is not None and prior_spec.loader is not None,
        "fixed_unit_lineage_release_rejected",
    )
    prior_product = importlib.util.module_from_spec(prior_spec)
    current_product = sys.modules.get("p07_owner_private_memory_production_plan")
    try:
        sys.modules["p07_owner_private_memory_production_plan"] = prior_product
        prior_spec.loader.exec_module(prior_product)
        verified = resume.verify_fixed_controller_release(
            release_root,
            environment={},
        )
    except (OSError, ImportError, AttributeError) as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_release_rejected") from exc
    finally:
        if current_product is None:
            sys.modules.pop("p07_owner_private_memory_production_plan", None)
        else:
            sys.modules["p07_owner_private_memory_production_plan"] = current_product
    return verified


def _prior_attempt_archive_child_name(
    repository: Path = DEPLOY_REPOSITORY,
) -> str:
    """Recover the sole source-generation child from sealed Attempt-5 lineage."""

    _transitional_attempt_gate()
    release_root = CONTROLLER_RELEASES_ROOT / product.ATTEMPT5_PRIOR_CONTROLLER_RELEASE
    metadata = release_root.lstat()
    require(
        not stat.S_ISLNK(metadata.st_mode)
        and stat.S_ISDIR(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o555
        and metadata.st_uid == 0
        and metadata.st_gid == 0,
        "fixed_archive_child_lineage_rejected",
    )
    document = _canonical_release_json(
        release_root / "MANIFEST.json",
        code="fixed_archive_child_lineage_rejected",
    )
    source_pair = (
        document.get("deploy_commit"),
        document.get("deploy_parent"),
    )
    require(
        source_pair
        in _bounded_transitional_pairs(
            repository,
            upper=product.ARCHIVE_CHILD_CREATOR_LINEAGE_UPPER,
        ),
        "fixed_archive_child_lineage_rejected",
    )
    _verified_deploy_source_binding(release_root, document, repository)
    verified = _historical_controller_authority(release_root)
    source = verified.get("source")
    require(
        type(source) is dict
        and source.get("deploy_commit") == source_pair[0]
        and source.get("deploy_parent") == source_pair[1]
        and source.get("deploy_tree") == document.get("deploy_tree"),
        "fixed_archive_child_lineage_rejected",
    )
    try:
        selected = product._source_generated_memory_runtime(verified)
    except product.ProductionPlanRejected as exc:
        raise MemoryActivationRejected(
            "fixed_archive_child_lineage_rejected"
        ) from exc
    name = str(selected["archive_id"])
    require(
        sha256(name.encode("ascii")).hexdigest()
        == product.ATTEMPT5_PRIOR_ARCHIVE_CHILD_NAME_SHA256
        and name != product.stable_attempt_archive_child_name(),
        "fixed_archive_child_lineage_rejected",

    )
    return name

def _transitional_attempt_gate() -> None:
    require(
        product.TRANSITIONAL_INSTALL_ATTEMPT == 5
        and product.TRANSITIONAL_ATTEMPT_UNCONSUMED is False
        and product.TRANSITIONAL_WRITER_BOUNDARY is False
        and product.TRANSITIONAL_STAGE_ENTRY == "ARCHIVE_CHILD_NAME_CONVERGENCE_REQUIRED",
        "fixed_unit_lineage_attempt_rejected",
    )


def _transitional_release_id(unit_payload: bytes) -> str:
    try:
        lines = unit_payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_unit_rejected") from exc
    prefix = "Environment=MYUNA_PHASE_F_CONTROLLER_RELEASE_SHA256="
    selected = [line.removeprefix(prefix) for line in lines if line.startswith(prefix)]
    require(
        len(selected) == 1
        and re.fullmatch(r"[0-9a-f]{64}", selected[0]) is not None,
        "fixed_unit_lineage_unit_rejected",
    )
    return selected[0]


def _admit_transitional_controller_unit(
    before_unit: Mapping[str, object],
    repository: Path = DEPLOY_REPOSITORY,
) -> bool:
    _transitional_attempt_gate()
    require(
        before_unit.get("kind") == "regular"
        and before_unit.get("mode") == "0644"
        and before_unit.get("uid") == 0
        and before_unit.get("gid") == 0,
        "fixed_unit_lineage_unit_rejected",
    )
    try:
        unit_payload = base64.b64decode(
            str(before_unit.get("payload_b64")), validate=True
        )
    except ValueError as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_unit_rejected") from exc
    require(
        sha256(unit_payload).hexdigest() == before_unit.get("sha256"),
        "fixed_unit_lineage_unit_rejected",
    )
    release_id = _transitional_release_id(unit_payload)
    release_root = CONTROLLER_RELEASES_ROOT / release_id
    try:
        release_before = release_root.lstat()
    except OSError as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_release_rejected") from exc
    require(
        not stat.S_ISLNK(release_before.st_mode)
        and stat.S_ISDIR(release_before.st_mode)
        and stat.S_IMODE(release_before.st_mode) == 0o555
        and release_before.st_uid == 0
        and release_before.st_gid == 0,
        "fixed_unit_lineage_release_rejected",
    )
    document = _canonical_release_json(
        release_root / "MANIFEST.json",
        code="fixed_unit_lineage_release_rejected",
    )
    pairs = _bounded_transitional_pairs(repository)
    source_pair = (
        document.get("deploy_commit"),
        document.get("deploy_parent"),
    )
    require(
        source_pair in pairs,
        "fixed_unit_lineage_pair_rejected",
    )
    _verified_deploy_source_binding(release_root, document, repository)
    verified = _historical_controller_authority(release_root)
    source = verified.get("source")
    controller = verified.get("controller")
    sealed_authority = document.get("fixed_product_authority")
    sealed_controller = (
        sealed_authority.get("controller")
        if type(sealed_authority) is dict
        else None
    )
    require(
        type(source) is dict
        and type(controller) is dict
        and type(sealed_controller) is dict
        and source.get("deploy_commit") == source_pair[0]
        and source.get("deploy_parent") == source_pair[1]
        and source.get("deploy_tree") == document.get("deploy_tree")
        and controller.get("config_sha256")
        == sealed_controller.get("config_sha256"),
        "fixed_unit_lineage_release_rejected",
    )
    template = _file_observation(
        release_root / "myuna-telegram-owner-r5-resume.service.in"
    )
    try:
        template_payload = base64.b64decode(
            str(template["payload_b64"]), validate=True
        ).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_unit_rejected") from exc
    rendered = (
        template_payload.replace(
            "@CONTROLLER_RELEASE_ROOT@", release_root.as_posix()
        )
        .replace("@CONTROLLER_RELEASE_DIGEST@", release_id)
        .replace(
            "@CONTROLLER_CONFIG_SHA256@",
            str(controller["config_sha256"]),
        )
        .replace(
            "@CONTROLLER_AUTHORITY_SHA256@",
            str(verified["authority_sha256"]),
        )
    ).encode("utf-8")
    require(
        b"@CONTROLLER_" not in rendered and rendered == unit_payload,
        "fixed_unit_lineage_unit_rejected",
    )
    try:
        release_after = release_root.lstat()
    except OSError as exc:
        raise MemoryActivationRejected("fixed_unit_lineage_release_rejected") from exc
    require(
        (
            release_after.st_dev,
            release_after.st_ino,
            release_after.st_mode,
            release_after.st_nlink,
            release_after.st_uid,
            release_after.st_gid,
        )
        == (
            release_before.st_dev,
            release_before.st_ino,
            release_before.st_mode,
            release_before.st_nlink,
            release_before.st_uid,
            release_before.st_gid,
        ),
        "fixed_unit_lineage_release_rejected",
    )
    return True


def _publish_current_controller_release() -> tuple[Path, dict[str, object]]:
    """Publish and reopen the sealed current release without selecting it."""

    source_root = Path(__file__).resolve().parent
    authority = resume.verify_fixed_controller_release(source_root)
    require(
        CONTROLLER_RELEASES_ROOT.exists()
        and CONTROLLER_RELEASES_ROOT.is_dir()
        and not CONTROLLER_RELEASES_ROOT.is_symlink(),
        "fixed_controller_install_root_rejected",
    )
    release_root = CONTROLLER_RELEASES_ROOT / source_root.name
    if not release_root.exists() and not release_root.is_symlink():
        temporary = Path(
            tempfile.mkdtemp(
                prefix=f".{source_root.name}.",
                dir=CONTROLLER_RELEASES_ROOT,
            )
        )
        try:
            shutil.copytree(
                source_root,
                temporary,
                copy_function=shutil.copy2,
                dirs_exist_ok=True,
                symlinks=False,
            )
            for selected in sorted(
                (item for item in temporary.rglob("*") if item.is_file()),
                key=lambda item: item.as_posix(),
            ):
                descriptor = os.open(
                    selected,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            for directory in sorted(
                (item for item in temporary.rglob("*") if item.is_dir()),
                reverse=True,
            ):
                os.chmod(directory, 0o555)
                descriptor = os.open(
                    directory,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            os.chmod(temporary, 0o555)
            descriptor = os.open(
                temporary,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            completed = subprocess.run(
                [
                    "/usr/bin/mv",
                    "--no-clobber",
                    "--no-target-directory",
                    temporary.as_posix(),
                    release_root.as_posix(),
                ],
                check=False,
                capture_output=True,
                timeout=60,
            )
            require(
                completed.returncode == 0 and not temporary.exists(),
                "fixed_controller_publish_collision",
            )
            parent = os.open(
                CONTROLLER_RELEASES_ROOT,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except Exception:
            if temporary.exists():
                for selected in (temporary, *temporary.rglob("*")):
                    if not selected.is_symlink():
                        try:
                            os.chmod(selected, 0o755 if selected.is_dir() else 0o644)
                        except OSError:
                            pass
                shutil.rmtree(temporary, ignore_errors=True)
            raise
    installed_authority = resume.verify_fixed_controller_release(release_root)
    require(installed_authority == authority, "fixed_controller_install_rejected")

    return release_root, authority


def _render_controller_unit(
    release_root: Path,
    authority: Mapping[str, object],
) -> bytes:
    template = release_root / "myuna-telegram-owner-r5-resume.service.in"
    payload = template.read_text("utf-8")
    rendered = (
        payload.replace("@CONTROLLER_RELEASE_ROOT@", release_root.as_posix())
        .replace("@CONTROLLER_RELEASE_DIGEST@", release_root.name)
        .replace(
            "@CONTROLLER_CONFIG_SHA256@",
            str(authority["controller"]["config_sha256"]),
        )
        .replace(
            "@CONTROLLER_AUTHORITY_SHA256@",
            str(authority["authority_sha256"]),
        )
    ).encode("utf-8")
    require(b"@CONTROLLER_" not in rendered, "fixed_unit_render_rejected")
    return rendered


def install_current_controller_unit() -> dict[str, object]:
    """Publish the sealed current release and install its existing unit."""

    release_root, authority = _publish_current_controller_release()
    rendered = _render_controller_unit(release_root, authority)
    target_unit_sha256 = sha256(rendered).hexdigest()
    before_unit = _file_observation(UNIT_PATH)
    transitional_unit = False
    if before_unit["sha256"] not in {
        ACCEPTED_OLD_UNIT_SHA256,
        target_unit_sha256,
    }:
        transitional_unit = _admit_transitional_controller_unit(before_unit)
    require(
        before_unit["kind"] == "regular"
        and before_unit["mode"] == "0644"
        and before_unit["uid"] == 0
        and before_unit["gid"] == 0
        and (
            before_unit["sha256"]
            in {ACCEPTED_OLD_UNIT_SHA256, target_unit_sha256}
            or transitional_unit
        ),
        "fixed_unit_prestate_rejected",
    )
    if before_unit["sha256"] != target_unit_sha256:
        _atomic_file(UNIT_PATH, rendered, 0o644, 0, 0)
    installed = _file_observation(UNIT_PATH)
    require(
        installed["sha256"] == target_unit_sha256
        and installed["mode"] == "0644"
        and installed["uid"] == 0
        and installed["gid"] == 0
        and (
            f"ExecStart=/usr/bin/python3 {release_root.as_posix()}/"
            "telegram_r5_boot_resume.py"
        ).encode("ascii")
        in rendered,
        "fixed_unit_install_rejected",
    )
    require(
        resume.verify_fixed_controller_release(release_root) == authority,
        "fixed_controller_install_rejected",
    )
    return {
        "release": release_root.name,
        "schema": SCHEMA,
        "status": "INSTALLED_INACTIVE_NOT_STARTED",
        "unit_sha256": installed["sha256"],
    }


def _r5_durability_pair_state(
    config: Mapping[str, object],
    unit: Mapping[str, object],
    target_unit_sha256: str,
) -> str:
    require(
        config.get("kind") == "regular"
        and config.get("mode") == "0600"
        and config.get("uid") == 0
        and config.get("gid") == 0
        and unit.get("kind") == "regular"
        and unit.get("mode") == "0644"
        and unit.get("uid") == 0
        and unit.get("gid") == 0,
        "r5_durability_pair_metadata_rejected",
    )
    config_state = (
        "OLD"
        if config.get("sha256") == product.R5_DURABILITY_BASELINE_CONFIG_SHA256
        else (
            "TARGET"
            if config.get("sha256") == product.R5_DURABILITY_TARGET_CONFIG_SHA256
            else "THIRD_STATE"
        )
    )
    unit_state = (
        "OLD"
        if unit.get("sha256") == product.R5_DURABILITY_BASELINE_UNIT_SHA256
        else "TARGET" if unit.get("sha256") == target_unit_sha256 else "THIRD_STATE"
    )
    require(
        config_state == unit_state and config_state in {"OLD", "TARGET"},
        "r5_durability_pair_state_rejected",
    )
    return config_state


def _r5_durability_daemon_reload() -> None:
    try:
        completed = subprocess.run(
            ["/usr/bin/systemctl", "daemon-reload"],
            check=False,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MemoryActivationRejected(
            "r5_durability_daemon_reload_rejected"
        ) from exc
    require(
        completed.returncode == 0,
        "r5_durability_daemon_reload_rejected",
    )


def _install_r5_durability_pair(
    target_release_root: Path,
    target_authority: Mapping[str, object],
    baseline_release_root: Path,
    baseline_authority: Mapping[str, object],
) -> dict[str, object]:
    product.validate_r5_durability_authority(
        baseline_authority,
        target_authority,
    )
    target_unit = _render_controller_unit(target_release_root, target_authority)
    baseline_unit = _render_controller_unit(
        baseline_release_root,
        baseline_authority,
    )
    require(
        sha256(baseline_unit).hexdigest()
        == product.R5_DURABILITY_BASELINE_UNIT_SHA256,
        "r5_durability_baseline_unit_rejected",
    )
    target_unit_sha256 = sha256(target_unit).hexdigest()
    target_config = product.r5_durability_target_config()
    config_path = Path(product.R5_CONFIG_PATH)
    before_config = _file_observation(config_path)
    before_unit = _file_observation(UNIT_PATH)
    state = _r5_durability_pair_state(
        before_config,
        before_unit,
        target_unit_sha256,
    )
    if state == "TARGET":
        return {
            "callbacks": 0,
            "config_sha256": product.R5_DURABILITY_TARGET_CONFIG_SHA256,
            "release": target_release_root.name,
            "schema": SCHEMA,
            "status": "R5_DURABILITY_TARGET",
            "unit_sha256": target_unit_sha256,
        }
    old_config = base64.b64decode(
        str(before_config["payload_b64"]), validate=True
    )
    callbacks = 0
    try:
        require(
            _file_observation(config_path) == before_config
            and _file_observation(UNIT_PATH) == before_unit,
            "r5_durability_pair_aba_rejected",
        )
        callbacks += 1
        _atomic_file(config_path, target_config, 0o600, 0, 0)
        observed_config = _file_observation(config_path)
        require(
            observed_config.get("sha256")
            == product.R5_DURABILITY_TARGET_CONFIG_SHA256,
            "r5_durability_config_install_rejected",
        )
        require(
            _file_observation(UNIT_PATH) == before_unit,
            "r5_durability_pair_aba_rejected",
        )
        callbacks += 1
        _atomic_file(UNIT_PATH, target_unit, 0o644, 0, 0)
        callbacks += 1
        _r5_durability_daemon_reload()
        after_config = _file_observation(config_path)
        after_unit = _file_observation(UNIT_PATH)
        require(
            _r5_durability_pair_state(
                after_config,
                after_unit,
                target_unit_sha256,
            )
            == "TARGET",
            "r5_durability_target_reobservation_rejected",
        )
        require(
            resume.verify_fixed_controller_release(target_release_root)
            == target_authority,
            "r5_durability_target_release_changed",
        )
        return {
            "callbacks": callbacks,
            "config_sha256": product.R5_DURABILITY_TARGET_CONFIG_SHA256,
            "release": target_release_root.name,
            "schema": SCHEMA,
            "status": "R5_DURABILITY_TARGET",
            "unit_sha256": target_unit_sha256,
        }
    except (
        MemoryActivationRejected,
        product.ProductionPlanRejected,
        resume.ResumeRejected,
        OSError,
        ValueError,
    ) as exc:
        if callbacks == 0:
            raise
        try:
            current_config = _file_observation(config_path)
            current_unit = _file_observation(UNIT_PATH)
            require(
                current_config.get("sha256")
                in {
                    product.R5_DURABILITY_BASELINE_CONFIG_SHA256,
                    product.R5_DURABILITY_TARGET_CONFIG_SHA256,
                }
                and current_unit.get("sha256")
                in {
                    product.R5_DURABILITY_BASELINE_UNIT_SHA256,
                    target_unit_sha256,
                },
                "r5_durability_rollback_prestate_rejected",
            )
            if current_unit.get("sha256") != product.R5_DURABILITY_BASELINE_UNIT_SHA256:
                _atomic_file(UNIT_PATH, baseline_unit, 0o644, 0, 0)
            if current_config.get("sha256") != product.R5_DURABILITY_BASELINE_CONFIG_SHA256:
                _atomic_file(config_path, old_config, 0o600, 0, 0)
            _r5_durability_daemon_reload()
            require(
                _r5_durability_pair_state(
                    _file_observation(config_path),
                    _file_observation(UNIT_PATH),
                    target_unit_sha256,
                )
                == "OLD",
                "r5_durability_rollback_reobservation_rejected",
            )
        except (
            MemoryActivationRejected,
            product.ProductionPlanRejected,
            resume.ResumeRejected,
            OSError,
            ValueError,
        ) as rollback_exc:
            raise MemoryActivationRejected(
                "r5_durability_manual_recovery_required"
            ) from rollback_exc
        raise MemoryActivationRejected(
            "r5_durability_install_rolled_back"
        ) from exc


def install_r5_durability_selection() -> dict[str, object]:
    """Install the one exact source-command controller/config selection."""

    try:
        lock_descriptor = os.open(
            CONTROLLER_RELEASES_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError) as exc:
        raise MemoryActivationRejected("r5_durability_lock_rejected") from exc
    try:
        target_release_root, target_authority = _publish_current_controller_release()
        baseline_release_root = (
            CONTROLLER_RELEASES_ROOT
            / product.R5_DURABILITY_BASELINE_CONTROLLER_RELEASE
        )
        baseline_authority = _historical_controller_authority(
            baseline_release_root
        )
        return _install_r5_durability_pair(
            target_release_root,
            target_authority,
            baseline_release_root,
            baseline_authority,
        )
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)


def parser() -> argparse.ArgumentParser:
    selected = argparse.ArgumentParser()
    selected.add_argument("--install-current-controller-unit", action="store_true")
    selected.add_argument("--install-r5-durability-selection", action="store_true")
    selected.add_argument("--preflight-only", action="store_true")
    selected.add_argument("--supervised-start", action="store_true")
    selected.add_argument("--stage", choices=product.FIXED_STAGES)
    return selected


def main() -> int:
    values = parser().parse_args()
    require(
        sum(
            int(value)
            for value in (
                values.install_current_controller_unit,
                values.install_r5_durability_selection,
                values.preflight_only,
                values.stage is not None,
            )
        )
        <= 1,
        "fixed_action_ambiguous",
    )
    require(
        not values.supervised_start or values.stage == "ARM_AND_START_TARGET_ONCE",
        "fixed_supervised_decision_rejected",
    )
    if values.install_current_controller_unit:
        try:
            result = install_current_controller_unit()
        except Exception as exc:
            code = getattr(exc, "code", "fixed_install_rejected")
            print(
                json.dumps(
                    {"reason": code, "schema": SCHEMA, "status": "rejected"},
                    sort_keys=True,
                )
            )
            return 1
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    if values.install_r5_durability_selection:
        try:
            result = install_r5_durability_selection()
        except Exception as exc:
            code = getattr(exc, "code", "r5_durability_install_rejected")
            print(
                json.dumps(
                    {"reason": code, "schema": SCHEMA, "status": "rejected"},
                    sort_keys=True,
                )
            )
            return 1
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    if values.preflight_only:
        try:
            authority = load_installed_source_authority()
            plan = _fresh_checkpoint_plan(authority)
        except Exception as exc:
            code = getattr(exc, "code", "fixed_preflight_rejected")
            print(
                json.dumps(
                    {"reason": code, "schema": SCHEMA, "status": "rejected"},
                    sort_keys=True,
                )
            )
            return 1
        print(
            json.dumps(
                {
                    "plan_sha256": plan["plan_sha256"],
                    "schema": SCHEMA,
                    "status": "PREFLIGHT_ONLY_NO_MUTATION",
                },
                sort_keys=True,
            )
        )
        return 0
    return fixed_owner_entry(
        stage=values.stage,
        supervised_start=values.supervised_start,
    )


if __name__ == "__main__":
    raise SystemExit(main())
