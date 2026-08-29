#!/usr/bin/env python3
"""Build the sealed, builder-derived Phase-F controller release."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import grp
from hashlib import sha1, sha256
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
import telegram_r5_boot_resume as boot

SCHEMA = "myuna.telegram.r5-controller-release.v3"
SOURCE_SCHEMA = "myuna.telegram.r5-controller-corresponding-source.v2"
PAIRED_BUILDER = "scripts/build_p07_hybrid_live_releases_v1.py"
GATEWAY_BUILDER = "scripts/build_telegram_gateway_release_v1.py"
CONTROLLER_BUILDER = "scripts/build_telegram_r5_controller_release_v1.py"
CUTOVER_COMMAND = "scripts/phase_f_owner_adjudicated_one_time_cutover_v1.py"
CUTOVER_ACCEPTED_DEPLOY_PARENT = (
    "6b9cce77bbab5968bcaf2d45de0ad37b0c4d01aa"
)
RENDER_HELPER = "scripts/activate_p07_hybrid_external_generation_v1.py"
DIARY_HELPER = "scripts/p07_owner_day_diary_v2.py"
_R5_DURABILITY_HYBRID_BUILDER_BLOB = (
    "b2075d024ad98ab5bec93ebfec29187fa183d14d"
)
RUNTIME_MEMBERS = (
    ("scripts/activate_p07_owner_private_memory_v1.py", "activate_p07_owner_private_memory_v1.py"),
    ("scripts/p07_owner_private_memory_production_plan.py", "p07_owner_private_memory_production_plan.py"),
    (CUTOVER_COMMAND, "phase_f_owner_adjudicated_one_time_cutover_v1.py"),
    ("scripts/telegram_r5_boot_resume.py", "telegram_r5_boot_resume.py"),
)
STATIC_MEMBERS = (
    ("channels/astrbot-telegram/compose.dev.yml", "source-authority/channels/astrbot-telegram/compose.dev.yml"),
    ("docs/ADR-035-telegram-r5-boot-resume.md", "ADR-035-telegram-r5-boot-resume.md"),
    (PAIRED_BUILDER, "source-authority/build_p07_hybrid_live_releases_v1.py"),
    (GATEWAY_BUILDER, "source-authority/build_telegram_gateway_release_v1.py"),
    (RENDER_HELPER, "source-authority/activate_p07_hybrid_external_generation_v1.py"),
    (DIARY_HELPER, "source-authority/p07_owner_day_diary_v2.py"),
    (CONTROLLER_BUILDER, "source-authority/build_telegram_r5_controller_release_v1.py"),
    ("systemd/myuna-telegram-owner-r5-resume.service", "myuna-telegram-owner-r5-resume.service.in"),
)
FORBIDDEN_MODULES = frozenset(
    {
        "activate_p07_d_generation13_v1",
        "p07_d_activation_transaction",
        "p07_owner_private_memory_transactional_controller",
        "p07_owner_private_memory_transactional_runtime",
        "activation_transaction_substrate_v1",
    }
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_CHUNK_BYTES = 8 * 1024 * 1024


class TelegramR5ControllerReleaseRejected(RuntimeError):
    """The source, builder output, or sealed publication was rejected."""


@contextmanager
def _source_parent_contract(parent: str):
    """Admit only the frozen parent for the new one-time cutover release.

    The product validator predates this exact-base T1 and stores its accepted
    direct parent as a module constant.  The override is process-local, bounded
    to validation, and restored even on rejection; it creates no compatibility
    route and cannot select an arbitrary caller-provided parent.
    """

    if parent not in {product.ACCEPTED_DEPLOY_PARENT, CUTOVER_ACCEPTED_DEPLOY_PARENT}:
        raise TelegramR5ControllerReleaseRejected("source_parent_rejected")
    original = product.ACCEPTED_DEPLOY_PARENT
    product.ACCEPTED_DEPLOY_PARENT = parent
    try:
        yield
    finally:
        product.ACCEPTED_DEPLOY_PARENT = original


def _validate_r5_authority(
    baseline: Mapping[str, object], authority: Mapping[str, object]
) -> dict[str, object]:
    source = authority.get("source")
    _require(type(source) is dict, "source_parent_rejected")
    parent = str(source.get("deploy_parent"))
    with _source_parent_contract(parent):
        return product.validate_r5_durability_authority(baseline, authority)


def _validate_source_authority(authority: Mapping[str, object]) -> dict[str, object]:
    source = authority.get("source")
    _require(type(source) is dict, "source_parent_rejected")
    parent = str(source.get("deploy_parent"))
    with _source_parent_contract(parent):
        return product.validate_source_authority(authority)


def _authority_bundle_members(authority: Mapping[str, object]) -> set[str]:
    source = authority.get("source")
    _require(type(source) is dict, "source_parent_rejected")
    parent = str(source.get("deploy_parent"))
    with _source_parent_contract(parent):
        return product.authority_bundle_members(authority)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise TelegramR5ControllerReleaseRejected(code)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def _git(root: Path, *arguments: str, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        ["/usr/bin/git", "-c", f"safe.directory={root.resolve()}", "-C", root.resolve().as_posix(), *arguments],
        check=False,
        capture_output=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise TelegramR5ControllerReleaseRejected("source_git_identity_rejected")
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise TelegramR5ControllerReleaseRejected("source_git_identity_rejected") from exc


def _validate_repository(root: Path, commit: str, *, parent: str | None = None) -> str:
    _require(_COMMIT.fullmatch(commit) is not None, "source_commit_rejected")
    _require(_git(root, "rev-parse", "HEAD") == commit, "source_commit_rejected")
    _require(_git(root, "status", "--porcelain=v1", "--untracked-files=all") == "", "source_worktree_not_clean")
    if parent is not None:
        _require(_git(root, "rev-parse", "HEAD^") == parent, "source_parent_rejected")
    tree = str(_git(root, "rev-parse", f"{commit}^{{tree}}"))
    _require(_COMMIT.fullmatch(tree) is not None, "source_tree_rejected")
    return tree


def _git_member(root: Path, commit: str, source: str, destination: str) -> tuple[dict[str, object], bytes]:
    row = str(_git(root, "ls-tree", commit, "--", source)).split()
    if len(row) < 4 or row[1] != "blob" or row[3] != source:
        raise TelegramR5ControllerReleaseRejected("source_member_rejected")
    payload = _git(root, "show", f"{commit}:{source}", binary=True)
    assert isinstance(payload, bytes)
    metadata = (root / source).lstat()
    _require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and (root / source).read_bytes() == payload,
        "source_member_rejected",
    )
    installed_mode = "0444" if destination.startswith("source-authority/") or not destination.endswith(".py") else "0555"
    return (
        {
            "blob": row[2],
            "bytes": len(payload),
            "content_sha256": sha256(payload).hexdigest(),
            "destination": destination,
            "installed_mode": installed_mode,
            "mode": row[0],
            "source": source,
        },
        payload,
    )


def _generated_member(destination: str, payload: bytes) -> dict[str, object]:
    return {
        "blob": sha1(f"blob {len(payload)}\0".encode("ascii") + payload, usedforsecurity=False).hexdigest(),
        "bytes": len(payload),
        "content_sha256": sha256(payload).hexdigest(),
        "destination": destination,
        "installed_mode": "0444",
        "mode": "100644",
        "source": f"builder-output:{destination}",
    }


def _load_module(name: str, path: Path, search: tuple[Path, ...]):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise TelegramR5ControllerReleaseRejected("builder_module_rejected")
    module = importlib.util.module_from_spec(spec)
    old_path = list(sys.path)
    sys.modules[name] = module
    try:
        sys.path[:0] = [item.as_posix() for item in search]
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(name, None)
        raise TelegramR5ControllerReleaseRejected("builder_module_rejected") from exc
    finally:
        sys.path[:] = old_path
    return module


def _load_builders(deploy_root: Path, core_root: Path):
    search = (deploy_root / "scripts", core_root / "src")
    return (
        _load_module("_phase_f_hybrid_builder", deploy_root / PAIRED_BUILDER, search),
        _load_module("_phase_f_gateway_builder", deploy_root / GATEWAY_BUILDER, search),
        _load_module("_phase_f_render_helper", deploy_root / RENDER_HELPER, search),
        _load_module("_phase_f_diary_helper", deploy_root / DIARY_HELPER, search),
    )


def _tree_payloads(root: Path) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    metadata = root.lstat()
    _require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), "builder_release_rejected")
    rows: list[dict[str, object]] = []
    payloads: dict[str, bytes] = {}
    for selected in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        metadata = selected.lstat()
        _require(not stat.S_ISLNK(metadata.st_mode), "builder_release_rejected")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "builder_release_rejected")
        relative = selected.relative_to(root).as_posix()
        payload = selected.read_bytes()
        rows.append({"path": relative, "sha256": sha256(payload).hexdigest(), "size": len(payload)})
        payloads[relative] = payload
    _require(bool(rows), "builder_release_rejected")
    return rows, payloads


def _input_tree_member_set(root: Path) -> str:
    rows: list[dict[str, object]] = []
    for selected in sorted((root, *root.rglob("*")), key=lambda item: item.relative_to(root).as_posix()):
        metadata = selected.lstat()
        _require(not stat.S_ISLNK(metadata.st_mode), "runtime_base_rejected")
        relative_path = Path(".") if selected == root else selected.relative_to(root)
        relative = "." if selected == root else relative_path.as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            if "__pycache__" not in relative_path.parts:
                rows.append({"kind": "directory", "mode": f"{stat.S_IMODE(metadata.st_mode):04o}", "path": relative})
        else:
            _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "runtime_base_rejected")
            generated_bytecode = (
                "__pycache__" in relative_path.parent.parts
                or relative_path.suffix in {".pyc", ".pyo"}
            )
            if not generated_bytecode:
                payload = selected.read_bytes()
                rows.append({"kind": "file", "mode": f"{stat.S_IMODE(metadata.st_mode):04o}", "path": relative, "sha256": sha256(payload).hexdigest(), "size": len(payload)})
    return sha256(_canonical(rows)).hexdigest()


def _release_bundle(key: str, root: Path, digest: str, final_root: str, receipt_sha256: str) -> tuple[dict[str, object], dict[str, bytes]]:
    rows, originals = _tree_payloads(root)
    prefix = f"staging/releases/{key}/{digest}"
    return (
        {
            "bundle_prefix": prefix,
            "digest": digest,
            "directory_mode": "0550",
            "file_mode": "0440",
            "members": rows,
            "member_set_sha256": product.release_member_set_sha256(rows),
            "receipt_sha256": receipt_sha256,
            "root": final_root,
        },
        {f"{prefix}/{path}": payload for path, payload in originals.items()},
    )


def _image_bundle(archive: Path, receipt: Mapping[str, object]) -> tuple[dict[str, object], dict[str, bytes]]:
    payload = archive.read_bytes()
    digest = sha256(payload).hexdigest()
    _require(
        bool(payload)
        and receipt.get("archive_sha256") == digest
        and receipt.get("archive_size") == len(payload),
        "builder_image_rejected",
    )
    rows: list[dict[str, object]] = []
    members: dict[str, bytes] = {}
    for index, offset in enumerate(range(0, len(payload), _IMAGE_CHUNK_BYTES)):
        chunk = payload[offset : offset + _IMAGE_CHUNK_BYTES]
        path = f"staging/image/{digest}.part-{index:06d}"
        rows.append({"path": path, "sha256": sha256(chunk).hexdigest(), "size": len(chunk)})
        members[path] = chunk
    reference = str(receipt.get("image_reference"))
    _require(
        reference.startswith(product.TARGET_IMAGE_PREFIX)
        and receipt.get("manifest_digest") == "sha256:" + reference[len(product.TARGET_IMAGE_PREFIX) :],
        "builder_image_rejected",
    )
    body = dict(receipt)
    return (
        {
            "archive_members": rows,
            "archive_sha256": digest,
            "archive_size": len(payload),
            "digest": reference[len(product.TARGET_IMAGE_PREFIX) :],
            "member_set_sha256": product.image_member_set_sha256(body),
            "receipt": body,
            "receipt_sha256": sha256(product.canonical(body)).hexdigest(),
            "reference": reference,
        },
        members,
    )


def _resolve_owner(owner: str) -> tuple[int, int]:
    user, group = owner.split(":", 1)
    try:
        return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
    except KeyError as exc:
        raise TelegramR5ControllerReleaseRejected("builder_owner_identity_rejected") from exc


def _target_files(
    helper: object,
    diary: object,
    core_candidate: Path,
    releases: Mapping[str, Mapping[str, object]],
    image: Mapping[str, object],
    source: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    try:
        evidence, _artifact, _receipt = helper.core_evidence(core_candidate)
        release_seed = {
            "artifacts": {"core": releases["core"]["digest"], "image": image["digest"], "plugin": releases["plugin"]["digest"], "runtime": releases["runtime"]["digest"]},
            "parent": {"epoch_id": product.PARENT_EPOCH_ID, "epoch_revision": product.PARENT_EPOCH_REVISION, "manifest_sha256": product.PARENT_MANIFEST_SHA256, "release_set_id": product.PARENT_RELEASE_SET_ID, "selector_sha256": product.PARENT_SELECTOR_SHA256},
            "source": dict(source),
        }
        memory_release_set_id = product.digest("p07_transactional_memory_release_set", release_seed)
        policy_overlay_id = product.digest(
            "p07_transactional_memory_policy",
            {"memory_release_set_id": memory_release_set_id, "no_old_data_migration": True, "prompt_owner": diary.TEMPORARY_PROMPT_OWNER, "summary_used": False},
        )
        archive_id = f"p07-owner-private-memory-transactional-{memory_release_set_id[:16]}"
        telegram_uid = pwd.getpwnam("myuna-gateway-telegram").pw_uid
        telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
        memory = diary.OwnerPrivateMemorySelectionV4(
            memory_release_set_id=memory_release_set_id,
            parent_release_set_id=product.PARENT_RELEASE_SET_ID,
            parent_manifest_digest=product.PARENT_MANIFEST_SHA256,
            parent_selector_digest=product.PARENT_SELECTOR_SHA256,
            parent_epoch_id=product.PARENT_EPOCH_ID,
            parent_epoch_revision=product.PARENT_EPOCH_REVISION,
            policy_overlay_id=policy_overlay_id,
            archive_id=archive_id,
            runtime_root=Path(product.MEMORY_RUNTIME_ROOT) / archive_id,
            expected_uid=telegram_uid,
            expected_gid=telegram_gid,
            egress_policy_digest=diary.HISTORICAL_RAW_RECALL_EGRESS_V1_DIGEST,
            p08_lifecycle_start_watermark=product.P08_LIFECYCLE_START_WATERMARK,
            calendar_zone="Asia/Shanghai",
            calendar_zone_config_digest=diary.calendar_zone_selection_digest("Asia/Shanghai"),
        )
        approval = product.digest("p07_transactional_memory_approval_seed", {"memory_release_set_id": memory_release_set_id, "release_seed": release_seed})
        core_binding, core_selector = helper.render_core_binding(evidence, approval)
        payloads = {
            "/etc/myuna/core-release-selector/qq.binding.json": core_binding,
            "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf": core_selector,
            "/etc/systemd/system/myuna-core@qq.service.d/zzzzzzzzz-p07-hybrid-external-v1.conf": helper.render_core_gate(),
            "/etc/systemd/system/myuna-core@qq.service.d/90-p07-owner-private-memory-v1.conf": ("[Service]\n" f"Environment=MYUNA_P07_EPISODIC_OVERLAY_ID={policy_overlay_id}\n" "Environment=MYUNA_P07_EPISODIC_MEMORY_RELEASE_SET_ID=" f"{memory_release_set_id}\n" "Environment=MYUNA_P07_REFLECTIVE_DIARY_MODE=disabled\n").encode("ascii"),
            "/etc/myuna-telegram-gateway/r5-resume-v1.json": helper.render_telegram_config(str(releases["plugin"]["digest"])),
            "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/zzzzzzzzzzz-p07-hybrid-external-v1.conf": helper.render_telegram_dropin(str(releases["runtime"]["digest"])),
            "/etc/myuna-telegram-gateway/p07-owner-private-memory-selector-v4.json": diary.canonical(memory.payload()),
        }
    except Exception as exc:
        raise TelegramR5ControllerReleaseRejected("builder_target_payload_rejected") from exc
    _require(set(payloads) == set(product.FILE_ROLES), "builder_target_payload_rejected")
    result: dict[str, dict[str, object]] = {}
    for path in sorted(payloads):
        uid, gid = _resolve_owner(product.FILE_OWNERS[path])
        role, mode = product.FILE_ROLES[path]
        payload = payloads[path]
        result[path] = {"gid": gid, "mode": mode, "owner": product.FILE_OWNERS[path], "payload_b64": base64.b64encode(payload).decode("ascii"), "payload_sha256": sha256(payload).hexdigest(), "role": role, "uid": uid}
    return result


def _orchestrate_product(
    deploy_root: Path,
    core_root: Path,
    astrbot_root: Path,
    runtime_base: Path,
    base_archive: Path,
    deploy_commit: str,
    core_commit: str,
    scratch: Path,
) -> tuple[dict[str, object], dict[str, bytes]]:
    deploy_tree = _validate_repository(
        deploy_root,
        deploy_commit,
        parent=CUTOVER_ACCEPTED_DEPLOY_PARENT,
    )
    core_tree = _validate_repository(core_root, core_commit)
    _require(core_commit == product.ACCEPTED_CORE_COMMIT and core_tree == product.ACCEPTED_CORE_TREE, "core_source_identity_rejected")
    astrbot_tree = _validate_repository(astrbot_root, product.ACCEPTED_ASTRBOT_COMMIT)
    for relative, expected in ((PAIRED_BUILDER, product.HYBRID_BUILDER_BLOB), (GATEWAY_BUILDER, product.GATEWAY_BUILDER_BLOB)):
        row = str(_git(deploy_root, "ls-tree", deploy_commit, "--", relative)).split()
        _require(len(row) >= 4 and row[2] == expected, "upstream_builder_identity_rejected")
    _require(runtime_base.name == product.ACCEPTED_RUNTIME_BASE and runtime_base.is_dir() and not runtime_base.is_symlink(), "runtime_base_rejected")
    paired, gateway, helper, diary = _load_builders(deploy_root, core_root)
    core_output, runtime_output, plugin_output = scratch / "core", scratch / "runtime", scratch / "plugin"
    image_work, image_output = scratch / "image-work", scratch / "image" / "astrbot.oci.tar"
    try:
        core_document = paired.build_core(core_root, core_commit, core_output)
        _require(paired.build_core(core_root, core_commit, core_output) == core_document, "core_builder_nondeterministic")
        core_digest = str(core_document["tree_sha256"])
        core_candidate = core_output / core_digest
        helper.core_evidence(core_candidate)
        runtime_document = paired.build_runtime(deploy_root, deploy_commit, core_root, core_commit, runtime_base, runtime_output, runtime_profile="p07-owner-private-memory-v1")
        _require(paired.build_runtime(deploy_root, deploy_commit, core_root, core_commit, runtime_base, runtime_output, runtime_profile="p07-owner-private-memory-v1") == runtime_document, "runtime_builder_nondeterministic")
        runtime_digest = str(runtime_document["release_digest"])
        runtime_candidate = runtime_output / runtime_digest
        runtime_manifest, runtime_projection = paired.runtime_artifact.verify_candidate(runtime_candidate)
        _require(runtime_manifest == runtime_document and runtime_projection.get("release_digest") == runtime_digest, "runtime_builder_verification_rejected")
        plugin_document = gateway.build_release(deploy_root, plugin_output)
        _require(gateway.verify_release(plugin_output, plugin_document), "plugin_builder_verification_rejected")
        plugin_digest = str(plugin_document["release_digest"])
        plugin_candidate = plugin_output / plugin_digest
        image_work.mkdir(parents=True)
        image_output.parent.mkdir(parents=True)
        image_receipt = gateway.build_deterministic_astrbot_archive(base_archive=base_archive, astrbot_source_root=astrbot_root, work_root=image_work, output_archive=image_output, source_commit=product.ACCEPTED_ASTRBOT_COMMIT, source_date_epoch=gateway.ASTRBOT_SOURCE_DATE_EPOCH, tool_identities=gateway.ASTRBOT_TOOL_IDENTITIES)
        _require(gateway.verify_deterministic_astrbot_archive(image_output, image_receipt), "image_builder_verification_rejected")
    except TelegramR5ControllerReleaseRejected:
        raise
    except Exception as exc:
        raise TelegramR5ControllerReleaseRejected("upstream_builder_rejected") from exc
    core_release, core_payloads = _release_bundle("core", core_candidate, core_digest, product.CORE_RELEASE_ROOT, str(core_document["installation_receipt_sha256"]))
    runtime_release, runtime_payloads = _release_bundle("runtime", runtime_candidate, runtime_digest, product.RUNTIME_RELEASE_ROOT, sha256(product.canonical(runtime_document)).hexdigest())
    plugin_release, plugin_payloads = _release_bundle("plugin", plugin_candidate, plugin_digest, product.PLUGIN_RELEASE_ROOT, sha256((plugin_output / f"{plugin_digest}{gateway.MANIFEST_SUFFIX}").read_bytes()).hexdigest())
    image, image_payloads = _image_bundle(image_output, image_receipt)
    releases = {"core": core_release, "plugin": plugin_release, "runtime": runtime_release}
    source = {"core_commit": core_commit, "core_tree": core_tree, "deploy_commit": deploy_commit, "deploy_parent": CUTOVER_ACCEPTED_DEPLOY_PARENT, "deploy_tree": deploy_tree}
    files = _target_files(helper, diary, core_candidate, releases, image, source)
    authority = {
        "builder": {"astrbot_commit": product.ACCEPTED_ASTRBOT_COMMIT, "astrbot_tree": astrbot_tree, "base_image_digest": gateway.ASTRBOT_BASE_DIGEST, "gateway_builder_blob": product.GATEWAY_BUILDER_BLOB, "hybrid_builder_blob": product.HYBRID_BUILDER_BLOB, "runtime_base_digest": runtime_base.name, "runtime_base_member_set_sha256": _input_tree_member_set(runtime_base), "tool_set_sha256": sha256(product.canonical(gateway.ASTRBOT_TOOL_IDENTITIES)).hexdigest()},
        "controller": {"config_sha256": files["/etc/myuna-telegram-gateway/r5-resume-v1.json"]["payload_sha256"], "member_set_sha256": "0" * 64, "source_receipt_sha256": "0" * 64},
        "files": files,
        "image": image,
        "parent": {"epoch_id": product.PARENT_EPOCH_ID, "epoch_revision": product.PARENT_EPOCH_REVISION, "lifecycle_start_watermark": product.P08_LIFECYCLE_START_WATERMARK, "manifest_sha256": product.PARENT_MANIFEST_SHA256, "release_set_id": product.PARENT_RELEASE_SET_ID, "selector_sha256": product.PARENT_SELECTOR_SHA256},
        "releases": releases,
        "schema": product.SOURCE_SCHEMA,
        "source": source,
    }
    payloads = {**core_payloads, **runtime_payloads, **plugin_payloads, **image_payloads}
    _require(len(payloads) == sum(len(item) for item in (core_payloads, runtime_payloads, plugin_payloads, image_payloads)), "builder_bundle_collision")
    return authority, payloads


def _historical_baseline_authority(
    release_root: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    _require(
        release_root.name == product.R5_DURABILITY_BASELINE_CONTROLLER_RELEASE,
        "r5_durability_baseline_release_rejected",
    )
    try:
        document, _manifest = boot._controller_manifest(release_root)
    except (OSError, boot.ResumeRejected) as exc:
        raise TelegramR5ControllerReleaseRejected(
            "r5_durability_baseline_release_rejected"
        ) from exc
    _require(
        document.get("deploy_commit")
        == product.R5_DURABILITY_BASELINE_DEPLOY_COMMIT
        and document.get("deploy_parent")
        == product.R5_DURABILITY_BASELINE_DEPLOY_PARENT
        and document.get("deploy_tree")
        == product.R5_DURABILITY_BASELINE_DEPLOY_TREE
        and document.get("core_commit")
        == product.R5_DURABILITY_BASELINE_CORE_COMMIT
        and document.get("core_tree")
        == product.R5_DURABILITY_BASELINE_CORE_TREE,
        "r5_durability_baseline_source_rejected",
    )
    prior_path = release_root / "p07_owner_private_memory_production_plan.py"
    prior_spec = importlib.util.spec_from_file_location(
        "p07_owner_private_memory_production_plan",
        prior_path,
    )
    _require(
        prior_spec is not None and prior_spec.loader is not None,
        "r5_durability_baseline_release_rejected",
    )
    prior_product = importlib.util.module_from_spec(prior_spec)
    current_product = sys.modules.get("p07_owner_private_memory_production_plan")
    try:
        sys.modules["p07_owner_private_memory_production_plan"] = prior_product
        prior_spec.loader.exec_module(prior_product)
        verified = boot.verify_fixed_controller_release(
            release_root,
            environment={},
        )
    except (OSError, ImportError, AttributeError, boot.ResumeRejected) as exc:
        raise TelegramR5ControllerReleaseRejected(
            "r5_durability_baseline_release_rejected"
        ) from exc
    finally:
        if current_product is None:
            sys.modules.pop("p07_owner_private_memory_production_plan", None)
        else:
            sys.modules["p07_owner_private_memory_production_plan"] = current_product
    _require(
        verified.get("release_sha256")
        == product.R5_DURABILITY_BASELINE_CONTROLLER_RELEASE,
        "r5_durability_baseline_release_rejected",
    )
    fixed = {
        key: verified[key]
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
    return document, fixed


def _orchestrate_r5_durability(
    deploy_root: Path,
    core_root: Path,
    baseline_release_root: Path,
    deploy_commit: str,
    core_commit: str,
    scratch: Path,
) -> tuple[dict[str, object], dict[str, bytes], dict[str, object]]:
    deploy_tree = _validate_repository(
        deploy_root,
        deploy_commit,
        parent=CUTOVER_ACCEPTED_DEPLOY_PARENT,
    )
    core_tree = _validate_repository(core_root, core_commit)
    _require(
        core_commit == product.ACCEPTED_CORE_COMMIT
        and core_tree == product.ACCEPTED_CORE_TREE,
        "core_source_identity_rejected",
    )
    for relative, expected in (
        (PAIRED_BUILDER, _R5_DURABILITY_HYBRID_BUILDER_BLOB),
        (GATEWAY_BUILDER, product.GATEWAY_BUILDER_BLOB),
    ):
        row = str(_git(deploy_root, "ls-tree", deploy_commit, "--", relative)).split()
        _require(
            len(row) >= 4 and row[2] == expected,
            "upstream_builder_identity_rejected",
        )
    baseline_document, baseline = _historical_baseline_authority(
        baseline_release_root
    )
    search = (deploy_root / "scripts", core_root / "src")
    gateway = _load_module(
        "_phase_f_gateway_builder",
        deploy_root / GATEWAY_BUILDER,
        search,
    )
    helper = _load_module(
        "_phase_f_render_helper",
        deploy_root / RENDER_HELPER,
        search,
    )
    plugin_output = scratch / "plugin"
    try:
        plugin_document = gateway.build_release(deploy_root, plugin_output)
        _require(
            gateway.verify_release(plugin_output, plugin_document),
            "plugin_builder_verification_rejected",
        )
    except TelegramR5ControllerReleaseRejected:
        raise
    except Exception as exc:
        raise TelegramR5ControllerReleaseRejected(
            "upstream_builder_rejected"
        ) from exc
    plugin_digest = str(plugin_document["release_digest"])
    _require(
        plugin_digest == product.R5_DURABILITY_TARGET_PLUGIN_RELEASE,
        "r5_durability_target_plugin_rejected",
    )
    plugin_release, plugin_payloads = _release_bundle(
        "plugin",
        plugin_output / plugin_digest,
        plugin_digest,
        product.PLUGIN_RELEASE_ROOT,
        sha256(
            (
                plugin_output
                / f"{plugin_digest}{gateway.MANIFEST_SUFFIX}"
            ).read_bytes()
        ).hexdigest(),
    )
    target_config = helper.render_telegram_config(plugin_digest)
    _require(
        target_config == product.r5_durability_target_config(),
        "r5_durability_target_config_rejected",
    )
    authority = json.loads(_canonical(baseline))
    authority["releases"]["plugin"] = plugin_release
    config = dict(authority["files"][product.R5_CONFIG_PATH])
    config["payload_b64"] = base64.b64encode(target_config).decode("ascii")
    config["payload_sha256"] = sha256(target_config).hexdigest()
    authority["files"][product.R5_CONFIG_PATH] = config
    authority["controller"] = {
        "config_sha256": sha256(target_config).hexdigest(),
        "member_set_sha256": "0" * 64,
        "source_receipt_sha256": "0" * 64,
    }
    authority["source"] = {
        "core_commit": core_commit,
        "core_tree": core_tree,
        "deploy_commit": deploy_commit,
        "deploy_parent": CUTOVER_ACCEPTED_DEPLOY_PARENT,
        "deploy_tree": deploy_tree,
    }
    generated: dict[str, bytes] = {}
    old_prefix = str(baseline["releases"]["plugin"]["bundle_prefix"]) + "/"
    for row in baseline_document["files"]:
        destination = str(row["destination"])
        if destination.startswith("staging/") and not destination.startswith(old_prefix):
            payload = (baseline_release_root / destination).read_bytes()
            _require(
                sha256(payload).hexdigest() == row["content_sha256"],
                "r5_durability_baseline_member_rejected",
            )
            generated[destination] = payload
    _require(
        not (set(generated) & set(plugin_payloads)),
        "builder_bundle_collision",
    )
    generated.update(plugin_payloads)
    _require(
        set(generated) == _authority_bundle_members(authority),
        "r5_durability_bundle_rejected",
    )
    _validate_r5_authority(baseline, authority)
    return authority, generated, baseline


def _manifest_and_payloads(
    deploy_root: Path,
    core_root: Path,
    astrbot_root: Path,
    runtime_base: Path,
    base_archive: Path,
    deploy_commit: str,
    core_commit: str,
    scratch: Path,
    baseline_controller_root: Path | None = None,
) -> tuple[bytes, dict[str, bytes]]:
    baseline: dict[str, object] | None = None
    if baseline_controller_root is None:
        authority, generated = _orchestrate_product(deploy_root, core_root, astrbot_root, runtime_base, base_archive, deploy_commit, core_commit, scratch)
    else:
        authority, generated, baseline = _orchestrate_r5_durability(
            deploy_root,
            core_root,
            baseline_controller_root,
            deploy_commit,
            core_commit,
            scratch,
        )
    deploy_tree = str(_git(deploy_root, "rev-parse", f"{deploy_commit}^{{tree}}"))
    core_tree = str(_git(core_root, "rev-parse", f"{core_commit}^{{tree}}"))
    source_rows: list[dict[str, object]] = []
    payloads: dict[str, bytes] = {}
    for source, destination in (*RUNTIME_MEMBERS, *STATIC_MEMBERS):
        row, payload = _git_member(deploy_root, deploy_commit, source, destination)
        source_rows.append(row)
        payloads[destination] = payload
    source_rows.sort(key=lambda item: str(item["destination"]))
    _require(len(source_rows) == len(payloads), "controller_member_collision")
    source_receipt = {"core_commit": core_commit, "core_members": [], "core_tree": core_tree, "deploy_commit": deploy_commit, "deploy_members": source_rows, "deploy_tree": deploy_tree, "member_count": len(source_rows), "schema": SOURCE_SCHEMA}
    source_receipt_bytes = _canonical(source_receipt)
    payloads.update(generated)
    files = sorted([*source_rows, *(_generated_member(path, payload) for path, payload in generated.items())], key=lambda item: str(item["destination"]))
    _require(len(files) == len(payloads), "controller_member_collision")
    authority["controller"] = {"config_sha256": authority["controller"]["config_sha256"], "member_set_sha256": sha256(_canonical(files)).hexdigest(), "source_receipt_sha256": sha256(source_receipt_bytes).hexdigest()}
    validated = (
        _validate_source_authority(authority)
        if baseline is None
        else _validate_r5_authority(baseline, authority)
    )
    fixed = {key: validated[key] for key in ("builder", "controller", "files", "image", "parent", "releases", "schema", "source")}
    controller = next(row for row in source_rows if row["source"] == CONTROLLER_BUILDER)
    paired = next(row for row in source_rows if row["source"] == PAIRED_BUILDER)
    closure = {"files": [], "roots": []}
    closure["sha256"] = sha256(_canonical(closure)).hexdigest()
    document = {
        "controller_builder": controller,
        "controller_builder_sha256": controller["content_sha256"],
        "core_commit": core_commit,
        "core_import_closure": closure,
        "core_tree": core_tree,
        "deploy_commit": deploy_commit,
        "deploy_parent": authority["source"]["deploy_parent"],
        "deploy_tree": deploy_tree,
        "files": files,
        "fixed_product_authority": fixed,
        "forbidden_modules": sorted(FORBIDDEN_MODULES),
        "owner_chain": list(boot.FIXED_OWNER_CHAIN),
        "paired_builder": paired,
        "paired_builder_sha256": paired["content_sha256"],
        "paired_source_package_sha256": sha256(source_receipt_bytes).hexdigest(),
        "paired_source_receipt_sha256": sha256(source_receipt_bytes).hexdigest(),
        "schema": SCHEMA,
        "source_receipt": source_receipt,
    }
    return _canonical(document), payloads


def _expected(document: Mapping[str, object], digest: str) -> dict[str, object]:
    authority = document.get("fixed_product_authority")
    _require(type(authority) is dict, "fixed_product_authority_rejected")
    config = str(authority["controller"]["config_sha256"])
    return {"controller_config_sha256": config, "controller_release_sha256": digest, "controller_static_authority_sha256": boot.fixed_controller_authority_sha256(document, digest, config)}


def build_release(
    deploy_root: Path,
    core_root: Path,
    astrbot_root: Path,
    runtime_base: Path,
    base_archive: Path,
    output_root: Path,
    deploy_commit: str,
    core_commit: str,
    *,
    baseline_controller_root: Path | None = None,
) -> str:
    scratch: Path | None = None
    temporary: Path | None = None
    try:
        if output_root.exists():
            _require(output_root.is_dir() and not output_root.is_symlink(), "release_output_rejected")
        else:
            output_root.mkdir(parents=True)
        scratch = Path(tempfile.mkdtemp(prefix=".phase-f-product-build-", dir=output_root))
        manifest, payloads = _manifest_and_payloads(
            deploy_root,
            core_root,
            astrbot_root,
            runtime_base,
            base_archive,
            deploy_commit,
            core_commit,
            scratch,
            baseline_controller_root,
        )
        digest = sha256(manifest).hexdigest()
        release = output_root / digest
        document = json.loads(manifest)
        expected = _expected(document, digest)
        if release.exists() or release.is_symlink():
            _require(not release.is_symlink() and release.is_dir() and (release / "MANIFEST.json").read_bytes() == manifest and verify_release(output_root, digest, expected), "release_output_collision")
            return digest
        temporary = Path(tempfile.mkdtemp(prefix=f".{digest}.", dir=output_root))
        for row in document["files"]:
            destination = str(row["destination"])
            target = temporary / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payloads[destination])
            os.chmod(target, int(str(row["installed_mode"]), 8))
            descriptor = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        receipt = temporary / "CORRESPONDING_SOURCE.json"
        receipt.write_bytes(_canonical(document["source_receipt"]))
        os.chmod(receipt, 0o444)
        descriptor = os.open(receipt, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        manifest_path = temporary / "MANIFEST.json"
        manifest_path.write_bytes(manifest)
        os.chmod(manifest_path, 0o444)
        descriptor = os.open(manifest_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        for directory in sorted((item for item in temporary.rglob("*") if item.is_dir()), key=lambda item: len(item.parts), reverse=True):
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
        moved = subprocess.run(["/usr/bin/mv", "--no-clobber", "--", temporary.as_posix(), release.as_posix()], check=False, capture_output=True, timeout=120)
        _require(moved.returncode == 0 and not temporary.exists(), "release_output_collision")
        temporary = None
        parent = os.open(output_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        _require(verify_release(output_root, digest, expected), "release_verification_rejected")
        return digest
    finally:
        for private in (temporary, scratch):
            if private is not None and private.exists():
                for selected in sorted((private, *private.rglob("*")), key=lambda item: len(item.parts), reverse=True):
                    if not selected.is_symlink():
                        try:
                            os.chmod(selected, 0o755 if selected.is_dir() else 0o644)
                        except OSError:
                            pass
                shutil.rmtree(private, ignore_errors=True)


def expected_controller_authority(output_root: Path, digest: str) -> dict[str, object]:
    document, _payload = boot._controller_manifest(output_root / digest)
    return _expected(document, digest)


def controller_selection_tuple(output_root: Path, digest: str) -> dict[str, str]:
    """Return the tuple an independent review must select for cutover."""

    document, _payload = boot._controller_manifest(output_root / digest)
    receipt = (output_root / digest / "CORRESPONDING_SOURCE.json").read_bytes()
    selected = {
        "deploy_commit": str(document.get("deploy_commit")),
        "deploy_tree": str(document.get("deploy_tree")),
        "public_package_sha256": sha256(receipt).hexdigest(),
        "release_sha256": digest,
    }
    _require(
        _COMMIT.fullmatch(selected["deploy_commit"]) is not None
        and _COMMIT.fullmatch(selected["deploy_tree"]) is not None
        and document.get("paired_source_package_sha256")
        == selected["public_package_sha256"]
        and document.get("paired_source_receipt_sha256")
        == selected["public_package_sha256"]
        and sha256((output_root / digest / "MANIFEST.json").read_bytes()).hexdigest()
        == digest,
        "controller_selection_rejected",
    )
    return selected


def verified_controller_authority(
    output_root: Path, digest: str
) -> dict[str, object]:
    document, _payload = boot._controller_manifest(output_root / digest)
    parent = str(document.get("deploy_parent"))
    with _source_parent_contract(parent):
        return boot.verify_fixed_controller_release(output_root / digest)


def verify_release(output_root: Path, digest: str, expected_authority: Mapping[str, object]) -> bool:
    try:
        document, _payload = boot._controller_manifest(output_root / digest)
        parent = str(document.get("deploy_parent"))
        with _source_parent_contract(parent):
            boot.verify_fixed_controller_release(
                output_root / digest,
                environment={
                    boot.CONTROLLER_RELEASE_ENV: str(expected_authority["controller_release_sha256"]),
                    boot.CONTROLLER_CONFIG_ENV: str(expected_authority["controller_config_sha256"]),
                    boot.CONTROLLER_AUTHORITY_ENV: str(expected_authority["controller_static_authority_sha256"]),
                },
            )
    except (
        KeyError,
        OSError,
        boot.ResumeRejected,
        TelegramR5ControllerReleaseRejected,
    ):
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("deploy_root", type=Path)
    parser.add_argument("core_root", type=Path)
    parser.add_argument("astrbot_root", type=Path)
    parser.add_argument("runtime_base", type=Path)
    parser.add_argument("base_archive", type=Path)
    parser.add_argument("output_root", type=Path)
    parser.add_argument("deploy_commit")
    parser.add_argument("core_commit")
    parser.add_argument("--r5-durability-baseline-root", type=Path)
    args = parser.parse_args()
    try:
        digest = build_release(
            args.deploy_root,
            args.core_root,
            args.astrbot_root,
            args.runtime_base,
            args.base_archive,
            args.output_root,
            args.deploy_commit,
            args.core_commit,
            baseline_controller_root=args.r5_durability_baseline_root,
        )
        expected = expected_controller_authority(args.output_root, digest)
        if not verify_release(args.output_root, digest, expected):
            raise TelegramR5ControllerReleaseRejected("release_verification_rejected")
        selection = controller_selection_tuple(args.output_root, digest)
    except (OSError, UnicodeError, TelegramR5ControllerReleaseRejected):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")))
        return 1
    print(
        json.dumps(
            {"release_digest": digest, "selection": selection, "status": "built"},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
