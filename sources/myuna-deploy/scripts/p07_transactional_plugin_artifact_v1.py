#!/usr/bin/env python3
"""Source-derived Telegram plugin artifact binding for P07 memory activation.

The contract deliberately separates a caller-provided locator from artifact
identity.  Identity is derived from one clean Deploy commit/tree, the exact
allowlisted Telegram plugin sources, the reviewed release builder, and the
reviewed config renderer.  Importing this module has no filesystem side effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Mapping

import build_telegram_gateway_release_v1 as gateway_release
from activate_p07_hybrid_external_generation_v1 import render_telegram_config


SOURCE_ID = "p07-transactional-memory-telegram-plugin-source-binding-v1"
SCHEMA = "myuna.p07-transactional-memory-telegram-plugin-binding.v1"
RELEASE_BUILDER_PATH = "scripts/build_telegram_gateway_release_v1.py"
CONFIG_RENDERER_PATH = "scripts/activate_p07_hybrid_external_generation_v1.py"
PLUGIN_SOURCE_ROOT = "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
MANIFEST_SUFFIX = gateway_release.MANIFEST_SUFFIX
ROLLBACK_PLUGIN_RELEASE_DIGEST = (
    "0aa958c2575814e3e2abbfe219a6d651f0bb156c45812f9cd39e51d4da512012"
)

_SHA = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_MODES = {"100644", "100755"}


class PluginArtifactRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PluginArtifactRejected(code)


def canonical(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def digest(domain: str, payload: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical(payload).rstrip()).hexdigest()


def git(source: Path, *arguments: str) -> str:
    completed = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            f"safe.directory={source.resolve()}",
            "-C",
            str(source.resolve()),
            *arguments,
        ],
        capture_output=True,
        check=False,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/usr/sbin"},
        text=True,
        timeout=120,
    )
    require(completed.returncode == 0, "plugin_source_git_rejected")
    return completed.stdout.strip()


def _regular_bytes(path: Path, code: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PluginArtifactRejected(code) from exc
    require(
        stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
        code,
    )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise PluginArtifactRejected(code) from exc


def validate_source(
    source: Path, *, expected_commit: str, expected_tree: str
) -> tuple[str, str]:
    require(
        _COMMIT.fullmatch(expected_commit) is not None
        and _COMMIT.fullmatch(expected_tree) is not None,
        "plugin_source_identity_rejected",
    )
    require(
        git(source, "rev-parse", "HEAD") == expected_commit
        and git(source, "rev-parse", "HEAD^{tree}") == expected_tree
        and not git(source, "status", "--porcelain"),
        "plugin_source_identity_rejected",
    )
    expected_plugin_paths = sorted(
        source_path
        for source_path, _destination, _mode in gateway_release.COMPONENTS
        if source_path.startswith(PLUGIN_SOURCE_ROOT + "/")
    )
    actual_plugin_paths = sorted(
        line
        for line in git(
            source,
            "ls-tree",
            "-r",
            "--name-only",
            "HEAD",
            "--",
            PLUGIN_SOURCE_ROOT,
        ).splitlines()
        if line
    )
    require(
        actual_plugin_paths == expected_plugin_paths,
        "plugin_source_inventory_rejected",
    )
    return expected_commit, expected_tree


def _tracked_file(source: Path, relative: str) -> dict[str, object]:
    pure = PurePosixPath(relative)
    require(
        relative == pure.as_posix()
        and not pure.is_absolute()
        and ".." not in pure.parts,
        "plugin_source_path_rejected",
    )
    fields = git(source, "ls-files", "-s", "--", relative).split()
    require(
        len(fields) == 4
        and fields[0] in _SOURCE_MODES
        and fields[2] == "0"
        and fields[3] == relative,
        "plugin_source_inventory_rejected",
    )
    payload = _regular_bytes(source / relative, "plugin_source_file_rejected")
    require(
        git(source, "rev-parse", f"HEAD:{relative}") == fields[1]
        and git(source, "hash-object", "--", relative) == fields[1],
        "plugin_source_blob_rejected",
    )
    return {
        "git_blob": fields[1],
        "path": relative,
        "sha256": sha256(payload).hexdigest(),
        "size": len(payload),
        "source_mode": fields[0],
    }


def _release_document(files: list[Mapping[str, object]]) -> dict[str, object]:
    release_files = [
        {
            "destination": str(row["destination"]),
            "mode": str(row["target_mode"]),
            "sha256": str(row["sha256"]),
            "size": int(row["size"]),
        }
        for row in files
    ]
    core = {"files": release_files, "schema": gateway_release.SCHEMA}
    release_digest = sha256(
        json.dumps(
            core,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    return {**core, "release_digest": release_digest}


def release_manifest_bytes(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(document), ensure_ascii=True, indent=2, sort_keys=True
    ).encode("ascii") + b"\n"


def _assemble_binding(
    *,
    deploy_commit: str,
    deploy_tree: str,
    source_files: list[Mapping[str, object]],
    release_builder: Mapping[str, object],
    config_renderer: Mapping[str, object],
) -> dict[str, object]:
    release_document = _release_document(source_files)
    release_digest = str(release_document["release_digest"])
    source_semantic = {
        "deploy_commit": deploy_commit,
        "deploy_tree": deploy_tree,
        "files": [dict(row) for row in source_files],
        "release_builder": dict(release_builder),
        "source_id": SOURCE_ID,
    }
    source_identity = {
        **source_semantic,
        "inventory_digest": digest("p07_plugin_source_inventory", source_semantic),
    }
    target_semantic = {
        "file_count": len(source_files),
        "inventory_digest": digest(
            "p07_plugin_release_inventory", release_document["files"]
        ),
        "manifest_sha256": sha256(release_manifest_bytes(release_document)).hexdigest(),
        "release_digest": release_digest,
        "release_schema": gateway_release.SCHEMA,
    }
    config_semantic = {
        "renderer": dict(config_renderer),
        "target_rendered_sha256": sha256(
            render_telegram_config(release_digest)
        ).hexdigest(),
    }
    rollback = {
        "rendered_config_sha256": sha256(
            render_telegram_config(ROLLBACK_PLUGIN_RELEASE_DIGEST)
        ).hexdigest(),
        "release_digest": ROLLBACK_PLUGIN_RELEASE_DIGEST,
    }
    semantic = {
        "config_rendering": {
            **config_semantic,
            "identity_digest": digest("p07_plugin_config_renderer", config_semantic),
        },
        "rollback": rollback,
        "schema": SCHEMA,
        "source": source_identity,
        "target": target_semantic,
    }
    return {
        **semantic,
        "binding_digest": digest("p07_plugin_source_binding", semantic),
    }


def derive_binding(
    source: Path, *, expected_commit: str, expected_tree: str
) -> dict[str, object]:
    deploy_commit, deploy_tree = validate_source(
        source, expected_commit=expected_commit, expected_tree=expected_tree
    )
    source_files: list[dict[str, object]] = []
    for order, (source_path, destination, mode) in enumerate(
        gateway_release.COMPONENTS
    ):
        row = _tracked_file(source, source_path)
        source_files.append(
            {
                **row,
                "destination": destination,
                "order": order,
                "target_mode": f"{mode:04o}",
            }
        )
    return _assemble_binding(
        deploy_commit=deploy_commit,
        deploy_tree=deploy_tree,
        source_files=source_files,
        release_builder=_tracked_file(source, RELEASE_BUILDER_PATH),
        config_renderer=_tracked_file(source, CONFIG_RENDERER_PATH),
    )


def validate_binding(value: Mapping[str, object]) -> dict[str, object]:
    selected = dict(value)
    require(
        set(selected)
        == {
            "binding_digest",
            "config_rendering",
            "rollback",
            "schema",
            "source",
            "target",
        }
        and selected.get("schema") == SCHEMA,
        "plugin_binding_schema_rejected",
    )
    source = selected.get("source")
    target = selected.get("target")
    renderer = selected.get("config_rendering")
    rollback = selected.get("rollback")
    require(
        isinstance(source, Mapping)
        and isinstance(target, Mapping)
        and isinstance(renderer, Mapping)
        and isinstance(rollback, Mapping),
        "plugin_binding_schema_rejected",
    )
    source = dict(source)
    target = dict(target)
    renderer = dict(renderer)
    rollback = dict(rollback)
    require(
        set(source)
        == {
            "deploy_commit",
            "deploy_tree",
            "files",
            "inventory_digest",
            "release_builder",
            "source_id",
        }
        and source.get("source_id") == SOURCE_ID
        and _COMMIT.fullmatch(str(source.get("deploy_commit", ""))) is not None
        and _COMMIT.fullmatch(str(source.get("deploy_tree", ""))) is not None
        and isinstance(source.get("files"), list)
        and isinstance(source.get("release_builder"), Mapping),
        "plugin_binding_source_rejected",
    )
    files = source["files"]
    expected_sources = [row[0] for row in gateway_release.COMPONENTS]
    expected_destinations = [row[1] for row in gateway_release.COMPONENTS]
    require(
        len(files) == len(gateway_release.COMPONENTS),
        "plugin_binding_source_rejected",
    )
    for order, row in enumerate(files):
        require(
            isinstance(row, Mapping)
            and set(row)
            == {
                "destination",
                "git_blob",
                "order",
                "path",
                "sha256",
                "size",
                "source_mode",
                "target_mode",
            }
            and row.get("order") == order
            and row.get("path") == expected_sources[order]
            and row.get("destination") == expected_destinations[order]
            and row.get("source_mode") in _SOURCE_MODES
            and row.get("target_mode") == f"{gateway_release.COMPONENTS[order][2]:04o}"
            and _COMMIT.fullmatch(str(row.get("git_blob", ""))) is not None
            and _SHA.fullmatch(str(row.get("sha256", ""))) is not None
            and type(row.get("size")) is int
            and int(row["size"]) >= 0,
            "plugin_binding_source_rejected",
        )
    release_builder = dict(source["release_builder"])
    require(
        set(release_builder)
        == {"git_blob", "path", "sha256", "size", "source_mode"}
        and release_builder.get("path") == RELEASE_BUILDER_PATH
        and release_builder.get("source_mode") in _SOURCE_MODES
        and _COMMIT.fullmatch(str(release_builder.get("git_blob", ""))) is not None
        and _SHA.fullmatch(str(release_builder.get("sha256", ""))) is not None
        and type(release_builder.get("size")) is int
        and int(release_builder["size"]) >= 0,
        "plugin_binding_source_rejected",
    )
    source_semantic = {
        key: source[key] for key in source if key != "inventory_digest"
    }
    require(
        source.get("inventory_digest")
        == digest("p07_plugin_source_inventory", source_semantic),
        "plugin_binding_source_digest_rejected",
    )
    release_document = _release_document(files)
    expected_target = {
        "file_count": len(files),
        "inventory_digest": digest(
            "p07_plugin_release_inventory", release_document["files"]
        ),
        "manifest_sha256": sha256(release_manifest_bytes(release_document)).hexdigest(),
        "release_digest": release_document["release_digest"],
        "release_schema": gateway_release.SCHEMA,
    }
    require(target == expected_target, "plugin_binding_target_rejected")
    renderer_source = renderer.get("renderer")
    require(
        isinstance(renderer_source, Mapping)
        and set(renderer_source)
        == {"git_blob", "path", "sha256", "size", "source_mode"}
        and renderer_source.get("path") == CONFIG_RENDERER_PATH
        and renderer_source.get("source_mode") in _SOURCE_MODES
        and _COMMIT.fullmatch(str(renderer_source.get("git_blob", ""))) is not None
        and _SHA.fullmatch(str(renderer_source.get("sha256", ""))) is not None
        and type(renderer_source.get("size")) is int
        and int(renderer_source["size"]) >= 0,
        "plugin_binding_config_renderer_rejected",
    )
    config_semantic = {
        "renderer": dict(renderer_source),
        "target_rendered_sha256": sha256(
            render_telegram_config(str(target["release_digest"]))
        ).hexdigest(),
    }
    require(
        renderer
        == {
            **config_semantic,
            "identity_digest": digest("p07_plugin_config_renderer", config_semantic),
        },
        "plugin_binding_config_renderer_rejected",
    )
    require(
        rollback
        == {
            "rendered_config_sha256": sha256(
                render_telegram_config(ROLLBACK_PLUGIN_RELEASE_DIGEST)
            ).hexdigest(),
            "release_digest": ROLLBACK_PLUGIN_RELEASE_DIGEST,
        },
        "plugin_binding_rollback_rejected",
    )
    semantic = {key: selected[key] for key in selected if key != "binding_digest"}
    require(
        selected.get("binding_digest")
        == digest("p07_plugin_source_binding", semantic),
        "plugin_binding_digest_rejected",
    )
    return selected


def binding_projection(value: Mapping[str, object]) -> dict[str, object]:
    selected = validate_binding(value)
    return validate_binding_projection({
        "binding_digest": selected["binding_digest"],
        "config_renderer_identity_digest": selected["config_rendering"][
            "identity_digest"
        ],
        "manifest_sha256": selected["target"]["manifest_sha256"],
        "release_digest": selected["target"]["release_digest"],
        "release_inventory_digest": selected["target"]["inventory_digest"],
        "rollback_config_sha256": selected["rollback"][
            "rendered_config_sha256"
        ],
        "rollback_release_digest": selected["rollback"]["release_digest"],
        "source_id": SOURCE_ID,
        "source_inventory_digest": selected["source"]["inventory_digest"],
    })


def validate_binding_projection(value: Mapping[str, object]) -> dict[str, object]:
    selected = dict(value)
    require(
        set(selected)
        == {
            "binding_digest",
            "config_renderer_identity_digest",
            "manifest_sha256",
            "release_digest",
            "release_inventory_digest",
            "rollback_config_sha256",
            "rollback_release_digest",
            "source_id",
            "source_inventory_digest",
        }
        and selected.get("source_id") == SOURCE_ID
        and all(
            _SHA.fullmatch(str(selected.get(field, ""))) is not None
            for field in (
                "binding_digest",
                "config_renderer_identity_digest",
                "manifest_sha256",
                "release_digest",
                "release_inventory_digest",
                "rollback_config_sha256",
                "rollback_release_digest",
                "source_inventory_digest",
            )
        ),
        "plugin_binding_projection_rejected",
    )
    return selected


@dataclass(frozen=True, slots=True)
class VerifiedPluginArtifact:
    release_digest: str
    files: Mapping[str, bytes]
    binding: Mapping[str, object]


def verify_candidate(
    candidate: Path, binding: Mapping[str, object]
) -> VerifiedPluginArtifact:
    selected = validate_binding(binding)
    target = selected["target"]
    source_files = selected["source"]["files"]
    release_document = _release_document(source_files)
    release_digest = str(target["release_digest"])
    require(
        candidate.name == release_digest
        and candidate.is_absolute(),
        "plugin_artifact_source_binding_rejected",
    )
    try:
        root_metadata = candidate.lstat()
    except OSError as exc:
        raise PluginArtifactRejected("plugin_artifact_source_binding_rejected") from exc
    require(
        stat.S_ISDIR(root_metadata.st_mode)
        and not stat.S_ISLNK(root_metadata.st_mode)
        and stat.S_IMODE(root_metadata.st_mode) == 0o555,
        "plugin_artifact_source_binding_rejected",
    )
    manifest = candidate.parent / f"{release_digest}{MANIFEST_SUFFIX}"
    try:
        manifest_metadata = manifest.lstat()
        manifest_bytes = manifest.read_bytes()
    except OSError as exc:
        raise PluginArtifactRejected("plugin_artifact_manifest_rejected") from exc
    require(
        stat.S_ISREG(manifest_metadata.st_mode)
        and not stat.S_ISLNK(manifest_metadata.st_mode)
        and manifest_metadata.st_nlink == 1
        and stat.S_IMODE(manifest_metadata.st_mode) == 0o444
        and manifest_bytes == release_manifest_bytes(release_document)
        and sha256(manifest_bytes).hexdigest() == target["manifest_sha256"],
        "plugin_artifact_manifest_rejected",
    )
    expected_paths = {str(row["destination"]) for row in source_files}
    actual_paths: set[str] = set()
    for path in candidate.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            continue
        actual_paths.add(path.relative_to(candidate).as_posix())
    require(actual_paths == expected_paths, "plugin_artifact_inventory_rejected")
    payloads: dict[str, bytes] = {}
    for row in source_files:
        relative = str(row["destination"])
        path = candidate / relative
        try:
            metadata = path.lstat()
            payload = path.read_bytes()
        except OSError as exc:
            raise PluginArtifactRejected("plugin_artifact_inventory_rejected") from exc
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == int(str(row["target_mode"]), 8)
            and len(payload) == row["size"]
            and sha256(payload).hexdigest() == row["sha256"],
            "plugin_artifact_inventory_rejected",
        )
        payloads[relative] = payload
    for directory in [candidate, *[p for p in candidate.rglob("*") if p.is_dir()]]:
        metadata = directory.lstat()
        require(
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o555,
            "plugin_artifact_inventory_rejected",
        )
    require(
        digest("p07_plugin_release_inventory", release_document["files"])
        == target["inventory_digest"],
        "plugin_artifact_inventory_rejected",
    )
    return VerifiedPluginArtifact(
        release_digest=release_digest,
        files=payloads,
        binding=selected,
    )


def _chmod_directories(root: Path) -> None:
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for directory in sorted(
        directories, key=lambda item: len(item.parts), reverse=True
    ):
        os.chmod(directory, 0o555)
    os.chmod(root, 0o555)


def materialize_source_bound_release(
    *,
    source: Path,
    output_root: Path,
    binding: Mapping[str, object],
) -> VerifiedPluginArtifact:
    selected = validate_binding(binding)
    require(
        derive_binding(
            source,
            expected_commit=str(selected["source"]["deploy_commit"]),
            expected_tree=str(selected["source"]["deploy_tree"]),
        )
        == selected,
        "plugin_source_binding_replay_rejected",
    )
    require(
        not output_root.exists() and not output_root.is_symlink(),
        "plugin_artifact_output_rejected",
    )
    output_root.mkdir(parents=True, mode=0o750)
    os.chmod(output_root, 0o750)
    release_digest = str(selected["target"]["release_digest"])
    release = output_root / release_digest
    manifest = output_root / f"{release_digest}{MANIFEST_SUFFIX}"
    temporary = Path(tempfile.mkdtemp(prefix=f".{release_digest}.", dir=output_root))
    manifest_temporary = output_root / f".{release_digest}.manifest.tmp"
    try:
        for row in selected["source"]["files"]:
            payload = _regular_bytes(
                source / str(row["path"]), "plugin_source_file_rejected"
            )
            require(
                len(payload) == row["size"]
                and sha256(payload).hexdigest() == row["sha256"],
                "plugin_source_blob_rejected",
            )
            target = temporary / str(row["destination"])
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target.write_bytes(payload)
            os.chmod(target, int(str(row["target_mode"]), 8))
        _chmod_directories(temporary)
        release_document = _release_document(selected["source"]["files"])
        manifest_temporary.write_bytes(release_manifest_bytes(release_document))
        os.chmod(manifest_temporary, 0o444)
        os.replace(temporary, release)
        os.replace(manifest_temporary, manifest)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        try:
            manifest_temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return verify_candidate(release, selected)
