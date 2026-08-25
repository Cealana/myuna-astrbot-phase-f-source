#!/usr/bin/env python3
"""Install a minimal immutable code release for the Owner Profile writer."""

from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from typing import Sequence


_BASE_PATH = Path(__file__).with_name("install_owner_profile_read_code_v1.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "_owner_profile_write_code_installer_base", _BASE_PATH
)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("code_installer_base_unavailable")
base = importlib.util.module_from_spec(_BASE_SPEC)
sys.modules[_BASE_SPEC.name] = base
_BASE_SPEC.loader.exec_module(base)


DESTINATION_ROOT = Path("/opt/myuna/owner-profile-write-v1")
MANIFEST_SCHEMA = "myuna.owner-profile-write-code-release.v1"
COMPONENT = "owner_profile_write_v1"
SOURCE_FILES = (
    "src/myuna_core/__init__.py",
    "src/myuna_core/audit.py",
    "src/myuna_core/authenticated_conversation.py",
    "src/myuna_core/channel_capability.py",
    "src/myuna_core/channel_gateway.py",
    "src/myuna_core/identity.py",
    "src/myuna_core/prompt_budget.py",
    "src/myuna_core/providers/__init__.py",
    "src/myuna_core/providers/audited.py",
    "src/myuna_core/providers/base.py",
    "src/myuna_core/providers/budget.py",
    "src/myuna_core/providers/credentials.py",
    "src/myuna_core/providers/deepseek.py",
    "src/myuna_core/providers/local.py",
    "src/myuna_core/providers/registry.py",
    "src/myuna_core/providers/runtime.py",
    "src/myuna_core/providers/transport.py",
    "src/myuna_core/owner_profile/__init__.py",
    "src/myuna_core/owner_profile/active_selector.py",
    "src/myuna_core/owner_profile/approval.py",
    "src/myuna_core/owner_profile/client.py",
    "src/myuna_core/owner_profile/contracts.py",
    "src/myuna_core/owner_profile/lifecycle.py",
    "src/myuna_core/owner_profile/lifecycle_ledger.py",
    "src/myuna_core/owner_profile/loader.py",
    "src/myuna_core/owner_profile/projection.py",
    "src/myuna_core/owner_profile/protocol.py",
    "src/myuna_core/owner_profile/retrieval.py",
    "src/myuna_core/owner_profile/write_bootstrap.py",
    "src/myuna_core/owner_profile/write_candidate.py",
    "src/myuna_core/owner_profile/write_intent.py",
    "src/myuna_core/owner_profile/write_protocol.py",
    "src/myuna_core/owner_profile/write_publish.py",
    "src/myuna_core/owner_profile/write_runtime.py",
    "src/myuna_core/owner_profile/write_socket_worker.py",
    "src/myuna_core/owner_profile/write_store.py",
    "deploy/myuna-owner-profile-write-v1.service",
    "deploy/myuna-owner-profile-write-v1.socket",
    "deploy/myuna-owner-profile-write-v1.tmpfiles.conf",
)

base.DESTINATION_ROOT = DESTINATION_ROOT
base.MANIFEST_SCHEMA = MANIFEST_SCHEMA
base.SOURCE_FILES = SOURCE_FILES

CodeReleaseBundle = base.CodeReleaseBundle
OwnerProfileCodeInstallError = base.OwnerProfileCodeInstallError


def build_code_bundle(source_root: Path, *, source_commit: str) -> CodeReleaseBundle:
    if (
        not isinstance(source_root, Path)
        or not source_root.is_absolute()
        or source_root.is_symlink()
        or not source_root.is_dir()
        or not isinstance(source_commit, str)
        or base._COMMIT.fullmatch(source_commit) is None
    ):
        raise base._reject("code_source_rejected")
    payloads = tuple(
        (relative, base._source_file(source_root, relative))
        for relative in SOURCE_FILES
    )
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "component": COMPONENT,
        "source_commit": source_commit,
        "files": [
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": sha256(payload).hexdigest(),
                "mode": "0440",
            }
            for relative, payload in payloads
        ],
    }
    manifest_bytes = base._canonical(manifest)
    return CodeReleaseBundle(
        source_commit=source_commit,
        release_sha256=sha256(manifest_bytes).hexdigest(),
        manifest_bytes=manifest_bytes,
        payloads=payloads,
    )


def validate_installed_code_release(
    release_sha256: str,
    *,
    destination_root: Path = DESTINATION_ROOT,
    uid: int = 0,
    gid: int,
) -> dict[str, object]:
    if base._DIGEST.fullmatch(release_sha256) is None:
        raise base._reject("code_release_identity_rejected")
    if not destination_root.is_absolute() or destination_root.is_symlink():
        raise base._reject("code_install_root_rejected")
    release = destination_root / "releases" / release_sha256
    manifest_path = release / base.MANIFEST_FILENAME
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise base._reject("code_release_content_rejected") from exc
    if (
        sha256(manifest_bytes).hexdigest() != release_sha256
        or not isinstance(manifest, dict)
        or manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("component") != COMPONENT
        or base._COMMIT.fullmatch(str(manifest.get("source_commit", ""))) is None
        or not isinstance(manifest.get("files"), list)
    ):
        raise base._reject("code_release_identity_rejected")
    records = manifest["files"]
    if any(
        not isinstance(record, dict)
        or not isinstance(record.get("path"), str)
        for record in records
    ):
        raise base._reject("code_release_content_rejected")
    expected_records = {record["path"]: record for record in records}
    if (
        len(expected_records) != len(records)
        or set(expected_records) != set(SOURCE_FILES)
    ):
        raise base._reject("code_release_file_set_rejected")
    expected_files = {base.MANIFEST_FILENAME, *SOURCE_FILES}
    expected_directories = base._expected_directories()
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    try:
        for entry in (release, *release.rglob("*")):
            metadata = entry.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != uid
                or metadata.st_gid != gid
            ):
                raise base._reject("code_release_metadata_rejected")
            relative = entry.relative_to(release).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != base.RELEASE_MODE:
                    raise base._reject("code_release_metadata_rejected")
                if entry != release:
                    actual_directories.add(relative)
            elif stat.S_ISREG(metadata.st_mode):
                if (
                    stat.S_IMODE(metadata.st_mode) != base.FILE_MODE
                    or metadata.st_nlink != 1
                ):
                    raise base._reject("code_release_metadata_rejected")
                actual_files.add(relative)
            else:
                raise base._reject("code_release_metadata_rejected")
    except OwnerProfileCodeInstallError:
        raise
    except OSError as exc:
        raise base._reject("code_install_unavailable") from exc
    if actual_files != expected_files or actual_directories != expected_directories:
        raise base._reject("code_release_file_set_rejected")
    for relative, record in expected_records.items():
        if (
            set(record) != {"bytes", "mode", "path", "sha256"}
            or record["mode"] != "0440"
            or record["path"] != relative
            or not isinstance(record["bytes"], int)
            or record["bytes"] < 1
            or base._DIGEST.fullmatch(str(record["sha256"])) is None
        ):
            raise base._reject("code_release_content_rejected")
        try:
            payload = (release / relative).read_bytes()
        except OSError as exc:
            raise base._reject("code_install_unavailable") from exc
        if len(payload) != record["bytes"] or sha256(payload).hexdigest() != record["sha256"]:
            raise base._reject("code_release_content_rejected")
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    arguments = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise base._reject("must_run_as_root")
        base.verify_git_source(
            arguments.source_root,
            expected_commit=arguments.source_commit,
        )
        bundle = build_code_bundle(
            arguments.source_root,
            source_commit=arguments.source_commit,
        )
        gid = base._service_gid()
        _, created = base.install_code_release(
            bundle,
            destination_root=DESTINATION_ROOT,
            gid=gid,
        )
        validate_installed_code_release(bundle.release_sha256, gid=gid)
        print(
            json.dumps(
                {
                    "status": "WRITE_CODE_RELEASE_INSTALLED_INACTIVE",
                    "created": created,
                    "code_release_sha256": bundle.release_sha256,
                    "source_commit": bundle.source_commit,
                    "profile_content_present": False,
                    "service_changed": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except OwnerProfileCodeInstallError as exc:
        print(
            json.dumps(
                {
                    "status": "REJECTED",
                    "error_category": str(exc),
                    "profile_content_present": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
