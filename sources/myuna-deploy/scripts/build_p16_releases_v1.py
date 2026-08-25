#!/usr/bin/env python3
"""Build deterministic P16 overlay releases without selecting them."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import tempfile


SCHEMA = "myuna.p16-release.v1"
CORE_INSTALLATION_RECEIPT_SCHEMA = "myuna.p16-core-installation-receipt.v1"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SOURCE_BYTES = 2 * 1024 * 1024

_CORE_OVERLAYS = {
    "src/myuna_core/conversation.py": "src/myuna_core/conversation.py",
    "src/myuna_core/degradation_bridge.py": "src/myuna_core/degradation_bridge.py",
    "src/myuna_core/degradation_http.py": "src/myuna_core/degradation_http.py",
    "src/myuna_core/external_context/live.py": "src/myuna_core/external_context/live.py",
    "src/myuna_core/http_api.py": "src/myuna_core/http_api.py",
    "src/myuna_core/user_visible_fault.py": "src/myuna_core/user_visible_fault.py",
    "tests/test_degradation_bridge.py": "tests/test_degradation_bridge.py",
    "tests/test_p16_failure_provenance_v1.py": "tests/test_p16_failure_provenance_v1.py",
    "fixtures/natural_degradation_r2a_core_bridge_golden.json": (
        "fixtures/natural_degradation_r2a_core_bridge_golden.json"
    ),
}
_GATEWAY_SHARED = {
    "runtime/degradation_shadow_enqueue.py": "scripts/degradation_shadow_enqueue.py",
    "runtime/fault_incident_v1.py": "scripts/fault_incident_v1.py",
    "runtime/gateway_degradation_protocol.py": (
        "scripts/gateway_degradation_protocol.py"
    ),
    "runtime/gateway_enqueue.py": "scripts/gateway_enqueue.py",
    "runtime/gateway_post_reply.py": "scripts/gateway_post_reply.py",
    "runtime/incident_history_runtime_adapter_v1.py": (
        "scripts/incident_history_runtime_adapter_v1.py"
    ),
    "runtime/incident_history_v1.py": "scripts/incident_history_v1.py",
    "runtime/user_visible_fault_v1.py": "scripts/user_visible_fault_v1.py",
}
_DIAGNOSTICS = {
    "fault_diagnostics_collector_v1.py": "scripts/fault_diagnostics_collector_v1.py",
    "fault_diagnostics_v1.py": "scripts/fault_diagnostics_v1.py",
    "fault_incident_v1.py": "scripts/fault_incident_v1.py",
    "incident_history_v1.py": "scripts/incident_history_v1.py",
    "myuna_diagnose.py": "scripts/myuna_diagnose.py",
}


def _read_source(path: Path) -> bytes:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file():
        raise ValueError("release source is not a regular file")
    if metadata.st_size <= 0 or metadata.st_size > _MAX_SOURCE_BYTES:
        raise ValueError("release source size is invalid")
    return path.read_bytes()


def _digest(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _tree_digest(root: Path) -> tuple[str, int]:
    files = [
        path
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
        if path.is_file() and not path.is_symlink()
    ]
    combined = sha256()
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        combined.update(len(relative).to_bytes(4, "big"))
        combined.update(relative)
        combined.update(len(payload).to_bytes(8, "big"))
        combined.update(payload)
    return combined.hexdigest(), len(files)


def _validate_commit(value: str) -> str:
    if _HEX40.fullmatch(value) is None:
        raise ValueError("source commit is invalid")
    return value


def _validate_base(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_dir():
        raise ValueError("base release is invalid")
    if _HEX64.fullmatch(resolved.name) is None:
        raise ValueError("base release digest is invalid")
    return resolved


def _manifest(
    kind: str,
    *,
    base: Path | None,
    overlays: dict[str, str],
    source_root: Path,
    source_commit: str,
) -> tuple[dict[str, object], str]:
    files: dict[str, dict[str, object]] = {}
    for destination, source in sorted(overlays.items()):
        payload = _read_source(source_root / source)
        files[destination] = {"sha256": _digest(payload), "size": len(payload)}
    unsigned: dict[str, object] = {
        "schema": SCHEMA,
        "kind": kind,
        "base_release_digest": base.name if base is not None else None,
        "source_commit": _validate_commit(source_commit),
        "files": files,
    }
    release_digest = _digest(_canonical(unsigned))
    return {**unsigned, "release_digest": release_digest}, release_digest


def _writable_directories(root: Path) -> dict[Path, int]:
    modes: dict[Path, int] = {}
    for path in [root, *root.rglob("*")]:
        if path.is_dir() and not path.is_symlink():
            mode = path.stat().st_mode & 0o777
            modes[path] = mode
            path.chmod(mode | 0o200)
    return modes


def _remove_temporary_tree(root: Path) -> None:
    """Remove only the builder-owned stage, including an immutable Core copy."""

    if not root.exists():
        return
    for path in [root, *root.rglob("*")]:
        if path.is_dir() and not path.is_symlink():
            path.chmod((path.stat().st_mode & 0o777) | 0o700)
    shutil.rmtree(root)


def _materialize(
    kind: str,
    *,
    base: Path | None,
    overlays: dict[str, str],
    source_root: Path,
    source_commit: str,
    output_root: Path,
) -> dict[str, object]:
    manifest, release_digest = _manifest(
        kind,
        base=base,
        overlays=overlays,
        source_root=source_root,
        source_commit=source_commit,
    )
    expected_manifest = _canonical(manifest) + b"\n"
    component_root = output_root / kind
    destination = component_root / release_digest
    if kind != "core" and destination.exists():
        installed = destination / "P16_MANIFEST.json"
        if installed.is_file() and not installed.is_symlink():
            if installed.read_bytes() == expected_manifest:
                return {"kind": kind, "release": str(destination), "reused": True}
        raise ValueError("existing P16 release does not match")
    component_root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".p16-build-", dir=component_root))
    try:
        if base is not None:
            _remove_temporary_tree(temporary)
            shutil.copytree(base, temporary, symlinks=True)
        directory_modes = _writable_directories(temporary)
        for relative, source in overlays.items():
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            previous_mode = (
                target.stat().st_mode & 0o777
                if target.exists() and not target.is_symlink()
                else 0o440
            )
            if target.is_symlink() or (target.exists() and not target.is_file()):
                raise ValueError("overlay destination is unsafe")
            payload = _read_source(source_root / source)
            target.write_bytes(payload)
            target.chmod(0o550 if relative == "myuna_diagnose.py" else previous_mode)
        manifest_path = temporary / "P16_MANIFEST.json"
        manifest_path.write_bytes(expected_manifest)
        manifest_path.chmod(0o440)
        if kind == "core":
            receipt = {
                "schema": CORE_INSTALLATION_RECEIPT_SCHEMA,
                "base_release_digest": base.name if base is not None else None,
                "source_commit": source_commit,
                "overlay_manifest_sha256": _digest(expected_manifest),
                "content_free": True,
                "private_content_read": False,
            }
            receipt_path = temporary / "P16_INSTALLATION_RECEIPT.json"
            receipt_path.write_bytes(_canonical(receipt) + b"\n")
            receipt_path.chmod(0o440)
        for path, mode in sorted(
            directory_modes.items(),
            key=lambda item: len(item[0].parts),
            reverse=True,
        ):
            path.chmod(mode)
        if base is None:
            temporary.chmod(0o550)
        if kind == "core":
            for path in [temporary, *temporary.rglob("*")]:
                if path.is_symlink():
                    raise ValueError("Core release contains a symlink")
                if not path.is_dir() and not path.is_file():
                    raise ValueError("Core release contains a non-regular entry")
                path.chmod(0o550 if path.is_dir() else 0o440)
            tree_digest, _ = _tree_digest(temporary)
            destination = component_root / tree_digest
        if destination.exists():
            installed = destination / "P16_MANIFEST.json"
            if installed.is_file() and not installed.is_symlink():
                if installed.read_bytes() == expected_manifest:
                    _remove_temporary_tree(temporary)
                    return {"kind": kind, "release": str(destination), "reused": True}
            raise ValueError("existing P16 release does not match")
        os.replace(temporary, destination)
    except BaseException:
        try:
            _remove_temporary_tree(temporary)
        except OSError:
            pass
        raise
    return {"kind": kind, "release": str(destination), "reused": False}


def build_releases(
    *,
    core_base: Path,
    qq_base: Path,
    telegram_base: Path,
    core_source_root: Path,
    deploy_source_root: Path,
    core_source_commit: str,
    deploy_source_commit: str,
    output_root: Path,
) -> dict[str, object]:
    core_base = _validate_base(core_base)
    qq_base = _validate_base(qq_base)
    telegram_base = _validate_base(telegram_base)
    releases = [
        _materialize(
            "core",
            base=core_base,
            overlays=_CORE_OVERLAYS,
            source_root=core_source_root,
            source_commit=core_source_commit,
            output_root=output_root,
        ),
        _materialize(
            "qq",
            base=qq_base,
            overlays={
                **_GATEWAY_SHARED,
                "runtime/qq_owner_runtime_gateway.py": (
                    "scripts/qq_owner_runtime_gateway.py"
                ),
            },
            source_root=deploy_source_root,
            source_commit=deploy_source_commit,
            output_root=output_root,
        ),
        _materialize(
            "telegram",
            base=telegram_base,
            overlays={
                **_GATEWAY_SHARED,
                "runtime/p07_d_runtime_readiness.py": (
                    "scripts/p07_d_runtime_readiness.py"
                ),
                "runtime/telegram_owner_runtime_gateway.py": (
                    "scripts/telegram_owner_runtime_gateway.py"
                ),
            },
            source_root=deploy_source_root,
            source_commit=deploy_source_commit,
            output_root=output_root,
        ),
        _materialize(
            "diagnostics",
            base=None,
            overlays=_DIAGNOSTICS,
            source_root=deploy_source_root,
            source_commit=deploy_source_commit,
            output_root=output_root,
        ),
    ]
    return {"schema": SCHEMA, "result": "built", "releases": releases}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-base", type=Path, required=True)
    parser.add_argument("--qq-base", type=Path, required=True)
    parser.add_argument("--telegram-base", type=Path, required=True)
    parser.add_argument("--core-source-root", type=Path, required=True)
    parser.add_argument("--deploy-source-root", type=Path, required=True)
    parser.add_argument("--core-source-commit", required=True)
    parser.add_argument("--deploy-source-commit", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = build_releases(**vars(args))
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
