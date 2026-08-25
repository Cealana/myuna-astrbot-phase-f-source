#!/usr/bin/env python3
"""Install one verified Host Cold-Boot release into the fixed WSL root."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile


SCHEMA = "myuna.host-cold-boot-release.v1"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
DESTINATION_ROOT = Path("/opt/myuna/host-cold-boot/releases")
ALLOWED_SOURCE_ROOTS = (Path("/mnt/c"), Path("/srv/myuna/staging"))
EXPECTED_FILES = {
    "ADR-037-host-cold-boot-recovery-v1.md",
    "Install-MyunaHostColdBootRelease.ps1",
    "Install-MyunaHostColdBootTask.ps1",
    "Invoke-MyunaHostColdBootInstall.ps1",
    "MANIFEST.json",
    "Start-MyunaHostColdBoot.ps1",
    "Start-MyunaHostColdBoot.vbs",
    "Start-PandaFanAutoconnect.ps1",
    "Test-MyunaHostColdBoot.ps1",
    "Test-MyunaAutologonState.ps1",
    "host_cold_boot_readiness_v1.py",
    "install_host_cold_boot_release_v1.py",
}


class InstallRejected(RuntimeError):
    pass


def canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ) + "\n"


def inside(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def verify_release(
    source: Path,
    digest: str,
    *,
    allowed_source_roots: tuple[Path, ...] = ALLOWED_SOURCE_ROOTS,
    require_root_owned: bool = False,
) -> dict[str, object]:
    if DIGEST.fullmatch(digest) is None:
        raise InstallRejected("release_digest_rejected")
    resolved = source.resolve(strict=True)
    if source.is_symlink() or not resolved.is_dir() or resolved.name != digest:
        raise InstallRejected("release_source_rejected")
    if not inside(resolved, tuple(root.resolve() for root in allowed_source_roots)):
        raise InstallRejected("release_source_boundary_rejected")
    actual = {path.name for path in resolved.iterdir()}
    if actual != EXPECTED_FILES or any(path.is_symlink() for path in resolved.iterdir()):
        raise InstallRejected("release_file_set_rejected")
    if stat.S_IMODE(resolved.stat().st_mode) != 0o555:
        raise InstallRejected("release_directory_mode_rejected")
    if require_root_owned and (
        resolved.stat().st_uid != 0 or resolved.stat().st_gid != 0
    ):
        raise InstallRejected("release_ownership_rejected")
    manifest_bytes = (resolved / "MANIFEST.json").read_bytes()
    if sha256(manifest_bytes).hexdigest() != digest:
        raise InstallRejected("release_manifest_digest_rejected")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallRejected("release_manifest_decode_rejected") from exc
    if manifest.get("schema") != SCHEMA or set(manifest) != {
        "files",
        "schema",
        "source_commit",
    }:
        raise InstallRejected("release_manifest_shape_rejected")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise InstallRejected("release_manifest_files_rejected")
    expected_manifest_paths = EXPECTED_FILES - {"MANIFEST.json"}
    if {entry.get("path") for entry in entries if isinstance(entry, dict)} != expected_manifest_paths:
        raise InstallRejected("release_manifest_paths_rejected")
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"mode", "path", "sha256", "size"}:
            raise InstallRejected("release_manifest_entry_rejected")
        path = resolved / entry["path"]
        payload = path.read_bytes()
        if len(payload) != entry["size"] or sha256(payload).hexdigest() != entry["sha256"]:
            raise InstallRejected("release_payload_rejected")
        if entry["mode"] not in {"0444", "0555"}:
            raise InstallRejected("release_mode_rejected")
        metadata = path.stat()
        if stat.S_IMODE(metadata.st_mode) != int(entry["mode"], 8):
            raise InstallRejected("release_file_mode_rejected")
        if require_root_owned and (metadata.st_uid != 0 or metadata.st_gid != 0):
            raise InstallRejected("release_ownership_rejected")
    manifest_metadata = (resolved / "MANIFEST.json").stat()
    if stat.S_IMODE(manifest_metadata.st_mode) != 0o444:
        raise InstallRejected("release_file_mode_rejected")
    if require_root_owned and (
        manifest_metadata.st_uid != 0 or manifest_metadata.st_gid != 0
    ):
        raise InstallRejected("release_ownership_rejected")
    return manifest


def install(
    source: Path,
    digest: str,
    *,
    destination_root: Path = DESTINATION_ROOT,
    allowed_source_roots: tuple[Path, ...] = ALLOWED_SOURCE_ROOTS,
) -> tuple[Path, bool]:
    manifest = verify_release(
        source,
        digest,
        allowed_source_roots=allowed_source_roots,
    )
    source = source.resolve(strict=True)
    if destination_root.is_symlink():
        raise InstallRejected("destination_root_rejected")
    destination_root.mkdir(parents=True, exist_ok=True)
    os.chown(destination_root, 0, 0)
    os.chmod(destination_root, 0o755)
    destination = destination_root / digest
    if destination.exists():
        verify_release(
            destination,
            digest,
            allowed_source_roots=(destination_root,),
            require_root_owned=True,
        )
        return destination, False
    temporary = Path(tempfile.mkdtemp(prefix=f".{digest}.install-", dir=destination_root))
    try:
        modes = {entry["path"]: int(entry["mode"], 8) for entry in manifest["files"]}
        for source_file in source.iterdir():
            target = temporary / source_file.name
            shutil.copyfile(source_file, target)
            os.chown(target, 0, 0)
            os.chmod(target, 0o444 if target.name == "MANIFEST.json" else modes[target.name])
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o555)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    verify_release(
        destination,
        digest,
        allowed_source_roots=(destination_root,),
        require_root_owned=True,
    )
    return destination, True


def main() -> int:
    if os.geteuid() != 0:
        raise InstallRejected("must_run_as_root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("staged_release", type=Path)
    parser.add_argument("release_digest")
    args = parser.parse_args()
    if args.verify_only:
        verify_release(
            args.staged_release,
            args.release_digest,
            allowed_source_roots=(DESTINATION_ROOT,),
            require_root_owned=True,
        )
        print(
            canonical(
                {
                    "release": args.release_digest,
                    "status": "RELEASE_VERIFIED_NO_MUTATION",
                }
            ),
            end="",
        )
        return 0
    destination, created = install(args.staged_release, args.release_digest)
    print(
        canonical(
            {
                "created": created,
                "release": destination.name,
                "status": "INSTALLED_INACTIVE",
            }
        ),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
