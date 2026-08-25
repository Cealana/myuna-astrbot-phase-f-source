#!/usr/bin/env python3
"""Build the content-addressed Host Cold-Boot Recovery v1 release."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import tempfile


SCHEMA = "myuna.host-cold-boot-release.v1"
FILES = {
    "host_cold_boot_readiness_v1.py": (
        "scripts/host_cold_boot_readiness_v1.py",
        0o555,
    ),
    "Start-MyunaHostColdBoot.ps1": (
        "scripts/windows/Start-MyunaHostColdBoot.ps1",
        0o444,
    ),
    "Start-MyunaHostColdBoot.vbs": (
        "scripts/windows/Start-MyunaHostColdBoot.vbs",
        0o444,
    ),
    "Start-PandaFanAutoconnect.ps1": (
        "scripts/windows/Start-PandaFanAutoconnect.ps1",
        0o444,
    ),
    "Test-MyunaHostColdBoot.ps1": (
        "scripts/windows/Test-MyunaHostColdBoot.ps1",
        0o444,
    ),
    "Test-MyunaAutologonState.ps1": (
        "scripts/windows/Test-MyunaAutologonState.ps1",
        0o444,
    ),
    "Install-MyunaHostColdBootTask.ps1": (
        "scripts/windows/Install-MyunaHostColdBootTask.ps1",
        0o444,
    ),
    "Install-MyunaHostColdBootRelease.ps1": (
        "scripts/windows/Install-MyunaHostColdBootRelease.ps1",
        0o444,
    ),
    "Invoke-MyunaHostColdBootInstall.ps1": (
        "scripts/windows/Invoke-MyunaHostColdBootInstall.ps1",
        0o444,
    ),
    "install_host_cold_boot_release_v1.py": (
        "scripts/install_host_cold_boot_release_v1.py",
        0o555,
    ),
    "ADR-037-host-cold-boot-recovery-v1.md": (
        "docs/ADR-037-host-cold-boot-recovery-v1.md",
        0o444,
    ),
}
DIGEST = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def build(source_root: Path, output_root: Path, source_commit: str) -> Path:
    if DIGEST.fullmatch(source_commit) is None:
        raise ValueError("source_commit_rejected")
    entries = []
    payloads: dict[str, tuple[bytes, int]] = {}
    for destination, (source_name, mode) in sorted(FILES.items()):
        source = source_root / source_name
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"source_rejected:{source_name}")
        payload = source.read_bytes()
        payloads[destination] = (payload, mode)
        entries.append(
            {
                "mode": f"{mode:04o}",
                "path": destination,
                "sha256": sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    manifest = canonical(
        {
            "files": entries,
            "schema": SCHEMA,
            "source_commit": source_commit,
        }
    )
    release_digest = sha256(manifest).hexdigest()
    release = output_root / release_digest
    if release.exists():
        if release.is_symlink() or not release.is_dir():
            raise ValueError("existing_release_rejected")
        if (release / "MANIFEST.json").read_bytes() != manifest:
            raise ValueError("existing_manifest_rejected")
        return release
    output_root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".host-cold-boot-", dir=output_root))
    try:
        for destination, (payload, mode) in payloads.items():
            target = temporary / destination
            target.write_bytes(payload)
            target.chmod(mode)
        target_manifest = temporary / "MANIFEST.json"
        target_manifest.write_bytes(manifest)
        target_manifest.chmod(0o444)
        temporary.chmod(0o555)
        os.replace(temporary, release)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return release


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_root", type=Path)
    parser.add_argument("output_root", type=Path)
    parser.add_argument("source_commit")
    args = parser.parse_args()
    release = build(args.source_root.resolve(), args.output_root.resolve(), args.source_commit)
    print(canonical({"release_digest": release.name, "status": "built"}).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
