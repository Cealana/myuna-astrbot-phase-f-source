#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Mapping


SCHEMA = "myuna.vision-decoder.content-addressed-release.v1"
MANIFEST_NAME = "RELEASE_MANIFEST.json"

COMPONENTS: Mapping[str, tuple[tuple[str, str], ...]] = {
    "worker": (
        (
            "components/vision-decoder-worker/myuna_media_decoder/__init__.py",
            "myuna_media_decoder/__init__.py",
        ),
        (
            "components/vision-decoder-worker/myuna_media_decoder/protocol.py",
            "myuna_media_decoder/protocol.py",
        ),
        (
            "components/vision-decoder-worker/myuna_media_decoder/worker.py",
            "myuna_media_decoder/worker.py",
        ),
        ("docs/ADR-047-vision-decoder-worker-v1.md", "docs/ADR-047-vision-decoder-worker-v1.md"),
    ),
    "probe": (
        ("scripts/vision_media_types.py", "vision_media_types.py"),
        ("scripts/pillow_media_probe.py", "pillow_media_probe.py"),
        (
            "config/vision-media-probe-pillow-v1.json",
            "config/vision-media-probe-pillow-v1.json",
        ),
    ),
}


class VisionDecoderReleaseRejected(ValueError):
    """Raised when a release source or destination violates the fixed contract."""


def _canonical(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _regular_file(root: Path, relative: str) -> Path:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise VisionDecoderReleaseRejected("release source path rejected")
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    if resolved_path.parent != resolved_root and resolved_root not in resolved_path.parents:
        raise VisionDecoderReleaseRejected("release source traversal rejected")
    return path


def build_release_document(repository_root: Path, *, component: str) -> dict[str, object]:
    root = Path(repository_root)
    try:
        specs = COMPONENTS[component]
    except KeyError:
        raise VisionDecoderReleaseRejected("release component rejected") from None
    files: list[dict[str, object]] = []
    seen: set[str] = set()
    for source, destination in specs:
        if destination in seen or destination.startswith("/") or ".." in Path(destination).parts:
            raise VisionDecoderReleaseRejected("release destination rejected")
        seen.add(destination)
        content = _regular_file(root, source).read_bytes()
        files.append(
            {
                "destination": destination,
                "mode": "0444",
                "sha256": _sha256(content),
                "source": source,
            }
        )
    identity = {
        "component": component,
        "files": files,
        "schema": SCHEMA,
    }
    return {
        **identity,
        "release_digest": _sha256(_canonical(identity)),
    }


def materialize_release(
    repository_root: Path,
    output_root: Path,
    *,
    component: str,
) -> dict[str, object]:
    repository = Path(repository_root)
    root = Path(output_root)
    document = build_release_document(repository, component=component)
    digest = str(document["release_digest"])
    target = root / component / digest
    if target.exists():
        manifest = target / MANIFEST_NAME
        if manifest.is_symlink() or not manifest.is_file() or manifest.read_bytes() != _canonical(document):
            raise VisionDecoderReleaseRejected("existing release rejected")
        return document
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{digest}.", dir=target.parent))
    try:
        for entry in document["files"]:
            assert isinstance(entry, dict)
            destination = temporary / str(entry["destination"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(_regular_file(repository, str(entry["source"])).read_bytes())
            destination.chmod(0o444)
        manifest = temporary / MANIFEST_NAME
        manifest.write_bytes(_canonical(document))
        manifest.chmod(0o444)
        for directory, _, _ in os.walk(temporary, topdown=False):
            Path(directory).chmod(0o555)
        temporary.rename(target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return document


def build_pair(repository_root: Path, output_root: Path) -> dict[str, object]:
    return {
        component: materialize_release(
            repository_root,
            output_root,
            component=component,
        )
        for component in ("worker", "probe")
    }

