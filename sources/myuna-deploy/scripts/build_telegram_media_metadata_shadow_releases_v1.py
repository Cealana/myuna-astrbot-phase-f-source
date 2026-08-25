#!/usr/bin/env python3
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Mapping


SCHEMA = "myuna.telegram-media-metadata-shadow.content-addressed-release.v1"
MANIFEST_NAME = "RELEASE_MANIFEST.json"
COMPONENTS: Mapping[str, tuple[tuple[str, str, str], ...]] = {
    "auth": (
        (
            "scripts/telegram_media_metadata_shadow_gateway.py",
            "scripts/telegram_media_metadata_shadow_gateway.py",
            "0555",
        ),
        (
            "scripts/telegram_media_metadata_shadow_enqueue.py",
            "telegram_media_metadata_shadow_enqueue.py",
            "0444",
        ),
        (
            "channels/astrbot-telegram/plugin/myuna_telegram_gateway/telegram_media_metadata_protocol.py",
            "telegram_media_metadata_protocol.py",
            "0444",
        ),
        (
            "docs/ADR-049-telegram-media-metadata-shadow-v1.md",
            "docs/ADR-049-telegram-media-metadata-shadow-v1.md",
            "0444",
        ),
    ),
    "worker": (
        (
            "components/telegram-media-metadata-shadow/telegram_media_metadata_shadow/__init__.py",
            "telegram_media_metadata_shadow/__init__.py",
            "0444",
        ),
        (
            "components/telegram-media-metadata-shadow/telegram_media_metadata_shadow/worker.py",
            "telegram_media_metadata_shadow/worker.py",
            "0444",
        ),
        (
            "docs/ADR-049-telegram-media-metadata-shadow-v1.md",
            "docs/ADR-049-telegram-media-metadata-shadow-v1.md",
            "0444",
        ),
    ),
}


class TelegramMediaShadowReleaseRejected(ValueError):
    """Raised when a source or release destination violates the fixed contract."""


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _regular_file(root: Path, relative: str) -> Path:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise TelegramMediaShadowReleaseRejected("release source rejected")
    resolved_root = root.resolve()
    resolved = path.resolve()
    if resolved.parent != resolved_root and resolved_root not in resolved.parents:
        raise TelegramMediaShadowReleaseRejected("release source traversal rejected")
    return path


def build_release_document(repository_root: Path, *, component: str) -> dict[str, object]:
    try:
        specifications = COMPONENTS[component]
    except KeyError:
        raise TelegramMediaShadowReleaseRejected("release component rejected") from None
    files: list[dict[str, str]] = []
    destinations: set[str] = set()
    for source, destination, mode in specifications:
        if destination in destinations or destination.startswith("/") or ".." in Path(destination).parts:
            raise TelegramMediaShadowReleaseRejected("release destination rejected")
        destinations.add(destination)
        content = _regular_file(Path(repository_root), source).read_bytes()
        files.append(
            {
                "destination": destination,
                "mode": mode,
                "sha256": sha256(content).hexdigest(),
                "source": source,
            }
        )
    identity = {"component": component, "files": files, "schema": SCHEMA}
    return {**identity, "release_digest": sha256(_canonical(identity)).hexdigest()}


def materialize_release(repository_root: Path, output_root: Path, *, component: str) -> dict[str, object]:
    repository = Path(repository_root)
    document = build_release_document(repository, component=component)
    target = Path(output_root) / component / str(document["release_digest"])
    if target.exists():
        manifest = target / MANIFEST_NAME
        if manifest.is_symlink() or not manifest.is_file() or manifest.read_bytes() != _canonical(document):
            raise TelegramMediaShadowReleaseRejected("existing release rejected")
        return document
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{document['release_digest']}.", dir=target.parent))
    try:
        for entry in document["files"]:
            destination = temporary / str(entry["destination"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(_regular_file(repository, str(entry["source"])).read_bytes())
            destination.chmod(int(str(entry["mode"]), 8))
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
        component: materialize_release(repository_root, output_root, component=component)
        for component in ("auth", "worker")
    }
