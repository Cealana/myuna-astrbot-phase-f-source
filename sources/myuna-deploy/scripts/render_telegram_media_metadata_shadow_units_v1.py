#!/usr/bin/env python3
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re


SCHEMA = "myuna.telegram-media-metadata-shadow.rendered-units.v1"
CORE = "@CORE_RELEASE_ROOT@"
AUTH = "@AUTH_RELEASE_ROOT@"
SHADOW = "@SHADOW_RELEASE_ROOT@"
CORE_PREFIX = "/srv/myuna/releases/core"
AUTH_PREFIX = "/opt/myuna/telegram-media-auth/releases"
SHADOW_PREFIX = "/opt/myuna/telegram-media-metadata-shadow/releases"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_UNRESOLVED = re.compile(r"@[A-Za-z][A-Za-z0-9_]*@")
_MUTABLE = re.compile(r"/(?:current|latest)(?:/|$)")


class TelegramMediaShadowUnitRejected(ValueError):
    """Raised when a unit template cannot be bound to exact releases."""


def _digest(value: str) -> str:
    if _DIGEST.fullmatch(value) is None:
        raise TelegramMediaShadowUnitRejected("release digest rejected")
    return value


def _text(content: bytes) -> str:
    if not isinstance(content, bytes) or content.startswith(b"\xef\xbb\xbf") or b"\x00" in content:
        raise TelegramMediaShadowUnitRejected("unit encoding rejected")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise TelegramMediaShadowUnitRejected("unit encoding rejected") from None
    if "\r" in text or not text.endswith("\n"):
        raise TelegramMediaShadowUnitRejected("unit newline rejected")
    if "/srv/myuna/repos/" in text or "/usr/local/" in text or _MUTABLE.search(text):
        raise TelegramMediaShadowUnitRejected("mutable unit path rejected")
    return text


def render_unit(content: bytes, *, kind: str, core_digest: str, auth_digest: str, worker_digest: str) -> bytes:
    text = _text(content)
    core_root = f"{CORE_PREFIX}/{_digest(core_digest)}"
    auth_root = f"{AUTH_PREFIX}/{_digest(auth_digest)}"
    shadow_root = f"{SHADOW_PREFIX}/{_digest(worker_digest)}"
    expected_counts = {
        "auth_socket": {CORE: 0, AUTH: 1, SHADOW: 0},
        "auth_service": {CORE: 1, AUTH: 3, SHADOW: 0},
        "worker_socket": {CORE: 0, AUTH: 0, SHADOW: 1},
        "worker_service": {CORE: 0, AUTH: 0, SHADOW: 2},
    }
    if kind not in expected_counts:
        raise TelegramMediaShadowUnitRejected("unit kind rejected")
    for placeholder, count in expected_counts[kind].items():
        if text.count(placeholder) != count:
            raise TelegramMediaShadowUnitRejected("unit placeholder count rejected")
    rendered = text.replace(CORE, core_root).replace(AUTH, auth_root).replace(SHADOW, shadow_root)
    if _UNRESOLVED.search(rendered) or "/srv/myuna/repos/" in rendered or _MUTABLE.search(rendered):
        raise TelegramMediaShadowUnitRejected("rendered unit rejected")
    if kind == "auth_service":
        required = (
            f"ExecStart=/usr/bin/python3 {auth_root}/scripts/telegram_media_metadata_shadow_gateway.py",
            f"Environment=PYTHONPATH={core_root}/src:{auth_root}",
        )
        if any(line not in rendered.splitlines() for line in required):
            raise TelegramMediaShadowUnitRejected("auth service binding rejected")
    if kind == "worker_service":
        required = (
            f"Environment=PYTHONPATH={shadow_root}",
            "ExecStart=/usr/bin/python3 -m telegram_media_metadata_shadow.worker --trace /var/log/myuna-telegram-media-metadata-shadow/trace.jsonl",
        )
        if any(line not in rendered.splitlines() for line in required):
            raise TelegramMediaShadowUnitRejected("worker service binding rejected")
    return rendered.encode("utf-8")


def render_repository_units(repository_root: Path, *, core_digest: str, auth_digest: str, worker_digest: str) -> dict[str, bytes]:
    root = Path(repository_root)
    names = {
        "myuna-telegram-media-auth-shadow-v1.socket": "auth_socket",
        "myuna-telegram-media-auth-shadow-v1.service": "auth_service",
        "myuna-telegram-media-metadata-shadow-v1.socket": "worker_socket",
        "myuna-telegram-media-metadata-shadow-v1.service": "worker_service",
    }
    rendered: dict[str, bytes] = {}
    for name, kind in names.items():
        path = root / "systemd" / name
        if path.is_symlink() or not path.is_file():
            raise TelegramMediaShadowUnitRejected("unit template rejected")
        rendered[name] = render_unit(
            path.read_bytes(),
            kind=kind,
            core_digest=core_digest,
            auth_digest=auth_digest,
            worker_digest=worker_digest,
        )
    return rendered


def build_evidence(repository_root: Path, *, core_digest: str, auth_digest: str, worker_digest: str) -> dict[str, object]:
    units = render_repository_units(
        repository_root,
        core_digest=core_digest,
        auth_digest=auth_digest,
        worker_digest=worker_digest,
    )
    return {
        "auth_release_root": f"{AUTH_PREFIX}/{_digest(auth_digest)}",
        "core_release_root": f"{CORE_PREFIX}/{_digest(core_digest)}",
        "schema": SCHEMA,
        "shadow_release_root": f"{SHADOW_PREFIX}/{_digest(worker_digest)}",
        "units": {
            name: {
                "inactive_install_target": f"/etc/systemd/system/{name}",
                "rendered_sha256": sha256(content).hexdigest(),
            }
            for name, content in sorted(units.items())
        },
    }
