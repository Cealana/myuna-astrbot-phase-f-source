#!/usr/bin/env python3
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
from typing import Mapping


SCHEMA = "myuna.astrbot-telegram.r4-content-addressed-units.v1"
CORE_RELEASE_ROOT_PREFIX = "/srv/myuna/releases/core"
GATEWAY_RELEASE_ROOT_PREFIX = "/opt/myuna/telegram-gateway/releases"
CORE_PLACEHOLDER = "@CORE_RELEASE_ROOT@"
GATEWAY_PLACEHOLDER = "@GATEWAY_RELEASE_ROOT@"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UNRESOLVED_PLACEHOLDER = re.compile(r"@[A-Za-z][A-Za-z0-9_]*@")
_MUTABLE_RELEASE_ALIAS = re.compile(r"/(?:current|latest)(?:/|$)")
_BANNED_MUTABLE_PATHS = (
    "/usr/local/libexec/myuna-telegram-gateway",
    "/usr/local/lib/myuna-telegram-gateway",
    "/srv/myuna/repos/",
)

UNIT_SPECS: Mapping[str, Mapping[str, object]] = {
    "runtime": {
        "filename": "myuna-telegram-owner-runtime-dev.service",
        "entrypoint": "telegram_owner_runtime_gateway.py",
        "core_placeholder_count": 1,
        "gateway_placeholder_count": 3,
        "unit_type": "service",
    },
    "challenge": {
        "filename": "myuna-telegram-owner-challenge-dev.service",
        "entrypoint": "telegram_owner_challenge_gateway.py",
        "core_placeholder_count": 1,
        "gateway_placeholder_count": 3,
        "unit_type": "service",
    },
    "runtime_socket": {
        "filename": "myuna-telegram-owner-runtime-dev.socket",
        "listen_stream": "/run/myuna-telegram-gateway/owner.sock",
        "core_placeholder_count": 0,
        "gateway_placeholder_count": 1,
        "unit_type": "socket",
    },
    "challenge_socket": {
        "filename": "myuna-telegram-owner-challenge-dev.socket",
        "listen_stream": "/run/myuna-telegram-gateway/challenge.sock",
        "core_placeholder_count": 0,
        "gateway_placeholder_count": 1,
        "unit_type": "socket",
    },
}


class TelegramUnitRenderRejected(ValueError):
    """Raised when a unit template or release binding is not exact."""


def _digest(value: str, label: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise TelegramUnitRenderRejected(f"{label} rejected")
    return value


def _spec(kind: str) -> Mapping[str, object]:
    try:
        return UNIT_SPECS[kind]
    except KeyError:
        raise TelegramUnitRenderRejected("unit kind rejected") from None


def _decode_template(template: bytes) -> str:
    if not isinstance(template, bytes):
        raise TelegramUnitRenderRejected("unit template type rejected")
    if template.startswith(b"\xef\xbb\xbf") or b"\x00" in template:
        raise TelegramUnitRenderRejected("unit template encoding rejected")
    try:
        text = template.decode("utf-8")
    except UnicodeDecodeError:
        raise TelegramUnitRenderRejected("unit template encoding rejected") from None
    if "\r" in text or not text.endswith("\n"):
        raise TelegramUnitRenderRejected("unit template newline contract rejected")
    return text


def _validate_template(text: str, *, kind: str) -> Mapping[str, object]:
    spec = _spec(kind)
    core_count = int(spec["core_placeholder_count"])
    gateway_count = int(spec["gateway_placeholder_count"])
    if text.count(CORE_PLACEHOLDER) != core_count:
        raise TelegramUnitRenderRejected("Core placeholder count rejected")
    if text.count(GATEWAY_PLACEHOLDER) != gateway_count:
        raise TelegramUnitRenderRejected("Gateway placeholder count rejected")
    if any(path in text for path in _BANNED_MUTABLE_PATHS):
        raise TelegramUnitRenderRejected("mutable runtime path rejected")
    if _MUTABLE_RELEASE_ALIAS.search(text) is not None:
        raise TelegramUnitRenderRejected("mutable release alias rejected")
    exec_lines = [
        line for line in text.splitlines() if line.startswith("ExecStart=")
    ]
    pythonpath_lines = [
        line
        for line in text.splitlines()
        if line.startswith("Environment=PYTHONPATH=")
    ]
    listen_lines = [
        line for line in text.splitlines() if line.startswith("ListenStream=")
    ]
    if spec["unit_type"] == "service":
        if len(exec_lines) != 1:
            raise TelegramUnitRenderRejected("ExecStart contract rejected")
        if len(pythonpath_lines) != 1:
            raise TelegramUnitRenderRejected("PYTHONPATH contract rejected")
        if listen_lines:
            raise TelegramUnitRenderRejected("service ListenStream rejected")
    elif spec["unit_type"] == "socket":
        if exec_lines or pythonpath_lines:
            raise TelegramUnitRenderRejected("socket process directive rejected")
        if listen_lines != [f"ListenStream={spec['listen_stream']}"]:
            raise TelegramUnitRenderRejected("ListenStream contract rejected")
        if "SocketGroup=myuna-gateway-telegram\n" not in text:
            raise TelegramUnitRenderRejected("SocketGroup contract rejected")
    else:
        raise TelegramUnitRenderRejected("unit type rejected")
    return spec


def render_service_unit(
    template: bytes,
    *,
    kind: str,
    core_release_digest: str,
    gateway_release_digest: str,
) -> bytes:
    core_digest = _digest(core_release_digest, "Core release digest")
    gateway_digest = _digest(gateway_release_digest, "Gateway release digest")
    text = _decode_template(template)
    spec = _validate_template(text, kind=kind)
    core_root = f"{CORE_RELEASE_ROOT_PREFIX}/{core_digest}"
    gateway_root = f"{GATEWAY_RELEASE_ROOT_PREFIX}/{gateway_digest}"
    rendered = text.replace(CORE_PLACEHOLDER, core_root).replace(
        GATEWAY_PLACEHOLDER,
        gateway_root,
    )

    if _UNRESOLVED_PLACEHOLDER.search(rendered) is not None:
        raise TelegramUnitRenderRejected("unresolved unit placeholder rejected")
    if any(path in rendered for path in _BANNED_MUTABLE_PATHS):
        raise TelegramUnitRenderRejected("mutable runtime path rejected")
    if _MUTABLE_RELEASE_ALIAS.search(rendered) is not None:
        raise TelegramUnitRenderRejected("mutable release alias rejected")

    if spec["unit_type"] == "service":
        entrypoint = str(spec["entrypoint"])
        expected_exec = (
            f"ExecStart=/usr/bin/python3 {gateway_root}/scripts/{entrypoint}"
        )
        expected_pythonpath = (
            f"Environment=PYTHONPATH={core_root}/src:{gateway_root}/scripts"
        )
        exec_lines = [
            line for line in rendered.splitlines() if line.startswith("ExecStart=")
        ]
        pythonpath_lines = [
            line
            for line in rendered.splitlines()
            if line.startswith("Environment=PYTHONPATH=")
        ]
        if exec_lines != [expected_exec]:
            raise TelegramUnitRenderRejected("rendered ExecStart rejected")
        if pythonpath_lines != [expected_pythonpath]:
            raise TelegramUnitRenderRejected("rendered PYTHONPATH rejected")
    elif spec["unit_type"] == "socket":
        listen_lines = [
            line
            for line in rendered.splitlines()
            if line.startswith("ListenStream=")
        ]
        if listen_lines != [f"ListenStream={spec['listen_stream']}"]:
            raise TelegramUnitRenderRejected("rendered ListenStream rejected")
    if f"Documentation=file:{gateway_root}/docs/" not in rendered:
        raise TelegramUnitRenderRejected("rendered Documentation path rejected")
    return rendered.encode("utf-8")


def render_repository_units(
    repository_root: Path,
    *,
    core_release_digest: str,
    gateway_release_digest: str,
) -> dict[str, bytes]:
    root = Path(repository_root)
    rendered: dict[str, bytes] = {}
    for kind, spec in UNIT_SPECS.items():
        filename = str(spec["filename"])
        template_path = root / "systemd" / filename
        if template_path.is_symlink() or not template_path.is_file():
            raise TelegramUnitRenderRejected("unit template path rejected")
        template = template_path.read_bytes()
        rendered[filename] = render_service_unit(
            template,
            kind=kind,
            core_release_digest=core_release_digest,
            gateway_release_digest=gateway_release_digest,
        )
    return rendered


def build_rendered_unit_evidence(
    repository_root: Path,
    *,
    core_release_digest: str,
    gateway_release_digest: str,
) -> dict[str, object]:
    core_digest = _digest(core_release_digest, "Core release digest")
    gateway_digest = _digest(gateway_release_digest, "Gateway release digest")
    root = Path(repository_root)
    units: dict[str, object] = {}
    for kind, spec in UNIT_SPECS.items():
        filename = str(spec["filename"])
        template_path = root / "systemd" / filename
        if template_path.is_symlink() or not template_path.is_file():
            raise TelegramUnitRenderRejected("unit template path rejected")
        template = template_path.read_bytes()
        rendered = render_service_unit(
            template,
            kind=kind,
            core_release_digest=core_digest,
            gateway_release_digest=gateway_digest,
        )
        units[filename] = {
            "inactive_install_target": f"/etc/systemd/system/{filename}",
            "rendered_sha256": sha256(rendered).hexdigest(),
            "staging_target": (
                f"/opt/myuna/telegram-gateway/staging/{gateway_digest}/"
                f"systemd/{filename}"
            ),
            "template_path": f"systemd/{filename}",
            "template_sha256": sha256(template).hexdigest(),
        }
    return {
        "core_release_root": f"{CORE_RELEASE_ROOT_PREFIX}/{core_digest}",
        "gateway_release_root": (
            f"{GATEWAY_RELEASE_ROOT_PREFIX}/{gateway_digest}"
        ),
        "schema": SCHEMA,
        "units": units,
    }
