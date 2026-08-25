#!/usr/bin/env python3
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re


SCHEMA = "myuna.vision-decoder.rendered-systemd-units.v1"
WORKER_PLACEHOLDER = "@WORKER_RELEASE@"
PROBE_PLACEHOLDER = "@PROBE_RELEASE@"
WORKER_ROOT_PREFIX = "/opt/myuna/vision-decoder-worker/releases"
PROBE_ROOT_PREFIX = "/opt/myuna/vision-media-probe/releases"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UNRESOLVED = re.compile(r"@[A-Za-z][A-Za-z0-9_]*@")
_MUTABLE_ALIAS = re.compile(r"/(?:current|latest)(?:/|$)")
_BANNED = ("/srv/myuna/repos/", "/usr/local/", "/opt/myuna/vision-media-probe/policies/")


class VisionDecoderUnitRenderRejected(ValueError):
    """Raised when a unit template or content-address binding is not exact."""


def _digest(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise VisionDecoderUnitRenderRejected("release digest rejected")
    return value


def _template(content: bytes) -> str:
    if not isinstance(content, bytes) or content.startswith(b"\xef\xbb\xbf") or b"\x00" in content:
        raise VisionDecoderUnitRenderRejected("unit template encoding rejected")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise VisionDecoderUnitRenderRejected("unit template encoding rejected") from None
    if "\r" in text or not text.endswith("\n"):
        raise VisionDecoderUnitRenderRejected("unit template newline rejected")
    return text


def render_service(template: bytes, *, worker_digest: str, probe_digest: str) -> bytes:
    worker = _digest(worker_digest)
    probe = _digest(probe_digest)
    text = _template(template)
    if text.count(WORKER_PLACEHOLDER) != 2 or text.count(PROBE_PLACEHOLDER) != 2:
        raise VisionDecoderUnitRenderRejected("unit placeholder count rejected")
    if any(value in text for value in _BANNED) or _MUTABLE_ALIAS.search(text):
        raise VisionDecoderUnitRenderRejected("mutable unit path rejected")
    worker_root = f"{WORKER_ROOT_PREFIX}/{worker}"
    probe_root = f"{PROBE_ROOT_PREFIX}/{probe}"
    rendered = text.replace(WORKER_PLACEHOLDER, worker).replace(PROBE_PLACEHOLDER, probe)
    if _UNRESOLVED.search(rendered) or any(value in rendered for value in _BANNED):
        raise VisionDecoderUnitRenderRejected("rendered unit path rejected")
    expected = {
        f"Documentation=file:{worker_root}/docs/ADR-047-vision-decoder-worker-v1.md",
        f"Environment=PYTHONPATH={worker_root}:{probe_root}",
        (
            "ExecStart=/opt/myuna/vision-decoder/runtimes/"
            "pillow-12.3.0-cp312-78cb2c6865a35ab8/bin/python "
            f"-m myuna_media_decoder.worker --policy {probe_root}/config/"
            "vision-media-probe-pillow-v1.json"
        ),
    }
    lines = set(rendered.splitlines())
    if not expected.issubset(lines):
        raise VisionDecoderUnitRenderRejected("rendered service contract rejected")
    return rendered.encode("utf-8")


def render_socket(template: bytes, *, worker_digest: str) -> bytes:
    worker = _digest(worker_digest)
    text = _template(template)
    if text.count(WORKER_PLACEHOLDER) != 1 or PROBE_PLACEHOLDER in text:
        raise VisionDecoderUnitRenderRejected("socket placeholder count rejected")
    if any(value in text for value in _BANNED) or _MUTABLE_ALIAS.search(text):
        raise VisionDecoderUnitRenderRejected("mutable socket path rejected")
    rendered = text.replace(WORKER_PLACEHOLDER, worker)
    if _UNRESOLVED.search(rendered) or any(value in rendered for value in _BANNED):
        raise VisionDecoderUnitRenderRejected("rendered socket path rejected")
    expected_documentation = (
        f"Documentation=file:{WORKER_ROOT_PREFIX}/{worker}/docs/"
        "ADR-047-vision-decoder-worker-v1.md"
    )
    if expected_documentation not in rendered.splitlines():
        raise VisionDecoderUnitRenderRejected("rendered socket contract rejected")
    return rendered.encode("utf-8")


def render_repository_units(
    repository_root: Path,
    *,
    worker_digest: str,
    probe_digest: str,
) -> dict[str, bytes]:
    root = Path(repository_root)
    service_path = root / "systemd/myuna-vision-decoder-shadow-v1.service"
    socket_path = root / "systemd/myuna-vision-decoder-shadow-v1.socket"
    for path in (service_path, socket_path):
        if path.is_symlink() or not path.is_file():
            raise VisionDecoderUnitRenderRejected("unit template path rejected")
    return {
        service_path.name: render_service(
            service_path.read_bytes(),
            worker_digest=worker_digest,
            probe_digest=probe_digest,
        ),
        socket_path.name: render_socket(
            socket_path.read_bytes(),
            worker_digest=worker_digest,
        ),
    }


def build_evidence(
    repository_root: Path,
    *,
    worker_digest: str,
    probe_digest: str,
) -> dict[str, object]:
    rendered = render_repository_units(
        repository_root,
        worker_digest=worker_digest,
        probe_digest=probe_digest,
    )
    return {
        "probe_release_root": f"{PROBE_ROOT_PREFIX}/{_digest(probe_digest)}",
        "schema": SCHEMA,
        "units": {
            name: {
                "inactive_install_target": f"/etc/systemd/system/{name}",
                "rendered_sha256": sha256(content).hexdigest(),
            }
            for name, content in sorted(rendered.items())
        },
        "worker_release_root": f"{WORKER_ROOT_PREFIX}/{_digest(worker_digest)}",
    }
