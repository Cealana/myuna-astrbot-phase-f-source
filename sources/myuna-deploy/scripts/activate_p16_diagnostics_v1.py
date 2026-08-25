#!/usr/bin/env python3
"""Activate or roll back the bounded P16 diagnostic release set."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile

from core_release_selector import (
    ReleaseEvidence,
    SelectionCandidate,
    SelectorContractError,
    build_binding_intent,
    canonical_json_bytes,
    compute_tree_digest,
    load_runtime_binding,
    parse_json_document,
    render_runtime_binding,
    validate_immutable_release_tree,
    validate_runtime_observation,
)


RELEASE_SCHEMA = "myuna.p16-release.v1"
RECEIPT_SCHEMA = "myuna.p16-activation-receipt.v1"
PREFLIGHT_SCHEMA = "myuna.p16-activation-preflight.v1"
BASELINE_SCHEMA = "myuna.diagnostics.baseline.v1"
BACKUP_ROOT = Path("/var/backups/myuna/p16-diagnostics-v1")
RECEIPT_ROOT = Path("/var/lib/myuna-diagnostics/receipts")
DIAGNOSTIC_RELEASE_ROOT = Path("/opt/myuna/fault-diagnostics-v1/releases")
CORE_RELEASE_ROOT = Path("/srv/myuna/releases/core")
QQ_RELEASE_ROOT = Path("/opt/myuna/context24-gateway/qq/releases")
TELEGRAM_RELEASE_ROOT = Path("/opt/myuna/context24-gateway/telegram/releases")
CORE_SELECTOR = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf"
)
CORE_BINDING = Path("/etc/myuna/core-release-selector/qq.binding.json")
CORE_GUARD = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/05-core-release-selector-guard-v1.conf"
)
QQ_SELECTOR = Path(
    "/etc/systemd/system/myuna-qq-owner-runtime-dev.service.d/"
    "zzzzzzzzzz-p16-diagnostics-v1.conf"
)
TELEGRAM_SELECTOR = Path(
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
    "zzzzzzzzzz-p16-diagnostics-v1.conf"
)
QQ_UNIT = Path("/etc/systemd/system/myuna-qq-owner-runtime-dev.service")
TMPFILES = Path("/etc/tmpfiles.d/myuna-fault-diagnostics-v1.conf")
BASELINE = Path("/etc/myuna-diagnostics/baseline.json")
WRAPPER = Path("/usr/local/bin/myuna-diagnose")
CORE_SERVICE = "myuna-core@qq.service"
QQ_SERVICE = "myuna-qq-owner-runtime-dev.service"
TELEGRAM_SERVICE = "myuna-telegram-owner-runtime-dev.service"
SESSION_DIRECTORIES = (
    Path("/var/lib/myuna-gateway"),
    Path("/var/lib/myuna-gateway/session-context"),
    Path("/var/lib/myuna-telegram-gateway"),
    Path("/var/lib/myuna-telegram-gateway/session-context"),
)
SESSION_ACL_MASKS = {
    SESSION_DIRECTORIES[0]: "r-x",
    SESSION_DIRECTORIES[1]: "--x",
    SESSION_DIRECTORIES[2]: "r-x",
    SESSION_DIRECTORIES[3]: "--x",
}
SESSION_DATABASES = (
    Path("/var/lib/myuna-gateway/session-context/context.db"),
    Path("/var/lib/myuna-telegram-gateway/session-context/context.db"),
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CORE_WORKDIR = re.compile(r"^/srv/myuna/releases/core/([0-9a-f]{64})$")
_QQ_EXEC = re.compile(
    r"(/opt/myuna/context24-gateway/qq/releases/[0-9a-f]{64})/"
    r"runtime/qq_owner_runtime_gateway\.py"
)
_TELEGRAM_EXEC = re.compile(
    r"(/opt/myuna/context24-gateway/telegram/releases/[0-9a-f]{64})/"
    r"runtime/telegram_owner_runtime_gateway\.py"
)
_MAX_FILE_BYTES = 2 * 1024 * 1024
_CORE_INSTALLATION_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "base_release_digest",
        "source_commit",
        "overlay_manifest_sha256",
        "content_free",
        "private_content_read",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "kind",
        "base_release_digest",
        "source_commit",
        "files",
        "release_digest",
    }
)
_EXPECTED_RELEASE_FILES = {
    "core": frozenset(
        {
            "src/myuna_core/degradation_bridge.py",
            "tests/test_degradation_bridge.py",
            "fixtures/natural_degradation_r2a_core_bridge_golden.json",
        }
    ),
    "qq": frozenset(
        {
            "runtime/degradation_shadow_enqueue.py",
            "runtime/fault_incident_v1.py",
            "runtime/gateway_degradation_protocol.py",
            "runtime/gateway_post_reply.py",
            "runtime/qq_owner_runtime_gateway.py",
        }
    ),
    "telegram": frozenset(
        {
            "runtime/degradation_shadow_enqueue.py",
            "runtime/fault_incident_v1.py",
            "runtime/gateway_degradation_protocol.py",
            "runtime/gateway_post_reply.py",
            "runtime/telegram_owner_runtime_gateway.py",
        }
    ),
    "diagnostics": frozenset(
        {
            "fault_diagnostics_collector_v1.py",
            "fault_diagnostics_v1.py",
            "fault_incident_v1.py",
            "myuna_diagnose.py",
        }
    ),
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _read_regular(path: Path) -> bytes:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("activation path is not a regular file")
    if metadata.st_size <= 0 or metadata.st_size > _MAX_FILE_BYTES:
        raise RuntimeError("activation file size is invalid")
    return path.read_bytes()


def _atomic_write(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _atomic_create(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    """Create a new file without replacing a path that appeared after preflight."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _run(
    command: list[str],
    *,
    timeout: float = 20.0,
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    if extra_env is not None:
        environment.update(extra_env)
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        timeout=timeout,
        cwd=cwd,
        env=environment,
    )


def _unit_properties(unit: str) -> dict[str, str]:
    result = _run(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=ActiveState",
            "--property=SubState",
            "--property=NRestarts",
            "--property=ExecStart",
            "--property=WorkingDirectory",
            "--no-pager",
        ],
        timeout=2.0,
    )
    fields: dict[str, str] = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise RuntimeError("systemd metadata is invalid")
        fields[key] = value
    expected = {"ActiveState", "SubState", "NRestarts", "ExecStart", "WorkingDirectory"}
    if set(fields) != expected:
        raise RuntimeError("systemd metadata is incomplete")
    return fields


def _release(path: Path, expected_kind: str) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_dir() or _HEX64.fullmatch(resolved.name) is None:
        raise RuntimeError("candidate release path is invalid")
    for candidate in [resolved, *resolved.rglob("*")]:
        if candidate.is_symlink():
            raise RuntimeError("candidate release contains a symlink")
    manifest = json.loads(_read_regular(resolved / "P16_MANIFEST.json").decode("ascii"))
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_FIELDS:
        raise RuntimeError("candidate release manifest is invalid")
    if manifest.get("schema") != RELEASE_SCHEMA or manifest.get("kind") != expected_kind:
        raise RuntimeError("candidate release manifest is invalid")
    release_digest = manifest.get("release_digest")
    unsigned = {key: value for key, value in manifest.items() if key != "release_digest"}
    if (
        not isinstance(release_digest, str)
        or _HEX64.fullmatch(release_digest) is None
        or _digest_bytes(_canonical(unsigned)) != release_digest
    ):
        raise RuntimeError("candidate release digest is invalid")
    source_commit = manifest.get("source_commit")
    if not isinstance(source_commit, str) or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise RuntimeError("candidate release manifest is invalid")
    base_digest = manifest.get("base_release_digest")
    if expected_kind == "diagnostics":
        if base_digest is not None:
            raise RuntimeError("candidate release manifest is invalid")
    elif not isinstance(base_digest, str) or _HEX64.fullmatch(base_digest) is None:
        raise RuntimeError("candidate release manifest is invalid")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != _EXPECTED_RELEASE_FILES[expected_kind]:
        raise RuntimeError("candidate release file inventory is invalid")
    for relative, expected in files.items():
        if (
            not isinstance(relative, str)
            or relative.startswith("/")
            or "\\" in relative
            or ".." in Path(relative).parts
            or not isinstance(expected, dict)
            or set(expected) != {"sha256", "size"}
        ):
            raise RuntimeError("candidate release file inventory is invalid")
        expected_digest = expected.get("sha256")
        expected_size = expected.get("size")
        if (
            not isinstance(expected_digest, str)
            or _HEX64.fullmatch(expected_digest) is None
            or type(expected_size) is not int
            or not 1 <= expected_size <= _MAX_FILE_BYTES
        ):
            raise RuntimeError("candidate release file inventory is invalid")
        payload = _read_regular(resolved / relative)
        if len(payload) != expected_size or _digest_bytes(payload) != expected_digest:
            raise RuntimeError("candidate release file digest is invalid")
    if expected_kind == "core":
        receipt_bytes = _read_regular(resolved / "P16_INSTALLATION_RECEIPT.json")
        receipt = json.loads(receipt_bytes.decode("ascii"))
        if (
            not isinstance(receipt, dict)
            or set(receipt) != _CORE_INSTALLATION_RECEIPT_FIELDS
            or receipt.get("schema") != "myuna.p16-core-installation-receipt.v1"
            or receipt.get("base_release_digest") != base_digest
            or receipt.get("source_commit") != source_commit
            or receipt.get("overlay_manifest_sha256")
            != _digest_bytes(_read_regular(resolved / "P16_MANIFEST.json"))
            or receipt.get("content_free") is not True
            or receipt.get("private_content_read") is not False
        ):
            raise RuntimeError("candidate Core installation receipt is invalid")
        tree_digest, _ = compute_tree_digest(resolved)
        if tree_digest != resolved.name:
            raise RuntimeError("candidate Core tree digest is invalid")
        for candidate in [resolved, *resolved.rglob("*")]:
            expected_mode = 0o550 if candidate.is_dir() else 0o440
            if stat.S_IMODE(candidate.stat().st_mode) != expected_mode:
                raise RuntimeError("candidate Core tree mode is invalid")
    elif release_digest != resolved.name:
        raise RuntimeError("candidate release digest is invalid")
    return manifest


def _copy_release(
    source: Path,
    destination_root: Path,
    group_name: str,
    expected_kind: str,
) -> Path:
    destination = destination_root / source.name
    if destination.exists():
        _release(destination, expected_kind)
        existing = _read_regular(destination / "P16_MANIFEST.json")
        candidate = _read_regular(source / "P16_MANIFEST.json")
        if existing != candidate:
            raise RuntimeError("installed candidate release drifted")
        return destination
    destination_root.mkdir(parents=True, exist_ok=True)
    temporary = destination_root / f".{source.name}.p16-install"
    if temporary.exists():
        raise RuntimeError("stale P16 install path exists")
    shutil.copytree(source, temporary, symlinks=False)
    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam(group_name).gr_gid
    for item in [temporary, *temporary.rglob("*")]:
        os.chown(item, uid, gid, follow_symlinks=False)
    os.replace(temporary, destination)
    _release(destination, expected_kind)
    return destination


def _selected_gateway_release(exec_start: str, *, channel: str) -> Path:
    pattern = _QQ_EXEC if channel == "qq" else _TELEGRAM_EXEC
    match = pattern.search(exec_start)
    if match is None:
        raise RuntimeError("gateway live release cannot be resolved")
    return Path(match.group(1))


def _selected_core_release(working_directory: str) -> Path:
    match = _CORE_WORKDIR.fullmatch(working_directory)
    if match is None:
        raise RuntimeError("Core live release cannot be resolved")
    return Path(working_directory)


def _core_selector(release: Path) -> bytes:
    return (
        "[Service]\n"
        f"WorkingDirectory={release}\n"
        f"Environment=PYTHONPATH={release}/src\n"
    ).encode("ascii")


def _core_runtime_binding(
    release: Path,
    *,
    manifest: dict[str, object],
    current_binding: object,
    approval_plan_digest: str,
    validate_tree=validate_immutable_release_tree,
    guard_payload: bytes | None = None,
) -> bytes:
    tree_digest, file_count = compute_tree_digest(release)
    if tree_digest != release.name:
        raise RuntimeError("installed Core tree digest is invalid")
    evidence = ReleaseEvidence(
        tree_sha256=tree_digest,
        source_commit=str(manifest["source_commit"]),
        file_count=file_count,
        artifact_manifest_sha256=_digest_bytes(
            _read_regular(release / "P16_MANIFEST.json")
        ),
        installation_receipt_sha256=_digest_bytes(
            _read_regular(release / "P16_INSTALLATION_RECEIPT.json")
        ),
    )
    validate_tree(release, evidence)
    candidate = SelectionCandidate(selected_release=evidence)
    intent = build_binding_intent(
        candidate,
        verifier_script_path=current_binding.verifier_script_path,
        verifier_script_sha256=current_binding.verifier_script_sha256,
    )
    binding = render_runtime_binding(
        intent,
        approval_plan_digest=approval_plan_digest,
    )
    guard = guard_payload if guard_payload is not None else _read_regular(CORE_GUARD)
    validate_runtime_observation(
        binding,
        observed_cwd=str(release),
        observed_pythonpath=str(release / "src"),
        selector_dropin=_core_selector(release),
        guard_dropin=guard,
        observed_verifier_path=binding.verifier_script_path,
        observed_verifier_sha256=binding.verifier_script_sha256,
        observed_tree_sha256=tree_digest,
        observed_file_count=file_count,
    )
    return canonical_json_bytes(binding.to_payload()) + b"\n"


def _verify_core_selection(release: Path, binding_payload: bytes) -> None:
    binding = load_runtime_binding(parse_json_document(binding_payload))
    verifier = Path(binding.verifier_script_path)
    _run(
        ["/usr/bin/python3", str(verifier), "verify-active"],
        timeout=10.0,
        cwd=release,
        extra_env={
            "PYTHONPATH": str(release / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )


def _gateway_selector(release: Path, runtime_name: str) -> bytes:
    return (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/python3 {release}/runtime/{runtime_name}\n"
        f"Environment=PYTHONPATH={release}/runtime\n"
        "Environment=MYUNA_SESSION_CONTEXT_STORE=sqlite-v1\n"
    ).encode("ascii")


def _tmpfiles() -> bytes:
    return (
        "d /run/myuna-fault-diagnostics 0755 root root -\n"
        "d /run/myuna-fault-diagnostics/qq 2750 myuna-gateway sudo -\n"
        "d /run/myuna-fault-diagnostics/telegram 2750 "
        "myuna-gateway-telegram sudo -\n"
    ).encode("ascii")


def _wrapper(release: Path) -> bytes:
    return (
        "#!/bin/sh\n"
        f"export PYTHONPATH={release}\n"
        f"exec /usr/bin/python3 {release}/myuna_diagnose.py \"$@\"\n"
    ).encode("ascii")


def _safe_unit_digests() -> dict[str, str]:
    return {
        "core_selector": _digest_bytes(_read_regular(CORE_SELECTOR)),
        "qq_unit": _digest_bytes(_read_regular(QQ_UNIT)),
        "qq_selector": _digest_bytes(_read_regular(QQ_SELECTOR)),
        "telegram_selector": _digest_bytes(_read_regular(TELEGRAM_SELECTOR)),
    }


def _baseline(core: Path, qq: Path, telegram: Path) -> bytes:
    payload = {
        "schema": BASELINE_SCHEMA,
        "core_working_directory": str(core),
        "qq_exec_path": str(qq / "runtime/qq_owner_runtime_gateway.py"),
        "telegram_exec_path": str(
            telegram / "runtime/telegram_owner_runtime_gateway.py"
        ),
        "session_capacity_messages": 128,
        "session_capacity_characters": 131072,
        "safe_unit_digests": _safe_unit_digests(),
    }
    return _canonical(payload) + b"\n"


def _session_acl_snapshot() -> bytes:
    return _run(["/usr/bin/getfacl", "-p", *map(str, SESSION_DIRECTORIES)]).stdout


def _apply_session_acl() -> None:
    for directory, mask in SESSION_ACL_MASKS.items():
        _run(
            [
                "/usr/bin/setfacl",
                "-m",
                f"g:sudo:--x,m::{mask}",
                str(directory),
            ]
        )
    _verify_session_acl()


def _verify_session_acl() -> None:
    for directory, mask in SESSION_ACL_MASKS.items():
        payload = _run(["/usr/bin/getfacl", "-cp", str(directory)]).stdout
        lines = {
            line.split("\t", 1)[0]
            for line in payload.decode("ascii").splitlines()
        }
        if "group:sudo:--x" not in lines or f"mask::{mask}" not in lines:
            raise RuntimeError("session traverse ACL verification failed")
    for database in SESSION_DATABASES:
        metadata = database.lstat()
        if (
            database.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RuntimeError("session database metadata verification failed")


def _backup_directory() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = BACKUP_ROOT / timestamp
    path.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(path, 0o700)
    return path


def _write_receipt(payload: dict[str, object]) -> Path:
    unsigned = {**payload, "schema": RECEIPT_SCHEMA}
    receipt_digest = _digest_bytes(_canonical(unsigned))
    document = {**unsigned, "receipt_digest": receipt_digest}
    RECEIPT_ROOT.mkdir(parents=True, mode=0o750, exist_ok=True)
    sudo_gid = grp.getgrnam("sudo").gr_gid
    os.chown(RECEIPT_ROOT.parent, 0, sudo_gid)
    os.chown(RECEIPT_ROOT, 0, sudo_gid)
    os.chmod(RECEIPT_ROOT.parent, 0o750)
    os.chmod(RECEIPT_ROOT, 0o750)
    path = RECEIPT_ROOT / f"{receipt_digest}.json"
    _atomic_write(
        path,
        _canonical(document) + b"\n",
        mode=0o640,
        uid=0,
        gid=sudo_gid,
    )
    return path


def _validate_selected(core: Path, qq: Path, telegram: Path) -> dict[str, object]:
    states = {
        "core": _unit_properties(CORE_SERVICE),
        "qq": _unit_properties(QQ_SERVICE),
        "telegram": _unit_properties(TELEGRAM_SERVICE),
    }
    if states["core"]["WorkingDirectory"] != str(core):
        raise RuntimeError("Core selector verification failed")
    if str(qq / "runtime/qq_owner_runtime_gateway.py") not in states["qq"]["ExecStart"]:
        raise RuntimeError("QQ selector verification failed")
    expected_telegram = telegram / "runtime/telegram_owner_runtime_gateway.py"
    if str(expected_telegram) not in states["telegram"]["ExecStart"]:
        raise RuntimeError("Telegram selector verification failed")
    if any(
        state["ActiveState"] != "active" or state["SubState"] != "running"
        for state in states.values()
    ):
        raise RuntimeError("target service is not active")
    return {
        key: {
            "active": value["ActiveState"],
            "substate": value["SubState"],
            "restarts": int(value["NRestarts"] or "0"),
        }
        for key, value in states.items()
    }


def _preflight_context(
    *,
    core_candidate: Path,
    qq_candidate: Path,
    telegram_candidate: Path,
    diagnostics_candidate: Path,
) -> dict[str, object]:
    if os.geteuid() != 0:
        raise RuntimeError("P16 preflight requires root")
    manifests = {
        "core": _release(core_candidate, "core"),
        "qq": _release(qq_candidate, "qq"),
        "telegram": _release(telegram_candidate, "telegram"),
        "diagnostics": _release(diagnostics_candidate, "diagnostics"),
    }
    current = {
        "core": _unit_properties(CORE_SERVICE),
        "qq": _unit_properties(QQ_SERVICE),
        "telegram": _unit_properties(TELEGRAM_SERVICE),
    }
    if any(
        state["ActiveState"] != "active" or state["SubState"] != "running"
        for state in current.values()
    ):
        raise RuntimeError("target service is not active")
    current_core = _selected_core_release(current["core"]["WorkingDirectory"])
    current_qq = _selected_gateway_release(current["qq"]["ExecStart"], channel="qq")
    current_telegram = _selected_gateway_release(
        current["telegram"]["ExecStart"],
        channel="telegram",
    )
    selected = {
        "core": current_core,
        "qq": current_qq,
        "telegram": current_telegram,
    }
    for key, live_release in selected.items():
        if manifests[key].get("base_release_digest") != live_release.name:
            raise RuntimeError("candidate base release does not match live prestate")
    for path in (QQ_SELECTOR, TELEGRAM_SELECTOR, TMPFILES, BASELINE, WRAPPER):
        if path.exists() or path.is_symlink():
            raise RuntimeError("P16 activation target already exists")
    _read_regular(CORE_SELECTOR)
    binding_bytes = _read_regular(CORE_BINDING)
    guard_bytes = _read_regular(CORE_GUARD)
    try:
        current_binding = load_runtime_binding(parse_json_document(binding_bytes))
    except (SelectorContractError, UnicodeError) as exc:
        raise RuntimeError("Core runtime binding is invalid") from exc
    if current_binding.selected_release.tree_sha256 != current_core.name:
        raise RuntimeError("Core runtime binding does not match live prestate")
    if current_binding.selector_dropin_sha256 != _digest_bytes(
        _read_regular(CORE_SELECTOR)
    ):
        raise RuntimeError("Core selector binding drifted")
    if current_binding.guard_dropin_sha256 != _digest_bytes(guard_bytes):
        raise RuntimeError("Core guard binding drifted")
    _read_regular(QQ_UNIT)
    for directory in SESSION_DIRECTORIES:
        metadata = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("session metadata directory is invalid")
    pwd.getpwnam("root")
    for group_name in ("myuna", "myuna-gateway", "myuna-gateway-telegram", "sudo"):
        grp.getgrnam(group_name)
    return {
        "manifests": manifests,
        "current": current,
        "selected": selected,
        "current_binding": current_binding,
        "current_binding_bytes": binding_bytes,
    }


def preflight(
    *,
    core_candidate: Path,
    qq_candidate: Path,
    telegram_candidate: Path,
    diagnostics_candidate: Path,
) -> dict[str, object]:
    context = _preflight_context(
        core_candidate=core_candidate,
        qq_candidate=qq_candidate,
        telegram_candidate=telegram_candidate,
        diagnostics_candidate=diagnostics_candidate,
    )
    manifests = context["manifests"]
    selected = context["selected"]
    return {
        "schema": PREFLIGHT_SCHEMA,
        "result": "ready",
        "live_base_release_digests": {
            key: selected[key].name for key in ("core", "qq", "telegram")
        },
        "candidate_release_digests": {
            "core": core_candidate.name,
            "qq": qq_candidate.name,
            "telegram": telegram_candidate.name,
            "diagnostics": diagnostics_candidate.name,
        },
        "activation_targets_absent": True,
        "content_free": True,
        "private_content_read": False,
        "channel_called": False,
        "model_called": False,
        "provider_called": False,
    }


def activate(
    *,
    core_candidate: Path,
    qq_candidate: Path,
    telegram_candidate: Path,
    diagnostics_candidate: Path,
) -> dict[str, object]:
    context = _preflight_context(
        core_candidate=core_candidate,
        qq_candidate=qq_candidate,
        telegram_candidate=telegram_candidate,
        diagnostics_candidate=diagnostics_candidate,
    )
    current = context["current"]
    current_core = context["selected"]["core"]
    current_qq = context["selected"]["qq"]
    current_telegram = context["selected"]["telegram"]
    manifests = context["manifests"]

    backup = _backup_directory()
    _atomic_write(
        backup / "core-selector.conf",
        _read_regular(CORE_SELECTOR),
        mode=0o600,
        uid=0,
        gid=0,
    )
    _atomic_write(
        backup / "core-binding.json",
        context["current_binding_bytes"],
        mode=0o600,
        uid=0,
        gid=0,
    )
    acl = _session_acl_snapshot()
    _atomic_write(backup / "session-acl.txt", acl, mode=0o600, uid=0, gid=0)
    prestate = {
        "core_working_directory": str(current_core),
        "qq_release": str(current_qq),
        "telegram_release": str(current_telegram),
        "core_selector_sha256": _digest_bytes(_read_regular(CORE_SELECTOR)),
        "core_binding_sha256": _digest_bytes(_read_regular(CORE_BINDING)),
        "core_guard_sha256": _digest_bytes(_read_regular(CORE_GUARD)),
        "qq_selector_absent": True,
        "telegram_selector_absent": True,
        "diagnostic_entry_absent": True,
    }
    _atomic_write(
        backup / "prestate.json",
        _canonical(prestate) + b"\n",
        mode=0o600,
        uid=0,
        gid=0,
    )

    core = _copy_release(core_candidate, CORE_RELEASE_ROOT, "myuna", "core")
    qq = _copy_release(qq_candidate, QQ_RELEASE_ROOT, "myuna-gateway", "qq")
    telegram = _copy_release(
        telegram_candidate,
        TELEGRAM_RELEASE_ROOT,
        "myuna-gateway-telegram",
        "telegram",
    )
    diagnostics = _copy_release(
        diagnostics_candidate,
        DIAGNOSTIC_RELEASE_ROOT,
        "sudo",
        "diagnostics",
    )
    sudo_gid = grp.getgrnam("sudo").gr_gid
    myuna_gid = grp.getgrnam("myuna").gr_gid
    approval_plan = {
        "schema": "myuna.p16-core-activation-plan.v1",
        "program": "P16",
        "core_tree_sha256": core.name,
        "core_source_commit": manifests["core"]["source_commit"],
        "deploy_source_commit": manifests["diagnostics"]["source_commit"],
        "qq_release_digest": qq.name,
        "telegram_release_digest": telegram.name,
        "rollback_core_selector_sha256": prestate["core_selector_sha256"],
        "rollback_core_binding_sha256": prestate["core_binding_sha256"],
    }
    approval_plan_digest = _digest_bytes(_canonical(approval_plan))
    core_binding = _core_runtime_binding(
        core,
        manifest=manifests["core"],
        current_binding=context["current_binding"],
        approval_plan_digest=approval_plan_digest,
    )
    changed: list[Path] = []
    stage = "write-core-binding"
    lifecycle_started = False
    try:
        _atomic_write(
            CORE_BINDING,
            core_binding,
            mode=0o640,
            uid=0,
            gid=myuna_gid,
        )
        stage = "write-core-selector"
        _atomic_write(CORE_SELECTOR, _core_selector(core), mode=0o644, uid=0, gid=0)
        changed.append(CORE_SELECTOR)
        stage = "write-gateway-selectors"
        _atomic_create(
            QQ_SELECTOR,
            _gateway_selector(qq, "qq_owner_runtime_gateway.py"),
            mode=0o644,
            uid=0,
            gid=0,
        )
        changed.append(QQ_SELECTOR)
        _atomic_create(
            TELEGRAM_SELECTOR,
            _gateway_selector(telegram, "telegram_owner_runtime_gateway.py"),
            mode=0o644,
            uid=0,
            gid=0,
        )
        changed.append(TELEGRAM_SELECTOR)
        _atomic_create(TMPFILES, _tmpfiles(), mode=0o644, uid=0, gid=0)
        changed.append(TMPFILES)
        stage = "create-runtime-directories"
        _run(["/usr/bin/systemd-tmpfiles", "--create", str(TMPFILES)])
        stage = "apply-session-traverse-acl"
        _apply_session_acl()
        BASELINE.parent.mkdir(parents=True, mode=0o750, exist_ok=True)
        os.chown(BASELINE.parent, 0, sudo_gid)
        os.chmod(BASELINE.parent, 0o750)
        _atomic_create(
            BASELINE,
            _baseline(core, qq, telegram),
            mode=0o640,
            uid=0,
            gid=sudo_gid,
        )
        changed.append(BASELINE)
        _atomic_create(
            WRAPPER,
            _wrapper(diagnostics),
            mode=0o750,
            uid=0,
            gid=sudo_gid,
        )
        changed.append(WRAPPER)
        stage = "verify-core-selector-binding"
        _verify_core_selection(core, core_binding)
        stage = "daemon-reload"
        _run(["/usr/bin/systemctl", "daemon-reload"])
        for service in (CORE_SERVICE, QQ_SERVICE, TELEGRAM_SERVICE):
            stage = f"restart-{service}"
            lifecycle_started = True
            _run(["/usr/bin/systemctl", "restart", service], timeout=60.0)
        stage = "verify-selected-services"
        verification = _validate_selected(core, qq, telegram)
    except BaseException:
        _atomic_write(
            CORE_BINDING,
            _read_regular(backup / "core-binding.json"),
            mode=0o640,
            uid=0,
            gid=myuna_gid,
        )
        _atomic_write(
            CORE_SELECTOR,
            _read_regular(backup / "core-selector.conf"),
            mode=0o644,
            uid=0,
            gid=0,
        )
        for path in reversed(changed):
            if path != CORE_SELECTOR:
                path.unlink(missing_ok=True)
        _run(["/usr/bin/setfacl", f"--restore={backup / 'session-acl.txt'}"])
        prior_binding = _read_regular(backup / "core-binding.json")
        _verify_core_selection(current_core, prior_binding)
        _run(["/usr/bin/systemctl", "daemon-reload"])
        if lifecycle_started:
            for service in (CORE_SERVICE, QQ_SERVICE, TELEGRAM_SERVICE):
                _run(["/usr/bin/systemctl", "restart", service], timeout=60.0)
        rollback_verification = _validate_selected(
            current_core,
            current_qq,
            current_telegram,
        )
        failure_receipt = {
            "result": "activation-failed-rolled-back",
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "failure_stage": stage,
            "backup_directory": str(backup),
            "prestate": prestate,
            "rollback_verification": rollback_verification,
            "content_free": True,
            "private_content_read": False,
            "channel_called": False,
            "model_called": False,
            "provider_called": False,
        }
        failure_path = _write_receipt(failure_receipt)
        raise RuntimeError(
            f"P16 activation failed at {stage}; rollback verified; "
            f"receipt={failure_path}"
        ) from None

    receipt = {
        "result": "activated",
        "activated_at": datetime.now(timezone.utc).isoformat(),
        "backup_directory": str(backup),
        "prestate": prestate,
        "selected_release_digests": {
            "core": core.name,
            "qq": qq.name,
            "telegram": telegram.name,
            "diagnostics": diagnostics.name,
        },
        "verification": verification,
        "core_approval_plan_digest": approval_plan_digest,
        "activation_file_digests": {
            "core_binding": _digest_bytes(_read_regular(CORE_BINDING)),
            "core_selector": _digest_bytes(_read_regular(CORE_SELECTOR)),
            "qq_selector": _digest_bytes(_read_regular(QQ_SELECTOR)),
            "telegram_selector": _digest_bytes(_read_regular(TELEGRAM_SELECTOR)),
            "tmpfiles": _digest_bytes(_read_regular(TMPFILES)),
            "baseline": _digest_bytes(_read_regular(BASELINE)),
            "wrapper": _digest_bytes(_read_regular(WRAPPER)),
        },
        "content_free": True,
        "private_content_read": False,
        "channel_called": False,
        "model_called": False,
        "provider_called": False,
    }
    receipt_path = _write_receipt(receipt)
    return {**receipt, "receipt_path": str(receipt_path)}


def _load_activation_receipt(receipt_path: Path) -> dict[str, object]:
    resolved = receipt_path.resolve(strict=True)
    receipt_root = RECEIPT_ROOT.resolve(strict=True)
    if resolved.parent != receipt_root or resolved.is_symlink():
        raise RuntimeError("activation receipt path is invalid")
    receipt = json.loads(_read_regular(resolved).decode("ascii"))
    if not isinstance(receipt, dict) or receipt.get("schema") != RECEIPT_SCHEMA:
        raise RuntimeError("activation receipt is invalid")
    if receipt.get("result") != "activated" or receipt.get("content_free") is not True:
        raise RuntimeError("activation receipt is invalid")
    supplied_digest = receipt.get("receipt_digest")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    if (
        not isinstance(supplied_digest, str)
        or _digest_bytes(_canonical(unsigned)) != supplied_digest
    ):
        raise RuntimeError("activation receipt digest is invalid")
    return receipt


def _validate_activation_receipt_live(receipt: dict[str, object]) -> None:
    selected = receipt.get("selected_release_digests")
    if not isinstance(selected, dict) or set(selected) != {
        "core",
        "qq",
        "telegram",
        "diagnostics",
    }:
        raise RuntimeError("activation receipt release inventory is invalid")
    current = {
        "core": _unit_properties(CORE_SERVICE),
        "qq": _unit_properties(QQ_SERVICE),
        "telegram": _unit_properties(TELEGRAM_SERVICE),
    }
    if any(
        state["ActiveState"] != "active" or state["SubState"] != "running"
        for state in current.values()
    ):
        raise RuntimeError("target service is not active")
    if Path(current["core"]["WorkingDirectory"]).name != selected.get("core"):
        raise RuntimeError("Core selector drifted after activation")
    if _selected_gateway_release(current["qq"]["ExecStart"], channel="qq").name != selected.get(
        "qq"
    ):
        raise RuntimeError("QQ selector drifted after activation")
    if _selected_gateway_release(
        current["telegram"]["ExecStart"],
        channel="telegram",
    ).name != selected.get("telegram"):
        raise RuntimeError("Telegram selector drifted after activation")
    activated_files = receipt.get("activation_file_digests")
    activated_paths = {
        "core_binding": CORE_BINDING,
        "core_selector": CORE_SELECTOR,
        "qq_selector": QQ_SELECTOR,
        "telegram_selector": TELEGRAM_SELECTOR,
        "tmpfiles": TMPFILES,
        "baseline": BASELINE,
        "wrapper": WRAPPER,
    }
    if not isinstance(activated_files, dict) or set(activated_files) != set(activated_paths):
        raise RuntimeError("activation file inventory is invalid")
    for key, path in activated_paths.items():
        if _digest_bytes(_read_regular(path)) != activated_files.get(key):
            raise RuntimeError("activation file drifted after activation")


def repair_owner_entry(
    *,
    activation_receipt: Path,
    diagnostics_candidate: Path,
) -> dict[str, object]:
    if os.geteuid() != 0:
        raise RuntimeError("P16 Owner entry repair requires root")
    receipt = _load_activation_receipt(activation_receipt)
    _validate_activation_receipt_live(receipt)
    _release(diagnostics_candidate, "diagnostics")
    backup_root = Path(str(receipt["backup_directory"])).resolve(strict=True)
    if backup_root.parent != BACKUP_ROOT.resolve(strict=True):
        raise RuntimeError("activation backup path is invalid")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    repair_backup = backup_root / f"owner-entry-repair-{timestamp}"
    repair_backup.mkdir(mode=0o700, exist_ok=False)
    wrapper_before = _read_regular(WRAPPER)
    acl_before = _session_acl_snapshot()
    _atomic_write(
        repair_backup / "wrapper",
        wrapper_before,
        mode=0o600,
        uid=0,
        gid=0,
    )
    _atomic_write(
        repair_backup / "session-acl.txt",
        acl_before,
        mode=0o600,
        uid=0,
        gid=0,
    )
    diagnostics = _copy_release(
        diagnostics_candidate,
        DIAGNOSTIC_RELEASE_ROOT,
        "sudo",
        "diagnostics",
    )
    sudo_gid = grp.getgrnam("sudo").gr_gid
    try:
        _apply_session_acl()
        _atomic_write(
            WRAPPER,
            _wrapper(diagnostics),
            mode=0o750,
            uid=0,
            gid=sudo_gid,
        )
    except BaseException:
        _run(["/usr/bin/setfacl", f"--restore={repair_backup / 'session-acl.txt'}"])
        _atomic_write(
            WRAPPER,
            wrapper_before,
            mode=0o750,
            uid=0,
            gid=sudo_gid,
        )
        raise
    selected = dict(receipt["selected_release_digests"])
    selected["diagnostics"] = diagnostics.name
    activated_files = dict(receipt["activation_file_digests"])
    activated_files["wrapper"] = _digest_bytes(_read_regular(WRAPPER))
    superseded_digest = str(receipt["receipt_digest"])
    updated = {
        key: value
        for key, value in receipt.items()
        if key not in {"receipt_digest", "schema"}
    }
    updated.update(
        {
            "selected_release_digests": selected,
            "activation_file_digests": activated_files,
            "repaired_at": datetime.now(timezone.utc).isoformat(),
            "supersedes_activation_receipt_digest": superseded_digest,
            "owner_entry_repair": {
                "backup_directory": str(repair_backup),
                "acl_before_sha256": _digest_bytes(acl_before),
                "acl_after_sha256": _digest_bytes(_session_acl_snapshot()),
                "wrapper_before_sha256": _digest_bytes(wrapper_before),
                "wrapper_after_sha256": activated_files["wrapper"],
                "session_databases_opened": False,
                "service_restarted": False,
            },
        }
    )
    path = _write_receipt(updated)
    return {**updated, "receipt_path": str(path)}


def rollback_preflight(receipt_path: Path) -> dict[str, object]:
    receipt = _load_activation_receipt(receipt_path)
    _validate_activation_receipt_live(receipt)
    prestate = receipt.get("prestate")
    if not isinstance(prestate, dict):
        raise RuntimeError("rollback prestate is invalid")
    backup = Path(str(receipt.get("backup_directory"))).resolve(strict=True)
    if backup.parent != BACKUP_ROOT.resolve(strict=True):
        raise RuntimeError("rollback backup path is invalid")
    if _digest_bytes(_read_regular(backup / "core-selector.conf")) != prestate.get(
        "core_selector_sha256"
    ):
        raise RuntimeError("rollback backup drifted after activation")
    if _digest_bytes(_read_regular(backup / "core-binding.json")) != prestate.get(
        "core_binding_sha256"
    ):
        raise RuntimeError("rollback backup drifted after activation")
    _read_regular(backup / "session-acl.txt")
    return {
        "schema": "myuna.p16-rollback-preflight.v1",
        "result": "ready",
        "activation_receipt_digest": receipt["receipt_digest"],
        "content_free": True,
        "private_content_read": False,
        "channel_called": False,
        "model_called": False,
        "provider_called": False,
        "state_changed": False,
    }


def rollback(receipt_path: Path) -> dict[str, object]:
    if os.geteuid() != 0:
        raise RuntimeError("P16 rollback requires root")
    resolved = receipt_path.resolve(strict=True)
    receipt_root = RECEIPT_ROOT.resolve(strict=True)
    if resolved.parent != receipt_root or resolved.is_symlink():
        raise RuntimeError("rollback receipt path is invalid")
    receipt = json.loads(_read_regular(resolved).decode("ascii"))
    if not isinstance(receipt, dict) or receipt.get("schema") != RECEIPT_SCHEMA:
        raise RuntimeError("rollback receipt is invalid")
    if receipt.get("result") != "activated" or receipt.get("content_free") is not True:
        raise RuntimeError("rollback receipt is invalid")
    supplied_digest = receipt.pop("receipt_digest", None)
    if not isinstance(supplied_digest, str):
        raise RuntimeError("rollback receipt is invalid")
    if _digest_bytes(_canonical(receipt)) != supplied_digest:
        raise RuntimeError("rollback receipt digest is invalid")
    backup = Path(str(receipt.get("backup_directory"))).resolve(strict=True)
    backup_root = BACKUP_ROOT.resolve(strict=True)
    if backup.parent != backup_root:
        raise RuntimeError("rollback backup path is invalid")
    selected = receipt.get("selected_release_digests")
    if not isinstance(selected, dict):
        raise RuntimeError("rollback receipt is invalid")
    current = {
        "core": _unit_properties(CORE_SERVICE),
        "qq": _unit_properties(QQ_SERVICE),
        "telegram": _unit_properties(TELEGRAM_SERVICE),
    }
    if Path(current["core"]["WorkingDirectory"]).name != selected.get("core"):
        raise RuntimeError("Core selector drifted after activation")
    current_qq = _selected_gateway_release(current["qq"]["ExecStart"], channel="qq")
    current_telegram = _selected_gateway_release(
        current["telegram"]["ExecStart"],
        channel="telegram",
    )
    if current_qq.name != selected.get("qq"):
        raise RuntimeError("QQ selector drifted after activation")
    if current_telegram.name != selected.get("telegram"):
        raise RuntimeError("Telegram selector drifted after activation")
    activated_files = receipt.get("activation_file_digests")
    activated_paths = {
        "core_binding": CORE_BINDING,
        "core_selector": CORE_SELECTOR,
        "qq_selector": QQ_SELECTOR,
        "telegram_selector": TELEGRAM_SELECTOR,
        "tmpfiles": TMPFILES,
        "baseline": BASELINE,
        "wrapper": WRAPPER,
    }
    if not isinstance(activated_files, dict) or set(activated_files) != set(activated_paths):
        raise RuntimeError("rollback activation file inventory is invalid")
    for key, path in activated_paths.items():
        if _digest_bytes(_read_regular(path)) != activated_files.get(key):
            raise RuntimeError("activation file drifted after activation")
    prestate = receipt.get("prestate")
    if not isinstance(prestate, dict):
        raise RuntimeError("rollback prestate is invalid")
    if _digest_bytes(_read_regular(backup / "core-selector.conf")) != prestate.get(
        "core_selector_sha256"
    ):
        raise RuntimeError("rollback backup drifted after activation")
    if _digest_bytes(_read_regular(backup / "core-binding.json")) != prestate.get(
        "core_binding_sha256"
    ):
        raise RuntimeError("rollback backup drifted after activation")
    myuna_gid = grp.getgrnam("myuna").gr_gid
    _atomic_write(
        CORE_BINDING,
        _read_regular(backup / "core-binding.json"),
        mode=0o640,
        uid=0,
        gid=myuna_gid,
    )
    _atomic_write(
        CORE_SELECTOR,
        _read_regular(backup / "core-selector.conf"),
        mode=0o644,
        uid=0,
        gid=0,
    )
    _verify_core_selection(
        Path(str(prestate["core_working_directory"])),
        _read_regular(backup / "core-binding.json"),
    )
    for path in (QQ_SELECTOR, TELEGRAM_SELECTOR, TMPFILES, BASELINE, WRAPPER):
        path.unlink(missing_ok=True)
    _run(["/usr/bin/setfacl", f"--restore={backup / 'session-acl.txt'}"])
    _run(["/usr/bin/systemctl", "daemon-reload"])
    for service in (CORE_SERVICE, QQ_SERVICE, TELEGRAM_SERVICE):
        _run(["/usr/bin/systemctl", "restart", service], timeout=60.0)
    restored = {
        "core": _unit_properties(CORE_SERVICE),
        "qq": _unit_properties(QQ_SERVICE),
        "telegram": _unit_properties(TELEGRAM_SERVICE),
    }
    if restored["core"]["WorkingDirectory"] != prestate.get("core_working_directory"):
        raise RuntimeError("Core rollback verification failed")
    if str(prestate.get("qq_release")) not in restored["qq"]["ExecStart"]:
        raise RuntimeError("QQ rollback verification failed")
    if str(prestate.get("telegram_release")) not in restored["telegram"]["ExecStart"]:
        raise RuntimeError("Telegram rollback verification failed")
    rollback_receipt = {
        "result": "rolled-back",
        "rolled_back_at": datetime.now(timezone.utc).isoformat(),
        "activation_receipt_digest": supplied_digest,
        "backup_directory": str(backup),
        "content_free": True,
        "private_content_read": False,
        "channel_called": False,
        "model_called": False,
        "provider_called": False,
    }
    path = _write_receipt(rollback_receipt)
    return {**rollback_receipt, "receipt_path": str(path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rollback", type=Path)
    parser.add_argument("--repair-owner-entry", type=Path)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--core-candidate", type=Path)
    parser.add_argument("--qq-candidate", type=Path)
    parser.add_argument("--telegram-candidate", type=Path)
    parser.add_argument("--diagnostics-candidate", type=Path)
    args = parser.parse_args()
    if args.rollback is not None:
        if any(
            value is not None
            for value in (
                args.repair_owner_entry,
                args.core_candidate,
                args.qq_candidate,
                args.telegram_candidate,
                args.diagnostics_candidate,
            )
        ):
            parser.error("--rollback cannot be combined with candidate paths")
        result = (
            rollback_preflight(args.rollback)
            if args.preflight
            else rollback(args.rollback)
        )
    elif args.repair_owner_entry is not None:
        if args.preflight or any(
            value is not None
            for value in (
                args.core_candidate,
                args.qq_candidate,
                args.telegram_candidate,
            )
        ):
            parser.error("--repair-owner-entry accepts only --diagnostics-candidate")
        if args.diagnostics_candidate is None:
            parser.error("--diagnostics-candidate is required for Owner entry repair")
        result = repair_owner_entry(
            activation_receipt=args.repair_owner_entry,
            diagnostics_candidate=args.diagnostics_candidate,
        )
    else:
        candidates = {
            "core_candidate": args.core_candidate,
            "qq_candidate": args.qq_candidate,
            "telegram_candidate": args.telegram_candidate,
            "diagnostics_candidate": args.diagnostics_candidate,
        }
        if any(value is None for value in candidates.values()):
            parser.error("all candidate paths are required for activation")
        result = preflight(**candidates) if args.preflight else activate(**candidates)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
