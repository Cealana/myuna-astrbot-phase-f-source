#!/usr/bin/env python3
from __future__ import annotations

from argparse import ArgumentParser
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any


SCHEMA = "myuna.context-capacity-128.live-config.v1"
BACKUP_ROOT = Path("/var/backups/myuna/context-capacity128-v1")
CORE_BASE_ENV = Path("/etc/myuna/effective-v6.env")
CORE_PROVIDER_ENV = Path("/etc/myuna/qq.env")
QQ_CONFIG = Path("/etc/myuna-gateway/qq-owner-runtime-v1.json")
TELEGRAM_CONFIG = Path("/etc/myuna-telegram-gateway/owner-runtime-v1.json")
CORE_OVERLAY = Path("/etc/myuna/context-capacity128-v1.env")
CORE_DROPIN = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/zzzzzz-context128-v1.conf"
)

EXPECTED_BASELINE_SHA256 = {
    CORE_BASE_ENV: "1cfa9213b3262f24dd322880585018c8f4ccb0fb1d1aa95e3ec52b5145cbf003",
    CORE_PROVIDER_ENV: "8cba42f5df84853c2e0ad9592b9898fa70fe35d5584f6003a2878e985a921507",
    QQ_CONFIG: "52fb2777937a27b4a121f18a8e9456627845e2ff3d27ea0fd786774db18e4e2a",
    TELEGRAM_CONFIG: "af3abe4479a9ab0a69dd31186b12ccd1b7fb9764ceae822d93d9fd4675d8b616",
}
BACKUP_NAMES = {
    CORE_BASE_ENV: "effective-v6.env",
    CORE_PROVIDER_ENV: "qq.env",
    QQ_CONFIG: "qq-owner-runtime-v1.json",
    TELEGRAM_CONFIG: "telegram-owner-runtime-v1.json",
}
CORE_OVERLAY_BYTES = (
    b"MYUNA_CONTEXT_MAX_MESSAGES=128\n"
    b"MYUNA_CONTEXT_MAX_CHARACTERS=131072\n"
    b"MYUNA_HTTP_MAX_BODY_BYTES=1048576\n"
    b"MYUNA_DEFINITION_PROMPT_MAX_CHARACTERS=300000\n"
    b"MYUNA_MODEL_INPUT_MAX_CHARACTERS=500000\n"
)
CORE_DROPIN_BYTES = (
    b"[Service]\n"
    b"EnvironmentFile=/etc/myuna/context-capacity128-v1.env\n"
)


def _digest_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _digest(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _canonical_candidate(path: Path) -> bytes:
    raw = path.read_bytes()
    trailing_newline = raw.endswith(b"\n")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError("gateway config is not an object")
    if document.get("max_history_messages") != 24:
        raise RuntimeError("gateway message baseline drifted")
    if document.get("max_history_characters") != 24_000:
        raise RuntimeError("gateway character baseline drifted")
    document["max_history_messages"] = 128
    document["max_history_characters"] = 131_072
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return encoded + (b"\n" if trailing_newline else b"")


def _validate_baseline() -> None:
    for path, expected in EXPECTED_BASELINE_SHA256.items():
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("baseline path is absent or unsafe")
        if _digest(path) != expected:
            raise RuntimeError("baseline digest drifted")
    if CORE_OVERLAY.exists() or CORE_DROPIN.exists():
        raise RuntimeError("candidate overlay already exists")


def _metadata(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "sha256": _digest(path),
        "mode": stat.st_mode & 0o777,
        "uid": stat.st_uid,
        "gid": stat.st_gid,
        "size": stat.st_size,
    }


def _backup_directory() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = BACKUP_ROOT / timestamp
    path.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(path, 0o700)
    return path


def preflight() -> dict[str, Any]:
    _validate_baseline()
    candidates = {
        QQ_CONFIG: _canonical_candidate(QQ_CONFIG),
        TELEGRAM_CONFIG: _canonical_candidate(TELEGRAM_CONFIG),
    }
    return {
        "schema": SCHEMA,
        "result": "ready",
        "baseline_digests_match": True,
        "candidate_overlay_absent": True,
        "gateway_candidates": {
            str(path): {
                "sha256": _digest_bytes(payload),
                "size": len(payload),
            }
            for path, payload in candidates.items()
        },
        "profile": {
            "max_history_messages": 128,
            "max_history_characters": 131_072,
            "http_max_body_bytes": 1_048_576,
            "definition_prompt_max_characters": 300_000,
            "model_input_max_characters": 500_000,
        },
    }


def apply_candidate() -> dict[str, Any]:
    if os.geteuid() != 0:
        raise RuntimeError("live config activation requires root")
    _validate_baseline()
    candidates = {
        QQ_CONFIG: _canonical_candidate(QQ_CONFIG),
        TELEGRAM_CONFIG: _canonical_candidate(TELEGRAM_CONFIG),
    }
    backup = _backup_directory()
    baseline: dict[str, dict[str, Any]] = {}
    for path in EXPECTED_BASELINE_SHA256:
        baseline[str(path)] = _metadata(path)
        destination = backup / BACKUP_NAMES[path]
        shutil.copy2(path, destination, follow_symlinks=False)
    _fsync_directory(backup)

    changed: list[Path] = []
    try:
        overlay_owner = CORE_BASE_ENV.stat()
        _atomic_write(
            CORE_OVERLAY,
            CORE_OVERLAY_BYTES,
            mode=0o640,
            uid=overlay_owner.st_uid,
            gid=overlay_owner.st_gid,
        )
        changed.append(CORE_OVERLAY)
        _atomic_write(
            CORE_DROPIN,
            CORE_DROPIN_BYTES,
            mode=0o644,
            uid=0,
            gid=0,
        )
        changed.append(CORE_DROPIN)
        for path, payload in candidates.items():
            stat = path.stat()
            _atomic_write(
                path,
                payload,
                mode=stat.st_mode & 0o777,
                uid=stat.st_uid,
                gid=stat.st_gid,
            )
            changed.append(path)
    except BaseException:
        for path in (QQ_CONFIG, TELEGRAM_CONFIG):
            source = backup / BACKUP_NAMES[path]
            if source.exists():
                original = baseline[str(path)]
                _atomic_write(
                    path,
                    source.read_bytes(),
                    mode=int(original["mode"]),
                    uid=int(original["uid"]),
                    gid=int(original["gid"]),
                )
        for path in (CORE_DROPIN, CORE_OVERLAY):
            if path.exists():
                os.replace(path, backup / f"failed-{path.name}")
        raise

    after = {str(path): _metadata(path) for path in changed}
    manifest = {
        "schema": SCHEMA,
        "state": "candidate-applied",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "backup_directory": str(backup),
        "baseline": baseline,
        "candidate": after,
        "profile": {
            "max_history_messages": 128,
            "max_history_characters": 131_072,
            "http_max_body_bytes": 1_048_576,
            "definition_prompt_max_characters": 300_000,
            "model_input_max_characters": 500_000,
        },
    }
    manifest_path = backup / "manifest.json"
    _atomic_write(
        manifest_path,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o600,
        uid=0,
        gid=0,
    )
    return {
        "schema": SCHEMA,
        "result": "candidate-applied",
        "backup_directory": str(backup),
        "profile": manifest["profile"],
        "changed_paths": [str(path) for path in changed],
    }


def rollback(backup: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise RuntimeError("live config rollback requires root")
    backup = backup.resolve(strict=True)
    expected_root = BACKUP_ROOT.resolve(strict=True)
    if backup.parent != expected_root:
        raise RuntimeError("rollback backup is outside the fixed backup root")
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        raise RuntimeError("rollback manifest schema mismatch")
    candidate = manifest.get("candidate")
    if not isinstance(candidate, dict):
        raise RuntimeError("rollback manifest is incomplete")
    for path in (CORE_OVERLAY, CORE_DROPIN, QQ_CONFIG, TELEGRAM_CONFIG):
        expected = candidate.get(str(path), {}).get("sha256")
        if not isinstance(expected, str) or not path.is_file() or _digest(path) != expected:
            raise RuntimeError("candidate drifted; rollback stopped")

    for path in (QQ_CONFIG, TELEGRAM_CONFIG):
        source = backup / BACKUP_NAMES[path]
        baseline = manifest["baseline"][str(path)]
        _atomic_write(
            path,
            source.read_bytes(),
            mode=int(baseline["mode"]),
            uid=int(baseline["uid"]),
            gid=int(baseline["gid"]),
        )
    for path in (CORE_DROPIN, CORE_OVERLAY):
        os.replace(path, backup / f"rolled-back-{path.name}")
        _fsync_directory(path.parent)
    for path, expected in EXPECTED_BASELINE_SHA256.items():
        if _digest(path) != expected:
            raise RuntimeError("rollback verification failed")
    return {
        "schema": SCHEMA,
        "result": "baseline-restored",
        "backup_directory": str(backup),
        "profile": {
            "max_history_messages": 24,
            "max_history_characters": 24_000,
            "http_max_body_bytes": 65_536,
            "model_input_max_characters": 400_000,
        },
    }


def main() -> int:
    parser = ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--preflight", action="store_true")
    group.add_argument("--apply", action="store_true")
    group.add_argument("--rollback", type=Path)
    args = parser.parse_args()
    if args.preflight:
        result = preflight()
    elif args.apply:
        result = apply_candidate()
    else:
        result = rollback(args.rollback)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
