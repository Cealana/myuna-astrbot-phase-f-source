#!/usr/bin/env python3
"""Create an encrypted, application-consistent Myuna server snapshot on Server BU."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


SNAPSHOT_RE = re.compile(r"^\d{8}T\d{6}Z$")
EXPECTED_SCHEMA = "myuna.server-usb-backup-config.v1"
MARKER_SCHEMA = "myuna.server-backup-device.v1"
RECEIPT_SCHEMA = "myuna.server-usb-backup-receipt.v1"


class BackupError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    usb_root: Path
    staging_root: Path
    passphrase_file: Path
    state_root: Path
    expected_label: str
    expected_filesystem: str
    expected_serial: str
    expected_disk_size: int
    minimum_free_bytes: int
    daily_keep: int
    weekly_keep: int
    monthly_keep: int


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def load_config(path: Path) -> Config:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema") != EXPECTED_SCHEMA:
        raise BackupError("CONFIG_SCHEMA_MISMATCH")
    retention = raw["retention"]
    device = raw["device"]
    return Config(
        usb_root=Path(raw["usb_root"]),
        staging_root=Path(raw["staging_root"]),
        passphrase_file=Path(raw["passphrase_file"]),
        state_root=Path(raw["state_root"]),
        expected_label=device["label"],
        expected_filesystem=device["filesystem"],
        expected_serial=device["serial"],
        expected_disk_size=int(device["disk_size"]),
        minimum_free_bytes=int(raw["minimum_free_bytes"]),
        daily_keep=int(retention["daily"]),
        weekly_keep=int(retention["weekly"]),
        monthly_keep=int(retention["monthly"]),
    )


def run(command: Sequence[str], *, timeout: int = 900, stdout=None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        list(command),
        stdin=subprocess.DEVNULL,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=stdout is None,
        timeout=timeout,
        check=False,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace") if isinstance(result.stderr, bytes) else (result.stderr or "")
        raise BackupError(f"COMMAND_FAILED:{Path(command[0]).name}:{stderr[-400:].strip()}")
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_remove_tree(path: Path, parent: Path) -> None:
    resolved_parent = parent.resolve()
    resolved = path.resolve()
    if resolved.parent != resolved_parent or not SNAPSHOT_RE.fullmatch(resolved.name):
        raise BackupError("UNSAFE_RETENTION_TARGET")
    if resolved.is_symlink() or not resolved.is_dir():
        raise BackupError("UNSAFE_RETENTION_TARGET_TYPE")
    shutil.rmtree(resolved)


def validate_marker(config: Config) -> dict:
    marker_path = config.usb_root / "DEVICE_ID.json"
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, NotADirectoryError, json.JSONDecodeError) as exc:
        raise BackupError("USB_MARKER_UNAVAILABLE") from exc
    expected = {
        "schema": MARKER_SCHEMA,
        "label": config.expected_label,
        "filesystem": config.expected_filesystem,
        "serial": config.expected_serial,
        "disk_size": config.expected_disk_size,
    }
    if any(marker.get(key) != value for key, value in expected.items()):
        raise BackupError("USB_MARKER_MISMATCH")
    return marker


def ensure_secure_secret(path: Path) -> None:
    stat = path.stat()
    if not path.is_file() or path.is_symlink() or stat.st_uid != 0 or (stat.st_mode & 0o077):
        raise BackupError("PASSPHRASE_METADATA_INVALID")
    if path.read_bytes().count(b"\n") > 1 or stat.st_size < 48 or stat.st_size > 256:
        raise BackupError("PASSPHRASE_FORMAT_INVALID")


def sqlite_backup(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_uri = f"file:{source}?mode=ro"
    with sqlite3.connect(source_uri, uri=True, timeout=20) as src:
        with sqlite3.connect(destination) as dst:
            src.backup(dst)
            row = dst.execute("PRAGMA integrity_check").fetchone()
            if not row or row[0] != "ok":
                raise BackupError(f"SQLITE_BACKUP_INVALID:{source.name}")


def create_tar(output: Path, paths: Sequence[tuple[Path, Sequence[str]]], excludes: Iterable[str] = ()) -> None:
    command = ["/usr/bin/tar", "--numeric-owner", "--acls", "--xattrs", "-czf", str(output)]
    for item in excludes:
        command.extend(["--exclude", item])
    for base, names in paths:
        command.extend(["-C", str(base), *names])
    run(command, timeout=1800)


def encrypt(source: Path, destination: Path, passphrase_file: Path) -> None:
    run(
        [
            "/usr/bin/gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
            "--passphrase-file", str(passphrase_file), "--symmetric", "--cipher-algo", "AES256",
            "--s2k-mode", "3", "--s2k-digest-algo", "SHA512", "--s2k-count", "65011712",
            "--compress-algo", "none", "--output", str(destination), str(source),
        ],
        timeout=1800,
    )


def decrypt(source: Path, destination: Path, passphrase_file: Path) -> None:
    run(
        [
            "/usr/bin/gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
            "--passphrase-file", str(passphrase_file), "--decrypt", "--output", str(destination), str(source),
        ],
        timeout=1800,
    )


def latest_minecraft_backup() -> Path:
    root = Path("/mnt/d/Playground/backups/minecraft/daily")
    candidates = sorted(
        (p for p in root.glob("minecraft-create-delight-*.tar.gz") if p.is_file() and not p.name.endswith(".partial")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise BackupError("MINECRAFT_BACKUP_MISSING")
    return candidates[0]


def retention_keep(names: Sequence[str], daily: int, weekly: int, monthly: int) -> set[str]:
    parsed = [(name, datetime.strptime(name, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)) for name in names]
    parsed.sort(key=lambda pair: pair[1], reverse=True)
    keep = {name for name, _ in parsed[:daily]}
    seen_weeks: set[tuple[int, int]] = set()
    seen_months: set[tuple[int, int]] = set()
    for name, stamp in parsed:
        week = (stamp.isocalendar().year, stamp.isocalendar().week)
        month = (stamp.year, stamp.month)
        if len(seen_weeks) < weekly and week not in seen_weeks:
            seen_weeks.add(week)
            keep.add(name)
        if len(seen_months) < monthly and month not in seen_months:
            seen_months.add(month)
            keep.add(name)
    return keep


def atomic_write(path: Path, payload: str, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def build_snapshot(config: Config) -> dict:
    validate_marker(config)
    ensure_secure_secret(config.passphrase_file)
    usage = shutil.disk_usage(config.usb_root)
    if usage.free < config.minimum_free_bytes:
        raise BackupError("USB_FREE_SPACE_GUARD")

    now = datetime.now(timezone.utc)
    run_id = now.strftime("%Y%m%dT%H%M%SZ")
    stage = config.staging_root / run_id
    incoming_root = config.usb_root / ".incoming"
    snapshots_root = config.usb_root / "snapshots"
    incoming = incoming_root / run_id
    published = snapshots_root / run_id
    if stage.exists() or incoming.exists() or published.exists():
        raise BackupError("RUN_ID_COLLISION")
    stage.mkdir(parents=True, mode=0o700)
    incoming_root.mkdir(parents=True, exist_ok=True)
    snapshots_root.mkdir(parents=True, exist_ok=True)
    incoming.mkdir(mode=0o700)

    plaintext = stage / "plaintext"
    plaintext.mkdir(mode=0o700)
    sqlite_root = plaintext / "sqlite"
    artifacts: list[dict] = []
    try:
        run(["/usr/bin/systemctl", "start", "minecraft-backup.service"], timeout=1200)
        minecraft_source = latest_minecraft_backup()

        pg_dump = plaintext / "myuna_dev.pgdump"
        with pg_dump.open("wb") as dump_output:
            run(["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/pg_dump", "--format=custom", "myuna_dev"], timeout=900, stdout=dump_output)
        run(["/usr/bin/pg_restore", "--list", str(pg_dump)], timeout=120)

        sqlite_backup(Path("/srv/myuna/channels/astrbot-qq/dev/astrbot-data/data_v4.db"), sqlite_root / "astrbot-qq-data_v4.db")
        sqlite_backup(Path("/srv/myuna/channels/astrbot-telegram/dev/astrbot-data/data_v4.db"), sqlite_root / "astrbot-telegram-data_v4.db")

        control_tar = plaintext / "myuna-control-plane.tar.gz"
        var_lib_names = sorted(p.name for p in Path("/var/lib").glob("myuna*") if p.is_dir())
        create_tar(
            control_tar,
            [
                (Path("/"), ["etc/myuna", "etc/myuna-gateway", "etc/myuna-telegram-gateway", "etc/systemd/system", "opt/myuna"]),
                (Path("/var/lib"), var_lib_names),
            ],
        )

        channels_tar = plaintext / "myuna-channel-runtime.tar.gz"
        create_tar(
            channels_tar,
            [
                (Path("/srv/myuna/channels/astrbot-qq/dev"), ["astrbot-data", "napcat-config", "napcat-qq/NapCat", "napcat-qq/nt_qq_cfb739976de621bd6ec6d70a5e640ed9"]),
                (Path("/srv/myuna/channels/astrbot-telegram/dev"), ["astrbot-data"]),
                (plaintext, ["sqlite"]),
            ],
            excludes=("*/logs/*", "*/temp/*", "*/crash_files/*", "*/Crashpad/*", "*/data_v4.db", "*/data_v4.db-wal", "*/data_v4.db-shm"),
        )

        project_tar = plaintext / "myuna-project-and-docs.tar.gz"
        create_tar(
            project_tar,
            [
                (Path("/srv/myuna"), ["repos"]),
                (Path("/mnt/c"), ["Server-Admin/Myuna"]),
                (Path("/mnt/d"), ["Playground/docs/myuna-foundation", "Playground/backups/myuna"]),
            ],
            excludes=("*/__pycache__/*", "*/.pytest_cache/*", "*/.mypy_cache/*"),
        )

        plaintext_sources = [
            (pg_dump, "postgresql-myuna_dev.pgdump.gpg", "postgresql_logical_dump"),
            (control_tar, "myuna-control-plane.tar.gz.gpg", "linux_control_plane"),
            (channels_tar, "myuna-channel-runtime.tar.gz.gpg", "channel_runtime"),
            (project_tar, "myuna-project-and-docs.tar.gz.gpg", "projects_and_documents"),
            (minecraft_source, "minecraft-latest.tar.gz.gpg", "minecraft_application_backup"),
        ]
        for source, output_name, backup_class in plaintext_sources:
            destination = incoming / output_name
            encrypt(source, destination, config.passphrase_file)
            artifacts.append({
                "backup_class": backup_class,
                "file": output_name,
                "sha256": sha256_file(destination),
                "encrypted_bytes": destination.stat().st_size,
                "source_bytes": source.stat().st_size,
            })

        verify_root = stage / "verify"
        verify_root.mkdir(mode=0o700)
        for item in artifacts:
            encrypted = incoming / item["file"]
            if sha256_file(encrypted) != item["sha256"]:
                raise BackupError("USB_HASH_MISMATCH")
            restored = verify_root / item["file"].removesuffix(".gpg")
            decrypt(encrypted, restored, config.passphrase_file)
            if item["backup_class"] == "postgresql_logical_dump":
                run(["/usr/bin/pg_restore", "--list", str(restored)], timeout=120)
            elif item["backup_class"] != "minecraft_application_backup":
                run(["/usr/bin/tar", "-tzf", str(restored)], timeout=300)
            elif sha256_file(restored) != sha256_file(minecraft_source):
                raise BackupError("MINECRAFT_RESTORE_HASH_MISMATCH")

        manifest = {
            "schema": "myuna.server-usb-backup-manifest.v1",
            "run_id": run_id,
            "created_at": now.isoformat(),
            "device": {
                "label": config.expected_label,
                "filesystem": config.expected_filesystem,
                "serial": config.expected_serial,
                "disk_size": config.expected_disk_size,
            },
            "encryption": "OpenPGP symmetric AES-256; passphrase stored off-device",
            "consistency": {
                "postgresql": "pg_dump custom format plus pg_restore list verification",
                "astrbot_sqlite": "SQLite online backup plus integrity_check",
                "minecraft": "minecraft-backup.service completed before selection",
                "napcat_session": "bounded configuration/session snapshot; QR re-login remains recovery fallback",
            },
            "minecraft_source": minecraft_source.name,
            "artifacts": artifacts,
            "restore_verification": "passed",
        }
        atomic_write(incoming / "MANIFEST.json", canonical_json(manifest), 0o640)
        sums = "".join(f"{item['sha256']}  {item['file']}\n" for item in artifacts)
        atomic_write(incoming / "SHA256SUMS", sums, 0o640)
        atomic_write(incoming / "COMPLETE", canonical_json({"run_id": run_id, "status": "COMPLETE"}), 0o640)
        os.replace(incoming, published)

        names = sorted(p.name for p in snapshots_root.iterdir() if p.is_dir() and SNAPSHOT_RE.fullmatch(p.name) and (p / "COMPLETE").is_file())
        keep = retention_keep(names, config.daily_keep, config.weekly_keep, config.monthly_keep)
        deleted: list[str] = []
        if len(names) > 1:
            for name in names:
                if name not in keep:
                    safe_remove_tree(snapshots_root / name, snapshots_root)
                    deleted.append(name)

        receipt = {
            "schema": RECEIPT_SCHEMA,
            "status": "SUCCESS",
            "run_id": run_id,
            "snapshot": str(published),
            "artifact_count": len(artifacts),
            "total_encrypted_bytes": sum(int(item["encrypted_bytes"]) for item in artifacts),
            "restore_verification": "passed",
            "retention_deleted": deleted,
            "secrets_exposed": False,
        }
        atomic_write(config.state_root / "LAST_SUCCESS.json", canonical_json(receipt), 0o640)
        atomic_write(Path("/mnt/c/Server-Admin/Myuna/backups/usb-daily/LAST_SUCCESS.json"), canonical_json(receipt), 0o640)
        atomic_write(Path("/mnt/d/Playground/backups/myuna/usb-daily/LAST_SUCCESS.json"), canonical_json(receipt), 0o640)
        return receipt
    finally:
        if stage.exists() and stage.parent.resolve() == config.staging_root.resolve() and SNAPSHOT_RE.fullmatch(stage.name):
            shutil.rmtree(stage)
        if incoming.exists() and incoming.parent.resolve() == incoming_root.resolve() and SNAPSHOT_RE.fullmatch(incoming.name):
            shutil.rmtree(incoming)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/myuna-usb-backup/config-v1.json")
    args = parser.parse_args()
    config = load_config(Path(args.config))
    config.state_root.mkdir(parents=True, exist_ok=True)
    lock_path = Path("/run/lock/myuna-usb-backup-v1.lock")
    with lock_path.open("w", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BackupError("BACKUP_ALREADY_RUNNING") from exc
        receipt = build_snapshot(config)
    print(canonical_json(receipt), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BackupError as exc:
        print(canonical_json({"schema": RECEIPT_SCHEMA, "status": "FAILED", "reason": str(exc)}), end="", file=sys.stderr)
        raise SystemExit(1)
