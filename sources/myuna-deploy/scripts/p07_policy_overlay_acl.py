from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess


class PolicyOverlayAclRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise PolicyOverlayAclRejected(code)


def _canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


def expected_entries(*, core_uid: int, telegram_uid: int) -> tuple[str, ...]:
    _require(
        core_uid > 0 and telegram_uid > 0 and core_uid != telegram_uid,
        "policy_overlay_acl_identity_rejected",
    )
    return tuple(
        sorted(
            (
                "group::---",
                "mask::r--",
                "other::---",
                "user::rw-",
                f"user:{core_uid}:r--",
                f"user:{telegram_uid}:r--",
            )
        )
    )


@dataclass(frozen=True, slots=True)
class PolicyOverlayAclProjection:
    core_uid: int
    telegram_uid: int
    entries: tuple[str, ...]
    file_uid: int
    file_gid: int
    file_mode: int

    def as_payload(self) -> dict[str, object]:
        return {
            "core_uid": self.core_uid,
            "entries": list(self.entries),
            "file_gid": self.file_gid,
            "file_mode": self.file_mode,
            "file_uid": self.file_uid,
            "schema": "myuna.p07-policy-overlay-acl.v1",
            "telegram_uid": self.telegram_uid,
        }

    @property
    def digest(self) -> str:
        return sha256(
            b"myuna-p07-policy-overlay-acl-v1\0" + _canonical(self.as_payload())
        ).hexdigest()


def _read_acl(path: Path) -> tuple[str, ...]:
    completed = subprocess.run(
        ["/usr/bin/getfacl", "-cpn", "--", str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    _require(
        completed.returncode == 0 and not completed.stderr.strip(),
        "policy_overlay_acl_unavailable",
    )
    entries = tuple(
        sorted(line.strip() for line in completed.stdout.splitlines() if line.strip())
    )
    _require(
        entries and all(not line.startswith("default:") for line in entries),
        "policy_overlay_acl_rejected",
    )
    return entries


def inspect_policy_overlay_acl(
    path: str | Path,
    *,
    core_uid: int,
    telegram_uid: int,
    file_gid: int,
) -> PolicyOverlayAclProjection:
    selected = Path(path)
    _require(selected.is_absolute(), "policy_overlay_acl_path_rejected")
    try:
        metadata = selected.lstat()
    except OSError as exc:
        raise PolicyOverlayAclRejected("policy_overlay_acl_unavailable") from exc
    _require(
        not selected.is_symlink() and stat.S_ISREG(metadata.st_mode),
        "policy_overlay_acl_type_rejected",
    )
    _require(
        metadata.st_uid == 0 and metadata.st_gid == file_gid,
        "policy_overlay_acl_owner_rejected",
    )
    _require(
        stat.S_IMODE(metadata.st_mode) == 0o640,
        "policy_overlay_acl_mode_rejected",
    )
    entries = _read_acl(selected)
    _require(
        entries == expected_entries(core_uid=core_uid, telegram_uid=telegram_uid),
        "policy_overlay_acl_rejected",
    )
    return PolicyOverlayAclProjection(
        core_uid=core_uid,
        telegram_uid=telegram_uid,
        entries=entries,
        file_uid=metadata.st_uid,
        file_gid=metadata.st_gid,
        file_mode=stat.S_IMODE(metadata.st_mode),
    )


def apply_policy_overlay_acl(
    path: str | Path,
    *,
    core_uid: int,
    telegram_uid: int,
    file_gid: int,
) -> PolicyOverlayAclProjection:
    _require(os.geteuid() == 0, "policy_overlay_acl_root_required")
    selected = Path(path)
    _require(selected.is_absolute(), "policy_overlay_acl_path_rejected")
    try:
        metadata = selected.lstat()
    except OSError as exc:
        raise PolicyOverlayAclRejected("policy_overlay_acl_unavailable") from exc
    _require(
        not selected.is_symlink() and stat.S_ISREG(metadata.st_mode),
        "policy_overlay_acl_type_rejected",
    )
    os.chown(selected, 0, file_gid)
    os.chmod(selected, 0o600)
    cleared = subprocess.run(
        ["/usr/bin/setfacl", "-bn", "--", str(selected)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    _require(cleared.returncode == 0, "policy_overlay_acl_apply_failed")
    applied = subprocess.run(
        [
            "/usr/bin/setfacl",
            "-m",
            (
                f"u:{core_uid}:r--,u:{telegram_uid}:r--,"
                "g::---,m::r--,o::---"
            ),
            "--",
            str(selected),
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    _require(applied.returncode == 0, "policy_overlay_acl_apply_failed")
    return inspect_policy_overlay_acl(
        selected,
        core_uid=core_uid,
        telegram_uid=telegram_uid,
        file_gid=file_gid,
    )
