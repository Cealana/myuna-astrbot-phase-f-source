from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

from .active_selector import (
    ActiveProfileTarget,
    initialize_active_profile_store,
    install_active_profile_target,
    load_active_profile,
)
from .contracts import MAX_PROFILE_BYTES, PROFILE_FILENAME, OwnerProfileError
from .lifecycle_ledger import load_lifecycle_ledger
from .loader import load_approved_profile, parse_profile_bytes
from .write_publish import (
    initialize_profile_release_store,
    install_immutable_profile_release,
)
from .write_store import initialize_candidate_store, validate_candidate_store


class OwnerProfileWriteBootstrapError(OwnerProfileError):
    pass


def _reject(code: str, *, retryable: bool = False) -> OwnerProfileWriteBootstrapError:
    return OwnerProfileWriteBootstrapError(code, retryable=retryable)


def _read_source_profile(path: Path, *, expected_uid: int) -> bytes:
    profile_path = path / PROFILE_FILENAME
    try:
        before = profile_path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or not 1 <= before.st_size <= MAX_PROFILE_BYTES
        ):
            raise _reject("profile_write_bootstrap_source_drift")
        descriptor = os.open(
            profile_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OwnerProfileWriteBootstrapError:
        raise
    except OSError as exc:
        raise _reject("profile_write_bootstrap_unavailable", retryable=True) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != expected_uid
            or opened.st_nlink != 1
        ):
            raise _reject("profile_write_bootstrap_source_drift")
        payload = os.read(descriptor, MAX_PROFILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if not payload or len(payload) > MAX_PROFILE_BYTES or len(payload) != before.st_size:
        raise _reject("profile_write_bootstrap_source_drift")
    return payload


def bootstrap_profile_write_store(
    *,
    source_release: Path,
    source_sha256: str,
    write_root: Path,
    lifecycle_ledger: Path,
    expected_uid: int | None = None,
) -> bool:
    uid = os.geteuid() if expected_uid is None else expected_uid
    if (
        isinstance(uid, bool)
        or not isinstance(uid, int)
        or uid < 0
        or not source_release.is_absolute()
        or not write_root.is_absolute()
        or lifecycle_ledger != write_root / "ledger"
    ):
        raise _reject("profile_write_bootstrap_path_rejected")
    source = load_approved_profile(
        source_release,
        expected_sha256=source_sha256,
        expected_owner_uid=uid,
    )
    source_bytes = _read_source_profile(source_release, expected_uid=uid)
    if sha256(source_bytes).hexdigest() != source.sha256:
        raise _reject("profile_write_bootstrap_source_drift")
    state = load_lifecycle_ledger(
        lifecycle_ledger,
        profile_id=source.profile_id,
        expected_uid=uid,
    )
    baseline = state.revisions.get(source.profile_revision)
    if (
        state.active_revision != source.profile_revision
        or baseline is None
        or baseline.status != "published"
        or baseline.profile_sha256 != source.sha256
    ):
        raise _reject("profile_write_bootstrap_lifecycle_drift")
    initialize_active_profile_store(write_root, expected_uid=uid)
    initialize_profile_release_store(write_root / "releases", expected_uid=uid)
    initialize_candidate_store(write_root / "candidates", expected_uid=uid)
    install_immutable_profile_release(
        write_root / "releases",
        source_bytes,
        expected_uid=uid,
    )
    return install_active_profile_target(
        write_root,
        ActiveProfileTarget.from_profile(source),
        expected_current=None,
        expected_uid=uid,
    )


def validate_profile_write_store(
    *,
    write_root: Path,
    lifecycle_ledger: Path,
    expected_uid: int | None = None,
) -> None:
    uid = os.geteuid() if expected_uid is None else expected_uid
    if (
        isinstance(uid, bool)
        or not isinstance(uid, int)
        or uid < 0
        or not write_root.is_absolute()
        or lifecycle_ledger != write_root / "ledger"
    ):
        raise _reject("profile_write_bootstrap_path_rejected")
    active = load_active_profile(write_root, expected_uid=uid)
    state = load_lifecycle_ledger(
        lifecycle_ledger,
        profile_id=active.profile_id,
        expected_uid=uid,
    )
    revision = state.revisions.get(active.profile_revision)
    if (
        state.active_revision != active.profile_revision
        or revision is None
        or revision.status != "published"
        or revision.profile_sha256 != active.sha256
    ):
        raise _reject("profile_write_bootstrap_lifecycle_drift")
    validate_candidate_store(write_root / "candidates", expected_uid=uid)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-release", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--write-root", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.validate_only:
            validate_profile_write_store(
                write_root=arguments.write_root,
                lifecycle_ledger=arguments.write_root / "ledger",
            )
            created = False
        else:
            created = bootstrap_profile_write_store(
                source_release=arguments.source_release,
                source_sha256=arguments.source_sha256,
                write_root=arguments.write_root,
                lifecycle_ledger=arguments.write_root / "ledger",
            )
        print(
            json.dumps(
                {
                    "status": "PROFILE_WRITE_STORE_READY",
                    "created": created,
                    "raw_content_recorded": False,
                    "profile_digest_recorded": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except OwnerProfileError as exc:
        print(
            json.dumps(
                {
                    "status": "REJECTED",
                    "error_category": exc.code,
                    "raw_content_recorded": False,
                    "profile_digest_recorded": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
