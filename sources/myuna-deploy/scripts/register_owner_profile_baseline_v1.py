#!/usr/bin/env python3
"""Register one exact Owner-approved baseline in the private lifecycle ledger."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import stat
from typing import Sequence

from install_owner_profile_data_v1 import (
    DEFAULT_INTAKE_ROOT,
    OwnerProfileInstallError,
    load_intake_bundle,
)
from install_owner_profile_service_identity_v1 import validate_service_identity
from myuna_core.owner_profile.contracts import OwnerProfileError
from myuna_core.owner_profile.lifecycle import (
    GENESIS_DIGEST,
    LifecycleEvent,
    LifecycleState,
    OwnerProfileLifecycleError,
)
from myuna_core.owner_profile.lifecycle_ledger import (
    append_lifecycle_event,
    initialize_lifecycle_ledger,
    load_lifecycle_ledger,
)
from myuna_core.owner_profile.loader import load_approved_profile


LEDGER_ROOT = Path("/var/lib/myuna-owner-profile-write-v1")
LEDGER_DIRECTORY = LEDGER_ROOT / "ledger"
PRIVATE_DIRECTORY_MODE = 0o700


class OwnerProfileBaselineRegisterError(RuntimeError):
    """A deterministic content-free baseline registration rejection."""


def _reject(code: str) -> OwnerProfileBaselineRegisterError:
    return OwnerProfileBaselineRegisterError(code)


def _ensure_private_directory(path: Path, *, uid: int, gid: int) -> None:
    try:
        path.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        os.chown(path, uid, gid)
        os.chmod(path, PRIVATE_DIRECTORY_MODE)
    except FileExistsError:
        pass
    except OSError as exc:
        raise _reject("baseline_ledger_unavailable") from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _reject("baseline_ledger_unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise _reject("baseline_ledger_rejected")


def _baseline_event(
    *,
    profile_id: str,
    revision: int,
    profile_sha256: str,
    confirmation_sha256: str,
) -> LifecycleEvent:
    event_seed = (
        f"baseline:{revision}:{profile_sha256}:{confirmation_sha256}"
    ).encode("ascii")
    return LifecycleEvent(
        event_type="baseline_registered",
        event_id=f"baseline-r{revision}-{sha256(event_seed).hexdigest()[:24]}",
        sequence=1,
        previous_event_sha256=GENESIS_DIGEST,
        profile_id=profile_id,
        base_revision=None,
        base_sha256=None,
        target_revision=revision,
        target_sha256=profile_sha256,
        confirmation_sha256=confirmation_sha256,
        reason_category="initial_registration",
    )


def _is_exact_registered(state: LifecycleState, event: LifecycleEvent) -> bool:
    if (
        state.last_sequence != 1
        or state.active_revision != event.target_revision
        or state.last_event_sha256 != event.sha256
        or set(state.revisions) != {event.target_revision}
    ):
        return False
    record = state.revisions[event.target_revision]
    return (
        record.revision == event.target_revision
        and record.profile_sha256 == event.target_sha256
        and record.status == "published"
        and record.confirmation_sha256 == event.confirmation_sha256
    )


def register_baseline(
    intake: Path,
    installed_release: Path,
    *,
    intake_uid: int,
    intake_root: Path = DEFAULT_INTAKE_ROOT,
    service_uid: int,
    ledger_root: Path = LEDGER_ROOT,
    ledger_directory: Path = LEDGER_DIRECTORY,
    ledger_uid: int = 0,
    ledger_gid: int = 0,
) -> tuple[LifecycleState, bool]:
    if (
        os.geteuid() != ledger_uid
        or isinstance(intake_uid, bool)
        or not isinstance(intake_uid, int)
        or intake_uid < 1
        or isinstance(service_uid, bool)
        or not isinstance(service_uid, int)
        or service_uid < 1
        or not ledger_root.is_absolute()
        or intake.parent != intake_root
        or ledger_directory.parent != ledger_root
    ):
        raise _reject("baseline_request_rejected")
    try:
        intake_bundle = load_intake_bundle(
            intake,
            intake_uid=intake_uid, allowed_roots=(intake_root,),
        )
        installed = load_approved_profile(
            installed_release,
            expected_sha256=intake_bundle.profile.sha256,
            expected_owner_uid=service_uid,
        )
    except (OwnerProfileInstallError, OwnerProfileError) as exc:
        raise _reject(str(exc)) from exc
    except OSError as exc:
        raise _reject("baseline_source_unavailable") from exc
    if installed != intake_bundle.profile:
        raise _reject("baseline_release_mismatch")
    event = _baseline_event(
        profile_id=installed.profile_id,
        revision=installed.profile_revision,
        profile_sha256=installed.sha256,
        confirmation_sha256=sha256(intake_bundle.approval_bytes).hexdigest(),
    )
    _ensure_private_directory(ledger_root, uid=ledger_uid, gid=ledger_gid)
    try:
        initialize_lifecycle_ledger(
            ledger_directory,
            expected_uid=ledger_uid,
        )
        state = load_lifecycle_ledger(
            ledger_directory,
            profile_id=installed.profile_id,
            expected_uid=ledger_uid,
        )
        if state.last_sequence == 0:
            state = append_lifecycle_event(
                ledger_directory,
                event,
                expected_uid=ledger_uid,
            )
            created = True
        elif _is_exact_registered(state, event):
            created = False
        else:
            raise _reject("baseline_existing_conflict")
    except OwnerProfileBaselineRegisterError:
        raise
    except OwnerProfileLifecycleError as exc:
        raise _reject(exc.code) from exc
    if not _is_exact_registered(state, event):
        raise _reject("baseline_postwrite_rejected")
    return state, created


def _status(created: bool, revision: int) -> str:
    return json.dumps(
        {
            "status": "BASELINE_REGISTERED_PRIVATE_LEDGER",
            "created": created,
            "profile_revision": revision,
            "active_revision": revision,
            "event_sequence": 1,
            "raw_content_recorded": False,
            "profile_digest_recorded": False,
            "profile_identity_recorded": False,
            "legacy_namespace_written": False,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--intake", required=True, type=Path)
    parser.add_argument("--installed-release", required=True, type=Path)
    parser.add_argument("--owner-account", default="serveradmin")
    arguments = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise _reject("baseline_requires_root")
        try:
            owner = pwd.getpwnam(arguments.owner_account)
        except KeyError as exc:
            raise _reject("baseline_owner_missing") from exc
        service_uid, _ = validate_service_identity()
        state, created = register_baseline(
            arguments.intake,
            arguments.installed_release,
            intake_uid=owner.pw_uid,
            service_uid=service_uid,
        )
        assert state.active_revision is not None
        print(_status(created, state.active_revision))
        return 0
    except OwnerProfileBaselineRegisterError as exc:
        print(
            json.dumps(
                {
                    "status": "REJECTED",
                    "error_category": str(exc),
                    "raw_content_recorded": False,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
