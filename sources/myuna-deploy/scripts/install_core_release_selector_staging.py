"""Install Core Release Selector v1 artifacts into inactive staging only.

The CLI has fixed production roots and never writes an active systemd drop-in,
runtime binding, marker, EnvironmentFile, or service state.  It performs no
daemon reload and no service lifecycle action.  Test-only callers may supply
temporary physical roots through ``install_inactive_staging``.
"""

from __future__ import annotations

import argparse
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
from typing import Mapping, Sequence

from core_release_selector import (
    GUARD_DROPIN,
    INSTANCE,
    STABLE_SELECTOR_DROPIN,
    UNIT,
    build_binding_intent,
    canonical_json_bytes,
    load_binding_intent,
    load_selection_candidate,
    parse_json_document,
    render_guard_dropin,
    render_selector_dropin,
)


FORMAL_DEPLOY = Path("/srv/myuna/repos/deploy")
TOOL_RELEASE_ROOT = Path("/opt/myuna/core-release-selector/releases")
CANDIDATE_ROOT = Path("/etc/myuna/core-release-selector/candidates")

SELECTOR_SOURCE = Path("scripts/core_release_selector.py")
CANDIDATE_SOURCE = Path("config/core-release-selector-v1.json")
INTENT_SOURCE = Path("config/core-release-selector-v1-binding-intent.json")

STAGED_CANDIDATE = "selection-candidate.json"
STAGED_INTENT = "qq.binding-intent.json"
STAGED_MANIFEST = "STAGING_MANIFEST.json"

STAGING_MANIFEST_SCHEMA = "myuna.core-release-selector.inactive-staging-manifest.v1"
STAGING_STATUS = "inactive_staging"

ACTIVE_RUNTIME_BINDING = Path("/etc/myuna/core-release-selector/qq.binding.json")
ACTIVE_GUARD_DROPIN = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/05-core-release-selector-guard-v1.conf"
)
ACTIVE_SELECTOR_DROPIN = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf"
)

_HEX_64 = re.compile(r"^[a-f0-9]{64}$")


class StagingInstallError(RuntimeError):
    """A deterministic inactive-install rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise StagingInstallError(code)


def digest_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _group_gid() -> int:
    try:
        return grp.getgrnam("myuna").gr_gid
    except KeyError as exc:
        raise StagingInstallError("myuna_group_missing") from exc


def _require_digest(value: str, code: str) -> str:
    require(isinstance(value, str) and _HEX_64.fullmatch(value) is not None, code)
    return value


def _ensure_parent(path: Path, *, uid: int, gid: int) -> None:
    if path.exists():
        require(not path.is_symlink() and path.is_dir(), "staging_parent_rejected")
    else:
        require(path.parent.is_dir() and not path.parent.is_symlink(), "staging_parent_missing")
        path.mkdir(mode=0o750)
        os.chown(path, uid, gid)
    metadata = path.stat()
    require(metadata.st_uid == uid and metadata.st_gid == gid, "staging_parent_owner_rejected")
    require(stat.S_IMODE(metadata.st_mode) == 0o750, "staging_parent_mode_rejected")


def _verify_directory(
    destination: Path,
    payloads: Mapping[str, bytes],
    *,
    uid: int,
    gid: int,
) -> None:
    require(not destination.is_symlink() and destination.is_dir(), "staged_directory_rejected")
    metadata = destination.stat()
    require(metadata.st_uid == uid and metadata.st_gid == gid, "staged_directory_owner_rejected")
    require(stat.S_IMODE(metadata.st_mode) == 0o550, "staged_directory_mode_rejected")
    entries = sorted(destination.iterdir(), key=lambda item: item.name)
    require([entry.name for entry in entries] == sorted(payloads), "staged_file_set_rejected")
    for entry in entries:
        require(not entry.is_symlink() and entry.is_file(), "staged_file_rejected")
        file_metadata = entry.stat()
        require(file_metadata.st_uid == uid and file_metadata.st_gid == gid, "staged_file_owner_rejected")
        require(stat.S_IMODE(file_metadata.st_mode) == 0o440, "staged_file_mode_rejected")
        require(entry.read_bytes() == payloads[entry.name], "staged_file_content_rejected")


def _install_directory(
    destination: Path,
    payloads: Mapping[str, bytes],
    *,
    uid: int,
    gid: int,
) -> bool:
    require(payloads and all("/" not in name and name not in {"", ".", ".."} for name in payloads), "staged_name_rejected")
    if destination.exists():
        _verify_directory(destination, payloads, uid=uid, gid=gid)
        return False
    require(not destination.is_symlink(), "staged_destination_rejected")
    temporary = destination.parent / f".{destination.name}.{os.getpid()}.tmp"
    require(not temporary.exists() and not temporary.is_symlink(), "staged_temporary_exists")
    try:
        temporary.mkdir(mode=0o700)
        for name, payload in payloads.items():
            target = temporary / name
            target.write_bytes(payload)
            os.chown(target, uid, gid)
            target.chmod(0o440)
        os.chown(temporary, uid, gid)
        temporary.chmod(0o550)
        os.replace(temporary, destination)
    except Exception:
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary)
        raise
    _verify_directory(destination, payloads, uid=uid, gid=gid)
    return True


def build_inactive_payloads(
    source_root: Path, *, approved_plan_digest: str
) -> tuple[str, dict[str, bytes], dict[str, bytes]]:
    approval = _require_digest(approved_plan_digest, "approved_plan_digest_rejected")
    selector_source = (source_root / SELECTOR_SOURCE).read_bytes()
    verifier_sha256 = digest_bytes(selector_source)
    verifier_path = (
        TOOL_RELEASE_ROOT / verifier_sha256 / "core_release_selector.py"
    ).as_posix()

    candidate_payload = parse_json_document((source_root / CANDIDATE_SOURCE).read_bytes())
    candidate = load_selection_candidate(candidate_payload)
    intent_payload = parse_json_document((source_root / INTENT_SOURCE).read_bytes())
    intent = load_binding_intent(intent_payload)
    expected_intent = build_binding_intent(
        candidate,
        verifier_script_path=verifier_path,
        verifier_script_sha256=verifier_sha256,
    )
    require(intent.to_payload() == expected_intent.to_payload(), "binding_intent_source_rejected")

    selector = render_selector_dropin(candidate).encode("utf-8")
    guard = render_guard_dropin(verifier_path).encode("utf-8")
    staged_components = {
        STAGED_CANDIDATE: canonical_json_bytes(candidate.to_payload()),
        STAGED_INTENT: canonical_json_bytes(intent.to_payload()),
        GUARD_DROPIN: guard,
        STABLE_SELECTOR_DROPIN: selector,
    }
    manifest = {
        "schema": STAGING_MANIFEST_SCHEMA,
        "status": STAGING_STATUS,
        "unit": UNIT,
        "instance": INSTANCE,
        "approved_inactive_install_plan_digest": approval,
        "tool_release": {
            "path": verifier_path,
            "sha256": verifier_sha256,
        },
        "selection": {
            "tree_sha256": candidate.selected_release.tree_sha256,
            "candidate_canonical_sha256": intent.candidate_canonical_sha256,
        },
        "artifacts": {
            name: digest_bytes(payload) for name, payload in sorted(staged_components.items())
        },
        "runtime_binding_present": False,
        "active_systemd_dropin_written": False,
        "daemon_reload_performed": False,
        "service_lifecycle_performed": False,
    }
    staged_components[STAGED_MANIFEST] = canonical_json_bytes(manifest)
    tool_payloads = {"core_release_selector.py": selector_source}
    return verifier_sha256, tool_payloads, staged_components


def install_inactive_staging(
    approved_plan_digest: str,
    *,
    source_root: Path = FORMAL_DEPLOY,
    tool_release_root: Path = TOOL_RELEASE_ROOT,
    candidate_root: Path = CANDIDATE_ROOT,
    uid: int = 0,
    gid: int | None = None,
) -> dict[str, object]:
    approval = _require_digest(approved_plan_digest, "approved_plan_digest_rejected")
    if gid is None:
        gid = _group_gid()
    verifier_sha256, tool_payloads, staged_payloads = build_inactive_payloads(
        source_root, approved_plan_digest=approval
    )
    require(
        ACTIVE_RUNTIME_BINDING not in (tool_release_root, candidate_root)
        and ACTIVE_GUARD_DROPIN not in (tool_release_root, candidate_root)
        and ACTIVE_SELECTOR_DROPIN not in (tool_release_root, candidate_root),
        "active_path_rejected",
    )

    _ensure_parent(tool_release_root.parent, uid=uid, gid=gid)
    _ensure_parent(tool_release_root, uid=uid, gid=gid)
    _ensure_parent(candidate_root.parent, uid=uid, gid=gid)
    _ensure_parent(candidate_root, uid=uid, gid=gid)

    tool_destination = tool_release_root / verifier_sha256
    staging_destination = candidate_root / approval
    tool_created = _install_directory(
        tool_destination, tool_payloads, uid=uid, gid=gid
    )
    staging_created = _install_directory(
        staging_destination, staged_payloads, uid=uid, gid=gid
    )
    return {
        "status": "inactive_staging_installed",
        "approved_plan_digest": approval,
        "tool_release_sha256": verifier_sha256,
        "tool_destination": tool_destination.as_posix(),
        "staging_destination": staging_destination.as_posix(),
        "tool_created": tool_created,
        "staging_created": staging_created,
        "runtime_changed": False,
        "systemd_changed": False,
        "daemon_reload_performed": False,
        "service_lifecycle_performed": False,
        "selected_or_activated": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install Core Release Selector v1 into inactive staging"
    )
    parser.add_argument("--approved-plan-digest", required=True)
    arguments = parser.parse_args(argv)
    if pwd.getpwuid(os.geteuid()).pw_name != "root":
        raise StagingInstallError("must_run_as_root")
    result = install_inactive_staging(arguments.approved_plan_digest)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
