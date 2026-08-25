#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any


class ActivationError(RuntimeError):
    pass


LOOPBACK_AUTHORIZATIONS = {
    "create_release": True,
    "activate_dev": True,
    "loopback_core_test": True,
    "real_memory": False,
    "tools": False,
    "external_listener": False,
    "astrbot_qq": False,
}
VOICE_HOTFIX_AUTHORIZATIONS = {
    "create_release": True,
    "activate_dev": True,
    "qq_owner_private_text": True,
    "restart_qq_core": True,
    "restart_channel_containers": False,
    "real_memory": False,
    "tools": False,
    "external_listener": False,
}


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActivationError(f"{label} is unavailable or invalid") from exc
    if not isinstance(value, dict):
        raise ActivationError(f"{label} must be a JSON object")
    return value


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def _verify_release_files(release_root: Path) -> int:
    manifest = release_root / "evidence/release-files.sha256"
    count = 0
    for line_number, line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line:
            continue
        try:
            expected, relative = line.split("  ", 1)
        except ValueError as exc:
            raise ActivationError(f"invalid release manifest line {line_number}") from exc
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise ActivationError("unsafe path in release manifest")
        candidate = release_root.joinpath(*pure.parts)
        if not candidate.is_file() or _sha256_file(candidate) != expected.upper():
            raise ActivationError(f"release checksum mismatch: {relative}")
        count += 1
    if count == 0:
        raise ActivationError("release manifest is empty")
    return count


def _verify_immutable(release_root: Path) -> None:
    for candidate in (release_root, *release_root.rglob("*")):
        if stat.S_IMODE(candidate.stat().st_mode) & 0o222:
            raise ActivationError(
                f"release path is writable: {candidate.relative_to(release_root)}"
            )


def _atomic_json(path: Path, document: dict[str, Any], mode: int) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_symlink(path: Path, target: Path) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.symlink_to(target, target_is_directory=True)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def activate(
    *,
    environment: str,
    release_root: Path,
    registry_path: Path,
    approval_path: Path,
    environments_root: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    if environment != "dev":
        raise ActivationError("current activation helper is dev-only")
    release_root = release_root.resolve(strict=True)
    registry = _load_object(registry_path, "Definition registry")
    approval = _load_object(approval_path, "release approval")
    summary = _load_object(
        release_root / "evidence/release-summary.json", "release summary"
    )
    if registry.get("schema_version") != 1 or summary.get("schema_version") != 1:
        raise ActivationError("unsupported registry or release schema")
    required_approval = {
        "approved": True,
        "version": summary.get("version"),
        "build_id": summary.get("build_id"),
        "source_sha256": summary.get("source_sha256"),
    }
    for key, expected in required_approval.items():
        if approval.get(key) != expected:
            raise ActivationError(f"release approval mismatch: {key}")
    authorizations = approval.get("authorizations")
    scope = approval.get("scope", "definition-v5-dev-release-only")
    expected_authorizations = (
        VOICE_HOTFIX_AUTHORIZATIONS
        if scope == "definition-v5-dev-qq-voice-hotfix-only"
        else LOOPBACK_AUTHORIZATIONS
    )
    if authorizations != expected_authorizations:
        raise ActivationError("approval authorizations do not match the loopback gate")
    if scope == "definition-v5-dev-qq-voice-hotfix-only":
        digest = approval.get("activation_plan_digest")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ActivationError("voice hotfix approval plan digest is invalid")
    if environment not in approval.get("allowed_environments", []):
        raise ActivationError("approval does not allow the selected environment")
    if (
        summary.get("status") != "approved-release"
        or summary.get("approved") is not True
        or summary.get("activation_allowed") is not True
        or environment not in summary.get("allowed_environments", [])
    ):
        raise ActivationError("release summary does not allow activation")

    release_id = summary.get("release_id")
    release_entries = registry.get("releases")
    if not isinstance(release_id, str) or not isinstance(release_entries, list):
        raise ActivationError("release identity or registry release list is invalid")
    matching = [entry for entry in release_entries if entry.get("release_id") == release_id]
    if len(matching) != 1:
        raise ActivationError("release is not uniquely registered")
    registered_path = (registry_path.parent / matching[0]["path"]).resolve(strict=True)
    if registered_path != release_root:
        raise ActivationError("release path does not match the Definition registry")

    verified_files = _verify_release_files(release_root)
    _verify_immutable(release_root)
    definition_dir = environments_root / environment / "definition"
    definition_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    current = definition_dir / "current"
    previous = definition_dir / "previous"
    previous_target: str | None = None
    if current.exists() or current.is_symlink():
        if not current.is_symlink():
            raise ActivationError("current Definition pointer is not a symlink")
        old_target = current.resolve(strict=True)
        previous_target = str(old_target)
        if old_target != release_root:
            _atomic_symlink(previous, old_target)
    _atomic_symlink(current, release_root)

    prior_version = registry.get("active_version")
    prior_release_ids = [
        entry.get("release_id")
        for entry in release_entries
        if environment in entry.get("active_environments", [])
    ]
    if len(prior_release_ids) > 1:
        raise ActivationError("multiple Definition releases are active before activation")
    prior_release_id = prior_release_ids[0] if prior_release_ids else None
    for entry in release_entries:
        active = entry.get("active_environments", [])
        if not isinstance(active, list):
            raise ActivationError("registry active_environments must be a list")
        active = [item for item in active if item != environment]
        if entry.get("release_id") == release_id:
            active.append(environment)
        entry["active_environments"] = sorted(set(active))
    for candidate in registry.get("candidates", []):
        if isinstance(candidate, dict):
            candidate["active"] = candidate.get("version") == summary.get("version")
    registry["previous_version"] = (
        prior_version if prior_version != summary.get("version") else registry.get("previous_version")
    )
    registry["active_version"] = summary.get("version")
    registry["previous_release_id"] = (
        prior_release_id
        if prior_release_id and prior_release_id != release_id
        else registry.get("previous_release_id")
    )
    registry["active_release_id"] = release_id
    _atomic_json(registry_path, registry, 0o640)

    timestamp = (now or datetime.now(timezone.utc)).astimezone().isoformat()
    record: dict[str, Any] = {
        "schema_version": 1,
        "environment": environment,
        "release_id": release_id,
        "version": summary.get("version"),
        "build_id": summary.get("build_id"),
        "source_sha256": summary.get("source_sha256"),
        "release_path": str(release_root),
        "previous_target": previous_target,
        "activated_at": timestamp,
        "activated_by": "server-owner-approved-codex-deployment",
        "approval_sha256": _sha256_file(approval_path),
        "verified_release_files": verified_files,
        "scope": (
            "qq-owner-private-dev-voice-hotfix-only"
            if scope == "definition-v5-dev-qq-voice-hotfix-only"
            else "loopback-dev-conversation-only"
        ),
        "previous_release_id": prior_release_id,
    }
    _atomic_json(definition_dir / "activation.json", record, 0o640)
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", default="dev")
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--environments-root", type=Path, required=True)
    args = parser.parse_args()
    record = activate(
        environment=args.environment,
        release_root=args.release_root,
        registry_path=args.registry,
        approval_path=args.approval,
        environments_root=args.environments_root,
    )
    print(
        json.dumps(
            {
                "environment": record["environment"],
                "release_id": record["release_id"],
                "verified_release_files": record["verified_release_files"],
                "scope": record["scope"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
