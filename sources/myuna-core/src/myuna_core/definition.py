from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import stat
from typing import Any


class DefinitionReleaseError(RuntimeError):
    """Raised when an activated Definition release fails closed validation."""


@dataclass(frozen=True, slots=True)
class DefinitionRelease:
    root: Path
    definition_root: Path
    release_id: str
    version: str
    build_id: str
    source_sha256: str
    allowed_environments: tuple[str, ...]
    verified_files: int


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _safe_manifest_path(relative: str) -> PurePosixPath:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise DefinitionReleaseError("unsafe path in Definition release manifest")
    return pure


def _verify_release_manifest(root: Path) -> int:
    manifest = root / "evidence/release-files.sha256"
    verified = 0
    for line_number, raw in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw:
            continue
        try:
            expected, relative = raw.split("  ", 1)
        except ValueError as exc:
            raise DefinitionReleaseError(
                f"invalid Definition release manifest line {line_number}"
            ) from exc
        pure = _safe_manifest_path(relative)
        path = root.joinpath(*pure.parts)
        if not path.is_file() or sha256_file(path) != expected.upper():
            raise DefinitionReleaseError(f"Definition release manifest mismatch: {relative}")
        verified += 1
    if verified == 0:
        raise DefinitionReleaseError("Definition release manifest is empty")
    return verified


def _require_immutable_tree(root: Path) -> None:
    for path in (root, *root.rglob("*")):
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o222:
            raise DefinitionReleaseError(
                f"Definition release contains a writable path: {path.relative_to(root)}"
            )


def load_definition_release(
    configured_path: Path,
    *,
    expected_release_id: str,
    environment: str,
) -> DefinitionRelease:
    if not configured_path.is_absolute():
        raise DefinitionReleaseError("Definition release path must be absolute")
    try:
        root = configured_path.resolve(strict=True)
    except OSError as exc:
        raise DefinitionReleaseError("Definition release path is unavailable") from exc
    if not root.is_dir():
        raise DefinitionReleaseError("Definition release path is not a directory")

    summary_path = root / "evidence/release-summary.json"
    try:
        summary: dict[str, Any] = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DefinitionReleaseError("Definition release summary is invalid") from exc
    if (
        summary.get("schema_version") != 1
        or summary.get("status") != "approved-release"
        or summary.get("approved") is not True
        or summary.get("activation_allowed") is not True
    ):
        raise DefinitionReleaseError("Definition release is not approved for activation")
    if summary.get("release_id") != expected_release_id:
        raise DefinitionReleaseError("configured Definition release ID does not match the release")
    allowed = summary.get("allowed_environments")
    if (
        not isinstance(allowed, list)
        or any(not isinstance(item, str) for item in allowed)
        or environment not in allowed
    ):
        raise DefinitionReleaseError("Definition release is not approved for this environment")
    version = summary.get("version")
    build_id = summary.get("build_id")
    source_sha256 = summary.get("source_sha256")
    if not all(isinstance(item, str) and item for item in (version, build_id, source_sha256)):
        raise DefinitionReleaseError("Definition release identity is incomplete")

    verified = _verify_release_manifest(root)
    _require_immutable_tree(root)
    definition_root = root / "runtime-build/definition"
    if not (definition_root / "SKILL.md").is_file():
        raise DefinitionReleaseError("Definition release entrypoint is missing")
    return DefinitionRelease(
        root=root,
        definition_root=definition_root,
        release_id=expected_release_id,
        version=version,
        build_id=build_id,
        source_sha256=source_sha256,
        allowed_environments=tuple(allowed),
        verified_files=verified,
    )
