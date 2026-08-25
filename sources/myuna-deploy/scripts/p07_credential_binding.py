#!/usr/bin/env python3
"""Strict, content-free P07 credential declaration contract."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import stat


CREDENTIAL_NAME = "deepseek_api_key"
DIRECTIVE_PREFIX = f"LoadCredential={CREDENTIAL_NAME}:"
FEATURE_FLAG = "Environment=MYUNA_P07_HYBRID_EXTERNAL_ENABLED=true"


class CredentialBindingRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CredentialBindingRejected(code)


def _digest(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def canonical_hybrid_gate() -> bytes:
    return f"[Service]\n{FEATURE_FLAG}\n".encode("ascii")


def legacy_duplicate_hybrid_gate(source: Path) -> bytes:
    return (
        f"[Service]\n{DIRECTIVE_PREFIX}{source.as_posix()}\n{FEATURE_FLAG}\n"
    ).encode("ascii")


def _read_regular_dropin(path: Path, *, expected_uid: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CredentialBindingRejected("credential_dropin_unavailable") from exc
    _require(
        not path.is_symlink() and stat.S_ISREG(metadata.st_mode),
        "credential_dropin_type_rejected",
    )
    _require(metadata.st_uid == expected_uid, "credential_dropin_owner_rejected")
    _require(
        stat.S_IMODE(metadata.st_mode) & 0o022 == 0,
        "credential_dropin_mode_rejected",
    )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CredentialBindingRejected("credential_dropin_unavailable") from exc


def credential_declarations(
    dropin_root: Path,
    *,
    expected_uid: int = 0,
) -> tuple[tuple[str, Path], ...]:
    _require(
        dropin_root.is_absolute(),
        "credential_dropin_root_rejected",
    )
    try:
        root_metadata = dropin_root.lstat()
    except OSError as exc:
        raise CredentialBindingRejected("credential_dropin_root_unavailable") from exc
    _require(
        not dropin_root.is_symlink() and stat.S_ISDIR(root_metadata.st_mode),
        "credential_dropin_root_type_rejected",
    )
    declarations: list[tuple[str, Path]] = []
    for dropin in sorted(dropin_root.glob("*.conf"), key=lambda item: item.name):
        payload = _read_regular_dropin(dropin, expected_uid=expected_uid)
        try:
            lines = payload.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise CredentialBindingRejected("credential_dropin_encoding_rejected") from exc
        for line in lines:
            if line.startswith(f"LoadCredential={CREDENTIAL_NAME}") and not line.startswith(
                DIRECTIVE_PREFIX
            ):
                raise CredentialBindingRejected("credential_declaration_malformed")
            if line.startswith(DIRECTIVE_PREFIX):
                source_text = line.removeprefix(DIRECTIVE_PREFIX)
                source = Path(source_text)
                _require(
                    source.is_absolute() and source.as_posix() == source_text,
                    "credential_source_path_rejected",
                )
                declarations.append((dropin.name, source))
    return tuple(declarations)


def effective_credential_declarations(
    dropin_root: Path,
    *,
    expected_uid: int = 0,
) -> tuple[tuple[str, Path], ...]:
    """Resolve the target credential after ordered systemd list resets.

    ``LoadCredential=`` is a list reset. Counting matching declarations
    without applying that reset can accept a configuration whose final
    effective set no longer contains ``deepseek_api_key``.
    """
    _require(dropin_root.is_absolute(), "credential_dropin_root_rejected")
    try:
        root_metadata = dropin_root.lstat()
    except OSError as exc:
        raise CredentialBindingRejected("credential_dropin_root_unavailable") from exc
    _require(
        not dropin_root.is_symlink() and stat.S_ISDIR(root_metadata.st_mode),
        "credential_dropin_root_type_rejected",
    )
    effective: list[tuple[str, Path]] = []
    for dropin in sorted(dropin_root.glob("*.conf"), key=lambda item: item.name):
        payload = _read_regular_dropin(dropin, expected_uid=expected_uid)
        try:
            lines = payload.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise CredentialBindingRejected(
                "credential_dropin_encoding_rejected"
            ) from exc
        for line in lines:
            directive = line.strip()
            if directive == "LoadCredential=":
                effective.clear()
                continue
            if directive.startswith(f"LoadCredential={CREDENTIAL_NAME}") and not directive.startswith(
                DIRECTIVE_PREFIX
            ):
                raise CredentialBindingRejected("credential_declaration_malformed")
            if directive.startswith(DIRECTIVE_PREFIX):
                source_text = directive.removeprefix(DIRECTIVE_PREFIX)
                source = Path(source_text)
                _require(
                    source.is_absolute() and source.as_posix() == source_text,
                    "credential_source_path_rejected",
                )
                effective.append((dropin.name, source))
    return tuple(effective)


def verify_source_metadata(source: Path, *, expected_uid: int = 0) -> dict[str, int]:
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise CredentialBindingRejected("credential_source_unavailable") from exc
    _require(
        not source.is_symlink() and stat.S_ISREG(metadata.st_mode),
        "credential_source_type_rejected",
    )
    _require(metadata.st_uid == expected_uid, "credential_source_owner_rejected")
    mode = stat.S_IMODE(metadata.st_mode)
    _require(mode == 0o600, "credential_source_mode_rejected")
    return {"gid": metadata.st_gid, "mode": mode, "uid": metadata.st_uid}


def verify_strict_binding(
    dropin_root: Path,
    *,
    canonical_dropin: str,
    expected_source: Path,
    expected_uid: int = 0,
) -> dict[str, object]:
    declarations = credential_declarations(dropin_root, expected_uid=expected_uid)
    canonical = tuple(
        declaration
        for declaration in declarations
        if declaration[0] == canonical_dropin
    )
    _require(len(canonical) == 1, "credential_owner_dropin_rejected")
    _require(
        all(source == expected_source for _name, source in declarations),
        "credential_source_drifted",
    )
    effective = effective_credential_declarations(
        dropin_root,
        expected_uid=expected_uid,
    )
    _require(len(effective) == 1, "credential_category_rejected")
    effective_dropin, effective_source = effective[0]
    _require(len(declarations) in {1, 2}, "credential_category_rejected")
    _require(
        len(declarations) == 1 or effective_dropin != canonical_dropin,
        "credential_category_rejected",
    )
    _require(effective_source == expected_source, "credential_source_drifted")
    canonical_metadata = (dropin_root / canonical_dropin).lstat()
    _require(
        canonical_metadata.st_uid == expected_uid
        and stat.S_IMODE(canonical_metadata.st_mode) == 0o644,
        "credential_canonical_dropin_permission_rejected",
    )
    source_metadata = verify_source_metadata(
        expected_source,
        expected_uid=expected_uid,
    )
    return {
        "canonical_dropin": canonical_dropin,
        "declaration_count": len(declarations),
        "effective_declaration_count": 1,
        "effective_dropin": effective_dropin,
        "source_metadata": source_metadata,
        "status": "strict",
    }


def verify_reconcilable_duplicate(
    dropin_root: Path,
    *,
    canonical_dropin: str,
    redundant_dropin: str,
    expected_source: Path,
    expected_uid: int = 0,
) -> dict[str, object]:
    declarations = credential_declarations(dropin_root, expected_uid=expected_uid)
    _require(len(declarations) == 2, "credential_duplicate_count_rejected")
    names = tuple(name for name, _source in declarations)
    sources = tuple(source for _name, source in declarations)
    _require(
        set(names) == {canonical_dropin, redundant_dropin},
        "credential_duplicate_owner_rejected",
    )
    _require(
        len(set(sources)) == 1 and sources[0] == expected_source,
        "credential_duplicate_source_rejected",
    )
    source_metadata = verify_source_metadata(expected_source, expected_uid=expected_uid)
    redundant_path = dropin_root / redundant_dropin
    redundant_payload = _read_regular_dropin(
        redundant_path,
        expected_uid=expected_uid,
    )
    _require(
        redundant_payload == legacy_duplicate_hybrid_gate(expected_source),
        "credential_redundant_dropin_drifted",
    )
    redundant_metadata = redundant_path.lstat()
    canonical_path = dropin_root / canonical_dropin
    canonical_payload = _read_regular_dropin(
        canonical_path,
        expected_uid=expected_uid,
    )
    canonical_metadata = canonical_path.lstat()
    _require(
        redundant_metadata.st_uid == expected_uid
        and stat.S_IMODE(redundant_metadata.st_mode) == 0o644,
        "credential_redundant_dropin_permission_rejected",
    )
    _require(
        canonical_metadata.st_uid == expected_uid
        and stat.S_IMODE(canonical_metadata.st_mode) == 0o644,
        "credential_canonical_dropin_permission_rejected",
    )
    return {
        "canonical_dropin_sha256": _digest(canonical_payload),
        "declaration_count": 2,
        "redundant_dropin_gid": redundant_metadata.st_gid,
        "redundant_dropin_mode": stat.S_IMODE(redundant_metadata.st_mode),
        "redundant_dropin_sha256": _digest(redundant_payload),
        "source_metadata": source_metadata,
        "status": "reconcilable_duplicate",
        "target_dropin_sha256": _digest(canonical_hybrid_gate()),
        "canonical_dropin_gid": canonical_metadata.st_gid,
        "canonical_dropin_mode": stat.S_IMODE(canonical_metadata.st_mode),
    }


def verify_effective_credential(
    credential: Path,
    *,
    expected_uid: int = 0,
) -> dict[str, int]:
    try:
        metadata = credential.lstat()
    except OSError as exc:
        raise CredentialBindingRejected("effective_credential_unavailable") from exc
    _require(
        not credential.is_symlink() and stat.S_ISREG(metadata.st_mode),
        "effective_credential_type_rejected",
    )
    _require(metadata.st_uid == expected_uid, "effective_credential_owner_rejected")
    mode = stat.S_IMODE(metadata.st_mode)
    _require(mode == 0o440, "effective_credential_mode_rejected")
    return {"gid": metadata.st_gid, "mode": mode, "uid": metadata.st_uid}
