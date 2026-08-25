from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import tomllib
import unicodedata

from .contracts import (
    DOCUMENT_TYPE,
    MAX_BODY_CHARACTERS,
    MAX_KEYWORD_CHARACTERS,
    MAX_KEYWORDS,
    MAX_PROFILE_BYTES,
    MAX_RECEIPT_BYTES,
    MAX_SECTIONS,
    MAX_TITLE_CHARACTERS,
    MAX_TOTAL_BODY_CHARACTERS,
    PROFILE_CATEGORIES,
    PROFILE_FILENAME,
    RECEIPT_FILENAME,
    RECEIPT_TYPE,
    SCHEMA_VERSION,
    OwnerProfile,
    OwnerProfileError,
    OwnerProfileSection,
    ProfileReceipt,
)


_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_KEYS = {
    "schema_version",
    "document_type",
    "profile_id",
    "profile_revision",
    "sections",
}
_SECTION_KEYS = {
    "section_id",
    "topic_key",
    "category",
    "title",
    "body",
    "keywords",
}
_RECEIPT_KEYS = {
    "schema_version",
    "receipt_type",
    "profile_sha256",
    "profile_bytes",
    "profile_schema_version",
    "profile_id",
    "profile_revision",
    "section_count",
    "category_counts",
}


def _safe_label(value: object) -> str:
    if not isinstance(value, str) or _SAFE_LABEL.fullmatch(value) is None:
        raise OwnerProfileError("malformed_profile")
    return value


def _clean_text(value: object, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise OwnerProfileError("malformed_profile")
    text = value.strip()
    if not text or len(text) > maximum or "\x00" in text:
        raise OwnerProfileError("malformed_profile")
    if any(
        unicodedata.category(character) == "Cc" and character not in "\n\r\t"
        for character in text
    ):
        raise OwnerProfileError("malformed_profile")
    return text


def _positive_int(value: object, *, error_code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise OwnerProfileError(error_code)
    return value


def _normalized_content(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(normalized.split())


def parse_profile_bytes(payload: bytes) -> OwnerProfile:
    if not payload or len(payload) > MAX_PROFILE_BYTES:
        raise OwnerProfileError("profile_oversize")
    try:
        parsed = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise OwnerProfileError("malformed_profile") from exc
    if not isinstance(parsed, dict) or set(parsed) != _PROFILE_KEYS:
        raise OwnerProfileError("malformed_profile")
    if parsed.get("schema_version") != SCHEMA_VERSION:
        raise OwnerProfileError("unknown_schema_version")
    if parsed.get("document_type") != DOCUMENT_TYPE:
        raise OwnerProfileError("malformed_profile")
    profile_id = _safe_label(parsed.get("profile_id"))
    profile_revision = _positive_int(
        parsed.get("profile_revision"),
        error_code="malformed_profile",
    )
    raw_sections = parsed.get("sections")
    if not isinstance(raw_sections, list) or not 1 <= len(raw_sections) <= MAX_SECTIONS:
        raise OwnerProfileError("malformed_profile")

    sections: list[OwnerProfileSection] = []
    section_ids: set[str] = set()
    topic_keys: set[str] = set()
    normalized_bodies: set[str] = set()
    total_body_characters = 0
    for raw in raw_sections:
        if not isinstance(raw, dict) or set(raw) != _SECTION_KEYS:
            raise OwnerProfileError("malformed_profile")
        section_id = _safe_label(raw.get("section_id"))
        topic_key = _safe_label(raw.get("topic_key"))
        category = raw.get("category")
        if category not in PROFILE_CATEGORIES:
            raise OwnerProfileError("malformed_profile")
        title = _clean_text(raw.get("title"), maximum=MAX_TITLE_CHARACTERS)
        body = _clean_text(raw.get("body"), maximum=MAX_BODY_CHARACTERS)
        raw_keywords = raw.get("keywords")
        if not isinstance(raw_keywords, list) or len(raw_keywords) > MAX_KEYWORDS:
            raise OwnerProfileError("malformed_profile")
        keywords = tuple(
            _clean_text(item, maximum=MAX_KEYWORD_CHARACTERS)
            for item in raw_keywords
        )
        normalized_keywords = [_normalized_content(item) for item in keywords]
        if len(normalized_keywords) != len(set(normalized_keywords)):
            raise OwnerProfileError("duplicate_keyword")
        normalized_body = _normalized_content(body)
        if section_id in section_ids:
            raise OwnerProfileError("duplicate_section_id")
        if normalized_body in normalized_bodies:
            raise OwnerProfileError("duplicate_section_content")
        if topic_key in topic_keys:
            raise OwnerProfileError("conflicting_topic_key")
        section_ids.add(section_id)
        topic_keys.add(topic_key)
        normalized_bodies.add(normalized_body)
        total_body_characters += len(body)
        sections.append(
            OwnerProfileSection(
                section_id=section_id,
                topic_key=topic_key,
                category=str(category),
                title=title,
                body=body,
                keywords=keywords,
            )
        )
    if total_body_characters > MAX_TOTAL_BODY_CHARACTERS:
        raise OwnerProfileError("profile_content_oversize")
    return OwnerProfile(
        profile_id=profile_id,
        profile_revision=profile_revision,
        sections=tuple(sections),
        sha256=sha256(payload).hexdigest(),
        byte_count=len(payload),
    )


def build_receipt(profile_bytes: bytes) -> dict[str, object]:
    profile = parse_profile_bytes(profile_bytes)
    return {
        "schema_version": 1,
        "receipt_type": RECEIPT_TYPE,
        "profile_sha256": profile.sha256,
        "profile_bytes": profile.byte_count,
        "profile_schema_version": SCHEMA_VERSION,
        "profile_id": profile.profile_id,
        "profile_revision": profile.profile_revision,
        "section_count": len(profile.sections),
        "category_counts": dict(profile.category_counts),
    }


def parse_receipt_bytes(payload: bytes) -> ProfileReceipt:
    if not payload or len(payload) > MAX_RECEIPT_BYTES:
        raise OwnerProfileError("malformed_receipt")
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OwnerProfileError("malformed_receipt") from exc
    if not isinstance(parsed, dict) or set(parsed) != _RECEIPT_KEYS:
        raise OwnerProfileError("malformed_receipt")
    digest = parsed.get("profile_sha256")
    if (
        parsed.get("schema_version") != 1
        or parsed.get("receipt_type") != RECEIPT_TYPE
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or parsed.get("profile_schema_version") != SCHEMA_VERSION
    ):
        raise OwnerProfileError("malformed_receipt")
    profile_bytes = _positive_int(
        parsed.get("profile_bytes"),
        error_code="malformed_receipt",
    )
    profile_revision = _positive_int(
        parsed.get("profile_revision"),
        error_code="malformed_receipt",
    )
    section_count = _positive_int(
        parsed.get("section_count"),
        error_code="malformed_receipt",
    )
    profile_id = parsed.get("profile_id")
    if not isinstance(profile_id, str) or _SAFE_LABEL.fullmatch(profile_id) is None:
        raise OwnerProfileError("malformed_receipt")
    raw_counts = parsed.get("category_counts")
    if not isinstance(raw_counts, dict) or not raw_counts:
        raise OwnerProfileError("malformed_receipt")
    counts: list[tuple[str, int]] = []
    for category in PROFILE_CATEGORIES:
        if category in raw_counts:
            counts.append(
                (
                    category,
                    _positive_int(
                        raw_counts[category],
                        error_code="malformed_receipt",
                    ),
                )
            )
    if set(raw_counts) != {category for category, _ in counts}:
        raise OwnerProfileError("malformed_receipt")
    return ProfileReceipt(
        profile_sha256=digest,
        profile_bytes=profile_bytes,
        profile_schema_version=SCHEMA_VERSION,
        profile_id=profile_id,
        profile_revision=profile_revision,
        section_count=section_count,
        category_counts=tuple(counts),
    )


def _validate_stat(
    result: os.stat_result,
    *,
    directory: bool,
    expected_uid: int,
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(result.st_mode) or stat.S_ISLNK(result.st_mode):
        raise OwnerProfileError("profile_type_drift")
    expected_mode = 0o700 if directory else 0o600
    if stat.S_IMODE(result.st_mode) != expected_mode or result.st_uid != expected_uid:
        raise OwnerProfileError("profile_permission_drift")


def _checked_stat(path: Path, *, directory: bool, expected_uid: int) -> os.stat_result:
    try:
        result = path.lstat()
    except OSError as exc:
        raise OwnerProfileError("profile_unavailable", retryable=True) from exc
    _validate_stat(result, directory=directory, expected_uid=expected_uid)
    return result


def _read_file_at(
    directory_descriptor: int,
    filename: str,
    *,
    maximum: int,
    expected_uid: int,
) -> bytes:
    try:
        before = os.stat(
            filename,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise OwnerProfileError("profile_unavailable", retryable=True) from exc
    _validate_stat(before, directory=False, expected_uid=expected_uid)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(filename, flags, dir_fd=directory_descriptor)
    except OSError as exc:
        raise OwnerProfileError("profile_unavailable", retryable=True) from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise OwnerProfileError("profile_type_drift")
        _validate_stat(opened, directory=False, expected_uid=expected_uid)
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(payload) > maximum:
        code = "profile_oversize" if filename == PROFILE_FILENAME else "malformed_receipt"
        raise OwnerProfileError(code)
    return payload


def load_approved_profile(
    release_directory: Path,
    *,
    expected_sha256: str,
    expected_owner_uid: int | None = None,
) -> OwnerProfile:
    if not isinstance(release_directory, Path) or not release_directory.is_absolute():
        raise OwnerProfileError("invalid_release_path")
    if not isinstance(expected_sha256, str) or _SHA256.fullmatch(expected_sha256) is None:
        raise OwnerProfileError("invalid_expected_digest")
    if (
        expected_owner_uid is not None
        and (
            isinstance(expected_owner_uid, bool)
            or not isinstance(expected_owner_uid, int)
            or expected_owner_uid < 0
        )
    ):
        raise OwnerProfileError("invalid_expected_owner")
    owner_uid = os.geteuid() if expected_owner_uid is None else expected_owner_uid
    before = _checked_stat(release_directory, directory=True, expected_uid=owner_uid)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_descriptor = os.open(release_directory, directory_flags)
    except OSError as exc:
        raise OwnerProfileError("profile_unavailable", retryable=True) from exc
    try:
        opened = os.fstat(directory_descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise OwnerProfileError("profile_type_drift")
        _validate_stat(opened, directory=True, expected_uid=owner_uid)
        profile_bytes = _read_file_at(
            directory_descriptor,
            PROFILE_FILENAME,
            maximum=MAX_PROFILE_BYTES,
            expected_uid=owner_uid,
        )
        receipt_bytes = _read_file_at(
            directory_descriptor,
            RECEIPT_FILENAME,
            maximum=MAX_RECEIPT_BYTES,
            expected_uid=owner_uid,
        )
    finally:
        os.close(directory_descriptor)
    profile = parse_profile_bytes(profile_bytes)
    receipt = parse_receipt_bytes(receipt_bytes)
    expected_directory_name = f"r{profile.profile_revision}-{expected_sha256}"
    if release_directory.name != expected_directory_name:
        raise OwnerProfileError("release_identity_mismatch")
    if profile.sha256 != expected_sha256:
        raise OwnerProfileError("profile_digest_mismatch")
    if receipt != ProfileReceipt(
        profile_sha256=profile.sha256,
        profile_bytes=profile.byte_count,
        profile_schema_version=SCHEMA_VERSION,
        profile_id=profile.profile_id,
        profile_revision=profile.profile_revision,
        section_count=len(profile.sections),
        category_counts=profile.category_counts,
    ):
        raise OwnerProfileError("receipt_mismatch")
    return profile
