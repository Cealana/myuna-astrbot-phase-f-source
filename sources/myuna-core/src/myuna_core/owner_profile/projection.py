from __future__ import annotations

from collections import Counter
import math

from .contracts import (
    AUDIT_NAMESPACE,
    PROFILE_CATEGORIES,
    SCHEMA_VERSION,
    OwnerProfileError,
    ProfileCurrentValue,
    ProfileModuleManifest,
    RetrievalResult,
)


_PUBLIC_ERROR_CATEGORIES = frozenset(
    {
        "conflicting_topic_key",
        "duplicate_keyword",
        "duplicate_section_content",
        "duplicate_section_id",
        "invalid_expected_digest",
        "invalid_expected_owner",
        "invalid_release_path",
        "invalid_timeout",
        "malformed_profile",
        "malformed_receipt",
        "profile_content_oversize",
        "profile_digest_mismatch",
        "profile_oversize",
        "profile_permission_drift",
        "profile_timeout",
        "profile_type_drift",
        "profile_unavailable",
        "query_out_of_contract",
        "receipt_mismatch",
        "release_identity_mismatch",
        "unknown_schema_version",
    }
)


def _duration(value: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError("duration must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError("duration must be finite and non-negative")
    return round(result, 3)


def _query_length_bucket(characters: int) -> str:
    if isinstance(characters, bool) or not isinstance(characters, int) or characters < 0:
        raise ValueError("query length is invalid")
    if characters == 0:
        return "0"
    if characters <= 32:
        return "1-32"
    if characters <= 128:
        return "33-128"
    if characters <= 256:
        return "129-256"
    return "257+"


def success_audit_projection(
    result: RetrievalResult,
    *,
    duration_ms: float,
) -> dict[str, object]:
    if result.state not in {"empty", "selected"}:
        raise ValueError("retrieval state is invalid")
    if (
        isinstance(result.profile_revision, bool)
        or not isinstance(result.profile_revision, int)
        or result.profile_revision < 1
    ):
        raise ValueError("profile revision is invalid")
    if any(category not in PROFILE_CATEGORIES for category in result.selected_categories):
        raise ValueError("selected category is invalid")
    counts = Counter(result.selected_categories)
    return {
        "event_namespace": AUDIT_NAMESPACE,
        "outcome": result.state,
        "profile_schema_version": SCHEMA_VERSION,
        "profile_revision": result.profile_revision,
        "selected_count": len(result.sections),
        "selected_category_counts": dict(sorted(counts.items())),
        "query_length_bucket": _query_length_bucket(result.query_characters),
        "duration_ms": _duration(duration_ms),
        "memory_write_performed": False,
        "legacy_namespace_written": False,
    }


def error_audit_projection(
    error: OwnerProfileError,
    *,
    query_characters: int,
    duration_ms: float,
) -> dict[str, object]:
    error_category = (
        error.code if error.code in _PUBLIC_ERROR_CATEGORIES else "internal_error"
    )
    return {
        "event_namespace": AUDIT_NAMESPACE,
        "outcome": "degraded" if error.retryable else "rejected",
        "profile_schema_version": SCHEMA_VERSION,
        "selected_count": 0,
        "selected_category_counts": {},
        "query_length_bucket": _query_length_bucket(query_characters),
        "duration_ms": _duration(duration_ms),
        "error_category": error_category,
        "retryable": error.retryable,
        "memory_write_performed": False,
        "legacy_namespace_written": False,
    }


def profile_v2_current_projection(
    manifest: ProfileModuleManifest,
    current: ProfileCurrentValue,
) -> dict[str, object]:
    """Return only the bounded current value; event history and reasons stay private."""
    if (
        current.module_id != manifest.module_id
        or current.field_id != manifest.field_id
        or current.manifest_digest != manifest.manifest_digest
    ):
        raise OwnerProfileError("profile_state_projection_conflict")
    result: dict[str, object] = {
        "display_name": manifest.display_name,
        "field_id": current.field_id,
        "module_id": current.module_id,
        "projection_digest": current.projection_digest,
        "state": current.state,
    }
    if current.state != "uninitialized":
        if current.scaled_value is None or manifest.scale is None:
            raise OwnerProfileError("profile_state_projection_conflict")
        result["scaled_value"] = current.scaled_value
        result["scale"] = manifest.scale
    return result


def render_profile_v2_current_context(
    manifest: ProfileModuleManifest,
    current: ProfileCurrentValue,
) -> str | None:
    projection = profile_v2_current_projection(manifest, current)
    if projection["state"] == "uninitialized":
        return None
    value = projection["scaled_value"]
    scale = projection["scale"]
    assert type(value) is int and type(scale) is int
    sign = "-" if value < 0 else ""
    absolute = abs(value)
    whole, fraction = divmod(absolute, scale)
    rendered = f"{sign}{whole}.{fraction:04d}".rstrip("0").rstrip(".")
    return f"{manifest.display_name}：{rendered}"
