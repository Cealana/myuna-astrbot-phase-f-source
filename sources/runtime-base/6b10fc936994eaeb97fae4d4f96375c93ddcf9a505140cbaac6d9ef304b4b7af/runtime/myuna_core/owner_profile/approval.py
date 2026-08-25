from __future__ import annotations

from dataclasses import dataclass
import json
import re

from .contracts import SCHEMA_VERSION, OwnerProfile, OwnerProfileError


APPROVAL_FILENAME = "approval.json"
APPROVAL_TYPE = "owner_profile_release_candidate_approval_v1"
APPROVAL_SCOPE = "exact_profile_revision"
APPROVAL_DECISION = "approved"
MAX_APPROVAL_BYTES = 4_096

_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_APPROVAL_KEYS = {
    "schema_version",
    "approval_type",
    "approval_scope",
    "decision",
    "profile_schema_version",
    "profile_id",
    "profile_revision",
    "profile_sha256",
}


@dataclass(frozen=True, slots=True)
class ProfileReleaseApproval:
    profile_schema_version: int
    profile_id: str
    profile_revision: int
    profile_sha256: str


def _positive_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise OwnerProfileError("malformed_approval")
    return value


def parse_profile_approval_bytes(payload: bytes) -> ProfileReleaseApproval:
    if not payload or len(payload) > MAX_APPROVAL_BYTES:
        raise OwnerProfileError("malformed_approval")
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OwnerProfileError("malformed_approval") from exc
    if not isinstance(parsed, dict) or set(parsed) != _APPROVAL_KEYS:
        raise OwnerProfileError("malformed_approval")
    if (
        isinstance(parsed.get("schema_version"), bool)
        or parsed.get("schema_version") != 1
        or parsed.get("approval_type") != APPROVAL_TYPE
        or parsed.get("approval_scope") != APPROVAL_SCOPE
        or parsed.get("decision") != APPROVAL_DECISION
        or isinstance(parsed.get("profile_schema_version"), bool)
        or parsed.get("profile_schema_version") != SCHEMA_VERSION
    ):
        raise OwnerProfileError("malformed_approval")
    profile_id = parsed.get("profile_id")
    profile_sha256 = parsed.get("profile_sha256")
    if (
        not isinstance(profile_id, str)
        or _SAFE_LABEL.fullmatch(profile_id) is None
        or not isinstance(profile_sha256, str)
        or _SHA256.fullmatch(profile_sha256) is None
    ):
        raise OwnerProfileError("malformed_approval")
    return ProfileReleaseApproval(
        profile_schema_version=SCHEMA_VERSION,
        profile_id=profile_id,
        profile_revision=_positive_integer(parsed.get("profile_revision")),
        profile_sha256=profile_sha256,
    )


def verify_profile_approval(
    profile: OwnerProfile,
    approval_bytes: bytes,
) -> ProfileReleaseApproval:
    approval = parse_profile_approval_bytes(approval_bytes)
    if approval != ProfileReleaseApproval(
        profile_schema_version=SCHEMA_VERSION,
        profile_id=profile.profile_id,
        profile_revision=profile.profile_revision,
        profile_sha256=profile.sha256,
    ):
        raise OwnerProfileError("approval_mismatch")
    return approval
