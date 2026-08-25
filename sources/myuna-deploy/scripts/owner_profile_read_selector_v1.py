"""Strict private selector contract for Owner Profile read-only v1."""

from __future__ import annotations

from dataclasses import dataclass
import re


CODE_RELEASE_ROOT = "/opt/myuna/owner-profile-read-v1/releases"
PROFILE_RELEASE_ROOT = "/var/lib/myuna-owner-profile-v1/releases"
PROFILE_WRITE_ROOT = "/var/lib/myuna-owner-profile-write-v1"
MAX_ENVIRONMENT_BYTES = 4_096
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CODE_PATH = re.compile(
    r"^/opt/myuna/owner-profile-read-v1/releases/([0-9a-f]{64})/src$"
)
_KEYS = (
    "PYTHONPATH",
    "MYUNA_OWNER_PROFILE_ROOT",
    "MYUNA_OWNER_PROFILE_INITIAL_REVISION",
    "MYUNA_OWNER_PROFILE_INITIAL_SHA256",
    "MYUNA_OWNER_PROFILE_OWNER_UID",
)


class OwnerProfileSelectorError(ValueError):
    """A deterministic content-free selector rejection."""


@dataclass(frozen=True, slots=True)
class OwnerProfileReadTarget:
    code_release_sha256: str
    profile_revision: int
    profile_sha256: str
    profile_owner_uid: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.code_release_sha256, str)
            or _DIGEST.fullmatch(self.code_release_sha256) is None
            or isinstance(self.profile_revision, bool)
            or not isinstance(self.profile_revision, int)
            or self.profile_revision < 1
            or not isinstance(self.profile_sha256, str)
            or _DIGEST.fullmatch(self.profile_sha256) is None
            or isinstance(self.profile_owner_uid, bool)
            or not isinstance(self.profile_owner_uid, int)
            or self.profile_owner_uid < 1
        ):
            raise OwnerProfileSelectorError("selector_target_rejected")

    @property
    def code_pythonpath(self) -> str:
        return f"{CODE_RELEASE_ROOT}/{self.code_release_sha256}/src"

    @property
    def profile_release_path(self) -> str:
        return (
            f"{PROFILE_RELEASE_ROOT}/r{self.profile_revision}-"
            f"{self.profile_sha256}"
        )


def render_environment(target: OwnerProfileReadTarget) -> bytes:
    if not isinstance(target, OwnerProfileReadTarget):
        raise TypeError("target must be OwnerProfileReadTarget")
    return (
        f"PYTHONPATH={target.code_pythonpath}\n"
        f"MYUNA_OWNER_PROFILE_ROOT={PROFILE_WRITE_ROOT}\n"
        f"MYUNA_OWNER_PROFILE_INITIAL_REVISION={target.profile_revision}\n"
        f"MYUNA_OWNER_PROFILE_INITIAL_SHA256={target.profile_sha256}\n"
        f"MYUNA_OWNER_PROFILE_OWNER_UID={target.profile_owner_uid}\n"
    ).encode("ascii")


def parse_environment(payload: bytes) -> OwnerProfileReadTarget:
    if not payload or len(payload) > MAX_ENVIRONMENT_BYTES:
        raise OwnerProfileSelectorError("selector_environment_rejected")
    try:
        text = payload.decode("ascii")
    except UnicodeError as exc:
        raise OwnerProfileSelectorError("selector_environment_rejected") from exc
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise OwnerProfileSelectorError("selector_environment_rejected")
    lines = text[:-1].split("\n")
    if len(lines) != len(_KEYS):
        raise OwnerProfileSelectorError("selector_environment_rejected")
    values: dict[str, str] = {}
    for line, expected_key in zip(lines, _KEYS, strict=True):
        if "=" not in line:
            raise OwnerProfileSelectorError("selector_environment_rejected")
        key, value = line.split("=", 1)
        if key != expected_key or not value:
            raise OwnerProfileSelectorError("selector_environment_rejected")
        values[key] = value
    code_match = _CODE_PATH.fullmatch(values["PYTHONPATH"])
    if (
        code_match is None
        or values["MYUNA_OWNER_PROFILE_ROOT"] != PROFILE_WRITE_ROOT
        or _DIGEST.fullmatch(values["MYUNA_OWNER_PROFILE_INITIAL_SHA256"])
        is None
    ):
        raise OwnerProfileSelectorError("selector_environment_rejected")
    try:
        revision = int(values["MYUNA_OWNER_PROFILE_INITIAL_REVISION"])
        owner_uid = int(values["MYUNA_OWNER_PROFILE_OWNER_UID"])
    except ValueError as exc:
        raise OwnerProfileSelectorError("selector_environment_rejected") from exc
    target = OwnerProfileReadTarget(
        code_release_sha256=code_match.group(1),
        profile_revision=revision,
        profile_sha256=values["MYUNA_OWNER_PROFILE_INITIAL_SHA256"],
        profile_owner_uid=owner_uid,
    )
    if render_environment(target) != payload:
        raise OwnerProfileSelectorError("selector_environment_rejected")
    return target


def selector_audit_projection(
    target: OwnerProfileReadTarget | None,
    *,
    outcome: str,
    error_category: str | None = None,
) -> dict[str, object]:
    if outcome not in {"accepted", "rejected", "failed"}:
        raise ValueError("unsupported selector outcome")
    allowed_errors = {
        None,
        "selector_target_rejected",
        "selector_environment_rejected",
        "selector_prestate_drift",
        "selector_install_unavailable",
        "selector_service_failed",
    }
    if error_category not in allowed_errors:
        raise ValueError("unsupported selector error category")
    return {
        "event_namespace": "owner_profile_read_selector_v1",
        "outcome": outcome,
        "profile_revision": target.profile_revision if target is not None else 0,
        "code_release_pinned": target is not None,
        "profile_release_pinned": False,
        "dynamic_private_selector": target is not None,
        "profile_digest_recorded": False,
        "profile_path_recorded": False,
        "profile_identity_recorded": False,
        "raw_content_recorded": False,
        "error_category": error_category,
    }
