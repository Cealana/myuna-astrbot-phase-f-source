"""Strict environment contract for the Owner Profile write worker v1."""

from __future__ import annotations

from dataclasses import dataclass
import re


WRITE_CODE_RELEASE_ROOT = "/opt/myuna/owner-profile-write-v1/releases"
WRITE_CAPABILITY_PROFILE = (
    "/opt/myuna/owner-profile-write-v1/capability/"
    "owner-private-profile-write-v1.json"
)
PROFILE_WRITE_ROOT = "/var/lib/myuna-owner-profile-write-v1"
MAX_ENVIRONMENT_BYTES = 8_192
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CORE_PATH = re.compile(
    r"^/opt/myuna/owner-profile-write-v1/releases/([0-9a-f]{64})/src$"
)
_KEYS = (
    "PYTHONPATH",
    "MYUNA_OWNER_PROFILE_SELECTED_CORE_RELEASE_SHA256",
    "MYUNA_OWNER_PROFILE_OWNER_UID",
    "MYUNA_OWNER_PROFILE_CORE_PEER_UID",
    "MYUNA_OWNER_PROFILE_ROOT",
    "MYUNA_OWNER_PROFILE_CANDIDATE_ROOT",
    "MYUNA_OWNER_PROFILE_LIFECYCLE_LEDGER",
    "MYUNA_OWNER_PROFILE_WRITE_CAPABILITY_PROFILE",
    "MYUNA_OWNER_PROFILE_READ_SOCKET",
    "MYUNA_OWNER_PROFILE_WRITE_AUDIT_DIR",
    "MYUNA_LOCAL_PROVIDER_BASE_URL",
    "MYUNA_LOCAL_PROVIDER_MODEL",
    "MYUNA_LOCAL_PROVIDER_TIMEOUT_SECONDS",
)
_FIXED_VALUES = {
    "MYUNA_OWNER_PROFILE_ROOT": PROFILE_WRITE_ROOT,
    "MYUNA_OWNER_PROFILE_CANDIDATE_ROOT": f"{PROFILE_WRITE_ROOT}/candidates",
    "MYUNA_OWNER_PROFILE_LIFECYCLE_LEDGER": f"{PROFILE_WRITE_ROOT}/ledger",
    "MYUNA_OWNER_PROFILE_WRITE_CAPABILITY_PROFILE": WRITE_CAPABILITY_PROFILE,
    "MYUNA_OWNER_PROFILE_READ_SOCKET": (
        "/run/myuna-owner-profile-read-v1/profile.sock"
    ),
    "MYUNA_OWNER_PROFILE_WRITE_AUDIT_DIR": (
        "/var/log/myuna-owner-profile-write-v1"
    ),
    "MYUNA_LOCAL_PROVIDER_BASE_URL": "http://127.0.0.1:879/v1",
    "MYUNA_LOCAL_PROVIDER_MODEL": "myuna-local-owner-v1",
    "MYUNA_LOCAL_PROVIDER_TIMEOUT_SECONDS": "120",
}


class OwnerProfileWriteEnvironmentError(ValueError):
    """A deterministic content-free writer environment rejection."""


@dataclass(frozen=True, slots=True)
class OwnerProfileWriteTarget:
    core_release_sha256: str
    write_code_release_sha256: str
    owner_profile_uid: int
    core_peer_uid: int

    def __post_init__(self) -> None:
        for uid in (self.owner_profile_uid, self.core_peer_uid):
            if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1:
                raise OwnerProfileWriteEnvironmentError(
                    "write_environment_target_rejected"
                )
        if any(
            not isinstance(value, str) or _DIGEST.fullmatch(value) is None
            for value in (
                self.core_release_sha256,
                self.write_code_release_sha256,
            )
        ):
            raise OwnerProfileWriteEnvironmentError(
                "write_environment_target_rejected"
            )

    @property
    def core_pythonpath(self) -> str:
        return (
            f"{WRITE_CODE_RELEASE_ROOT}/"
            f"{self.write_code_release_sha256}/src"
        )


def render_environment(target: OwnerProfileWriteTarget) -> bytes:
    if not isinstance(target, OwnerProfileWriteTarget):
        raise TypeError("target must be OwnerProfileWriteTarget")
    values = {
        "PYTHONPATH": target.core_pythonpath,
        "MYUNA_OWNER_PROFILE_SELECTED_CORE_RELEASE_SHA256": (
            target.core_release_sha256
        ),
        "MYUNA_OWNER_PROFILE_OWNER_UID": str(target.owner_profile_uid),
        "MYUNA_OWNER_PROFILE_CORE_PEER_UID": str(target.core_peer_uid),
        **_FIXED_VALUES,
    }
    return "".join(f"{key}={values[key]}\n" for key in _KEYS).encode("ascii")


def parse_environment(payload: bytes) -> OwnerProfileWriteTarget:
    if not payload or len(payload) > MAX_ENVIRONMENT_BYTES:
        raise OwnerProfileWriteEnvironmentError(
            "write_environment_rejected"
        )
    try:
        text = payload.decode("ascii")
    except UnicodeError as exc:
        raise OwnerProfileWriteEnvironmentError(
            "write_environment_rejected"
        ) from exc
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise OwnerProfileWriteEnvironmentError(
            "write_environment_rejected"
        )
    lines = text[:-1].split("\n")
    if len(lines) != len(_KEYS):
        raise OwnerProfileWriteEnvironmentError(
            "write_environment_rejected"
        )
    values: dict[str, str] = {}
    for line, expected_key in zip(lines, _KEYS, strict=True):
        if "=" not in line:
            raise OwnerProfileWriteEnvironmentError(
                "write_environment_rejected"
            )
        key, value = line.split("=", 1)
        if key != expected_key or not value:
            raise OwnerProfileWriteEnvironmentError(
                "write_environment_rejected"
            )
        values[key] = value
    core_match = _CORE_PATH.fullmatch(values["PYTHONPATH"])
    if core_match is None or any(
        values.get(key) != expected for key, expected in _FIXED_VALUES.items()
    ):
        raise OwnerProfileWriteEnvironmentError(
            "write_environment_rejected"
        )
    try:
        target = OwnerProfileWriteTarget(
            core_release_sha256=values[
                "MYUNA_OWNER_PROFILE_SELECTED_CORE_RELEASE_SHA256"
            ],
            write_code_release_sha256=core_match.group(1),
            owner_profile_uid=int(values["MYUNA_OWNER_PROFILE_OWNER_UID"]),
            core_peer_uid=int(values["MYUNA_OWNER_PROFILE_CORE_PEER_UID"]),
        )
    except ValueError as exc:
        raise OwnerProfileWriteEnvironmentError(
            "write_environment_rejected"
        ) from exc
    if render_environment(target) != payload:
        raise OwnerProfileWriteEnvironmentError(
            "write_environment_rejected"
        )
    return target


def environment_audit_projection(
    target: OwnerProfileWriteTarget | None,
    *,
    outcome: str,
    error_category: str | None = None,
) -> dict[str, object]:
    if outcome not in {"accepted", "rejected", "failed"}:
        raise ValueError("unsupported environment outcome")
    return {
        "event_namespace": "owner_profile_write_environment_v1",
        "outcome": outcome,
        "core_release_pinned": target is not None,
        "writer_identity_pinned": target is not None,
        "core_peer_identity_pinned": target is not None,
        "profile_digest_recorded": False,
        "profile_path_recorded": False,
        "profile_identity_recorded": False,
        "raw_content_recorded": False,
        "error_category": error_category,
    }
