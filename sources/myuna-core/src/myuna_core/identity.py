from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import re


_SAFE_ID = re.compile(r"^[a-z][a-z0-9._-]{2,127}$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_CHANNELS = frozenset(
    {
        "local",
        "astrbot_qq",
        "astrbot_telegram",
        "web",
        "api",
    }
)
_AUTHORITIES = frozenset({"owner", "member", "service", "test"})


class IdentityResolutionError(PermissionError):
    """Fail-closed identity error with no account-enumeration detail."""


def account_fingerprint(
    channel_kind: str,
    stable_account_id: str,
    pepper: bytes,
) -> str:
    """Create a domain-separated HMAC fingerprint without retaining the raw ID."""

    if channel_kind not in _CHANNELS:
        raise ValueError("unsupported identity channel")
    if not stable_account_id or len(stable_account_id) > 512:
        raise ValueError("stable account id must be non-empty and bounded")
    if len(pepper) < 32:
        raise ValueError("identity fingerprint pepper must contain at least 32 bytes")
    message = f"myuna-account-v1\0{channel_kind}\0{stable_account_id}".encode("utf-8")
    return hmac.new(pepper, message, sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class AccountBinding:
    binding_id: str
    principal_id: str
    namespace_id: str
    channel_kind: str
    account_fingerprint: str
    authority_level: str
    status: str = "verified"

    def __post_init__(self) -> None:
        for value, label in (
            (self.binding_id, "binding_id"),
            (self.principal_id, "principal_id"),
            (self.namespace_id, "namespace_id"),
        ):
            if _SAFE_ID.fullmatch(value) is None:
                raise ValueError(f"{label} must be a safe opaque identifier")
        if self.channel_kind not in _CHANNELS:
            raise ValueError("unsupported identity channel")
        if _FINGERPRINT.fullmatch(self.account_fingerprint) is None:
            raise ValueError("account fingerprint must be lowercase SHA-256 hex")
        if self.authority_level not in _AUTHORITIES:
            raise ValueError("unsupported authority level")
        if self.status not in {"pending", "verified", "disabled", "revoked"}:
            raise ValueError("unsupported binding status")


@dataclass(frozen=True, slots=True)
class AuthenticatedContext:
    binding_id: str
    principal_id: str
    namespace_id: str
    channel_kind: str
    account_fingerprint: str
    authority_level: str


@dataclass(frozen=True, slots=True)
class AuthenticatedEnvelope:
    context: AuthenticatedContext
    message_text: str

    def __post_init__(self) -> None:
        if not self.message_text:
            raise ValueError("message text must not be empty")


class IdentityRegistry:
    """Resolve authenticated gateway metadata; conversation text is never an input."""

    def __init__(self, bindings: tuple[AccountBinding, ...]) -> None:
        by_account: dict[tuple[str, str], AccountBinding] = {}
        binding_ids: set[str] = set()
        for binding in bindings:
            account_key = (binding.channel_kind, binding.account_fingerprint)
            if account_key in by_account:
                raise ValueError("duplicate channel account fingerprint")
            if binding.binding_id in binding_ids:
                raise ValueError("duplicate binding id")
            by_account[account_key] = binding
            binding_ids.add(binding.binding_id)
        self._by_account = by_account

    def resolve(
        self,
        *,
        channel_kind: str,
        stable_account_id: str,
        pepper: bytes,
    ) -> AuthenticatedContext:
        fingerprint = account_fingerprint(channel_kind, stable_account_id, pepper)
        binding = self._by_account.get((channel_kind, fingerprint))
        if binding is None or binding.status != "verified":
            raise IdentityResolutionError("authenticated account is not authorized")
        return AuthenticatedContext(
            binding_id=binding.binding_id,
            principal_id=binding.principal_id,
            namespace_id=binding.namespace_id,
            channel_kind=binding.channel_kind,
            account_fingerprint=binding.account_fingerprint,
            authority_level=binding.authority_level,
        )

    @staticmethod
    def attach_message(
        context: AuthenticatedContext,
        message_text: str,
    ) -> AuthenticatedEnvelope:
        return AuthenticatedEnvelope(context=context, message_text=message_text)
