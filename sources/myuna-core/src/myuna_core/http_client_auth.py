from __future__ import annotations

from dataclasses import dataclass, field
import hmac
import re
from typing import Mapping, Sequence

from .providers.credentials import CredentialError, load_systemd_credential


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
ALLOWED_CHANNEL_KINDS = frozenset({"astrbot_qq", "astrbot_telegram"})
LEGACY_CLIENT_ID = "legacy-dev"
LEGACY_CHANNEL_KIND = "loopback_dev"
MAX_HTTP_CLIENTS = 8


class HttpClientAuthError(ValueError):
    """Raised when an HTTP client credential contract is unsafe."""


@dataclass(frozen=True, slots=True)
class HttpClientCredentialSpec:
    client_id: str
    channel_kind: str
    credential_name: str

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.client_id) is None:
            raise HttpClientAuthError("HTTP client id must be a safe identifier")
        if self.channel_kind not in ALLOWED_CHANNEL_KINDS:
            raise HttpClientAuthError("HTTP client channel kind is not allowed")
        if _IDENTIFIER.fullmatch(self.credential_name) is None:
            raise HttpClientAuthError(
                "HTTP client credential name must be a safe identifier"
            )


@dataclass(frozen=True, slots=True)
class LoadedHttpClientCredential:
    client_id: str
    channel_kind: str
    token: str = field(repr=False)
    identity_headers_required: bool = True

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.client_id) is None:
            raise HttpClientAuthError("loaded HTTP client id is unsafe")
        if self.channel_kind not in ALLOWED_CHANNEL_KINDS | {LEGACY_CHANNEL_KIND}:
            raise HttpClientAuthError("loaded HTTP client channel is unsafe")
        if not 8 <= len(self.token) <= 4096:
            raise HttpClientAuthError("loaded HTTP client credential is unsafe")
        if "\n" in self.token or "\r" in self.token:
            raise HttpClientAuthError("loaded HTTP client credential is unsafe")
        if self.channel_kind == LEGACY_CHANNEL_KIND and self.identity_headers_required:
            raise HttpClientAuthError("legacy HTTP client headers must remain optional")
        if self.channel_kind != LEGACY_CHANNEL_KIND and not self.identity_headers_required:
            raise HttpClientAuthError("scoped HTTP client headers must be required")


def parse_http_client_credentials(raw: str) -> tuple[HttpClientCredentialSpec, ...]:
    value = raw.strip()
    if not value:
        return ()
    entries = tuple(part.strip() for part in value.split(","))
    if not entries or len(entries) > MAX_HTTP_CLIENTS or any(not item for item in entries):
        raise HttpClientAuthError("HTTP client credential list is invalid")

    parsed: list[HttpClientCredentialSpec] = []
    client_ids: set[str] = set()
    channel_kinds: set[str] = set()
    credential_names: set[str] = set()
    for entry in entries:
        fields = entry.split(":")
        if len(fields) != 3:
            raise HttpClientAuthError("HTTP client credential entry is invalid")
        spec = HttpClientCredentialSpec(
            client_id=fields[0],
            channel_kind=fields[1],
            credential_name=fields[2],
        )
        if spec.client_id in client_ids:
            raise HttpClientAuthError("HTTP client id must be unique")
        if spec.channel_kind in channel_kinds:
            raise HttpClientAuthError("HTTP client channel kind must be unique")
        if spec.credential_name in credential_names:
            raise HttpClientAuthError("HTTP client credential name must be unique")
        client_ids.add(spec.client_id)
        channel_kinds.add(spec.channel_kind)
        credential_names.add(spec.credential_name)
        parsed.append(spec)
    return tuple(parsed)


def load_http_client_credentials(
    specs: Sequence[HttpClientCredentialSpec],
    *,
    legacy_credential_name: str | None,
    environ: Mapping[str, str] | None = None,
) -> tuple[LoadedHttpClientCredential, ...]:
    if specs and legacy_credential_name:
        raise HttpClientAuthError(
            "legacy and channel-scoped HTTP credentials cannot be mixed"
        )
    if not specs and not legacy_credential_name:
        return ()

    if legacy_credential_name:
        token = load_systemd_credential(legacy_credential_name, environ=environ)
        return (
            LoadedHttpClientCredential(
                client_id=LEGACY_CLIENT_ID,
                channel_kind=LEGACY_CHANNEL_KIND,
                token=token,
                identity_headers_required=False,
            ),
        )

    loaded: list[LoadedHttpClientCredential] = []
    token_fingerprints: set[str] = set()
    for spec in specs:
        try:
            token = load_systemd_credential(spec.credential_name, environ=environ)
        except CredentialError:
            raise
        fingerprint = hmac.digest(
            b"myuna-http-client-token-uniqueness-v1",
            token.encode("utf-8"),
            "sha256",
        ).hex()
        if fingerprint in token_fingerprints:
            raise HttpClientAuthError("HTTP client credential values must be unique")
        token_fingerprints.add(fingerprint)
        loaded.append(
            LoadedHttpClientCredential(
                client_id=spec.client_id,
                channel_kind=spec.channel_kind,
                token=token,
                identity_headers_required=True,
            )
        )
    return tuple(loaded)


def authenticate_http_client(
    authorization: str,
    client_id: str,
    channel_kind: str,
    credentials: Sequence[LoadedHttpClientCredential],
) -> LoadedHttpClientCredential | None:
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return None
    supplied_token = authorization[len(prefix) :]
    if not supplied_token:
        return None

    matched: LoadedHttpClientCredential | None = None
    match_count = 0
    for credential in credentials:
        if hmac.compare_digest(supplied_token, credential.token):
            matched = credential
            match_count += 1
    if match_count != 1 or matched is None:
        return None

    if matched.identity_headers_required:
        if not hmac.compare_digest(client_id, matched.client_id):
            return None
        if not hmac.compare_digest(channel_kind, matched.channel_kind):
            return None
    elif client_id or channel_kind:
        if client_id and not hmac.compare_digest(client_id, matched.client_id):
            return None
        if channel_kind and not hmac.compare_digest(
            channel_kind,
            matched.channel_kind,
        ):
            return None
    return matched
