from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping
import os
import re

from .http_client_auth import (
    HttpClientAuthError,
    HttpClientCredentialSpec,
    parse_http_client_credentials,
)
from .context_window import (
    ContextWindowPolicy,
    ContextWindowPolicyError,
)
from .prompt_budget import (
    DEFAULT_DEFINITION_PROMPT_MAX_CHARACTERS,
    DEFAULT_MODEL_INPUT_MAX_CHARACTERS,
    PromptBudgetPolicy,
    PromptBudgetPolicyError,
)
from .providers.local import LOCAL_MODEL_ALIAS, normalize_loopback_base_url
from .providers.registry import get_model_spec


VALID_ENVIRONMENTS = frozenset({"dev", "staging", "prod"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
OWNER_MEMORY_SOCKET_V1 = Path("/run/myuna-owner-memory-read-v1/worker.sock")
OWNER_MEMORY_SOCKET_V2 = Path("/run/myuna-owner-memory-read-v2/worker.sock")
OWNER_MEMORY_PROTOCOLS = {
    "v1": OWNER_MEMORY_SOCKET_V1,
    "v2": OWNER_MEMORY_SOCKET_V2,
}
OWNER_PROFILE_SOCKET_V1 = Path("/run/myuna-owner-profile-read-v1/profile.sock")
OWNER_PROFILE_WRITE_SOCKET_V1 = Path(
    "/run/myuna-owner-profile-write-v1/profile-write.sock"
)


class ConfigurationError(ValueError):
    """Raised when deployment configuration violates a safety boundary."""


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    bind_host: str
    port: int
    data_dir: Path
    log_dir: Path
    definition_release: str | None
    definition_path: Path | None
    capability_manifest_path: Path | None
    enabled_providers: tuple[str, ...]
    dev_token_credential: str | None
    http_client_credentials: tuple[HttpClientCredentialSpec, ...]
    http_max_body_bytes: int
    conversation_max_messages: int
    conversation_max_characters: int
    memory_worker_enabled: bool
    memory_worker_socket: Path
    memory_synthetic_only: bool
    memory_synthetic_fixture: Path | None
    memory_synthetic_fixture_sha256: str | None
    memory_synthetic_at: datetime | None
    owner_memory_read_enabled: bool
    owner_memory_protocol: str
    owner_memory_worker_socket: Path
    owner_memory_timeout_ms: int
    definition_prompt_max_characters: int = (
        DEFAULT_DEFINITION_PROMPT_MAX_CHARACTERS
    )
    model_input_max_characters: int = DEFAULT_MODEL_INPUT_MAX_CHARACTERS
    owner_profile_read_enabled: bool = False
    owner_profile_worker_socket: Path = OWNER_PROFILE_SOCKET_V1
    owner_profile_timeout_ms: int = 500
    owner_profile_capability_profile_path: Path | None = None
    owner_profile_provider_allowlist: tuple[str, ...] = ()
    owner_profile_write_enabled: bool = False
    owner_profile_write_worker_socket: Path = OWNER_PROFILE_WRITE_SOCKET_V1
    owner_profile_write_timeout_ms: int = 150_000
    local_provider_base_url: str | None = None
    local_provider_model: str = LOCAL_MODEL_ALIAS
    local_provider_timeout_seconds: float = 120.0

    @property
    def ready(self) -> bool:
        return bool(
            self.definition_release
            and self.definition_path
            and self.capability_manifest_path
            and self.enabled_providers
            and (self.dev_token_credential or self.http_client_credentials)
        )

    @property
    def readiness_reasons(self) -> tuple[str, ...]:
        reasons: list[str] = []
        if not self.definition_release:
            reasons.append("no_approved_definition")
        if not self.definition_path:
            reasons.append("no_definition_path")
        if not self.capability_manifest_path:
            reasons.append("no_capability_manifest")
        if not self.enabled_providers:
            reasons.append("no_enabled_provider")
        if not self.dev_token_credential and not self.http_client_credentials:
            reasons.append("no_dev_api_token")
        return tuple(reasons)


def _parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError as exc:
        raise ConfigurationError("MYUNA_PORT must be an integer") from exc
    if not 1024 <= port <= 65535:
        raise ConfigurationError("MYUNA_PORT must be between 1024 and 65535")
    return port


def _parse_providers(raw: str) -> tuple[str, ...]:
    providers = tuple(
        dict.fromkeys(item.strip().lower() for item in raw.split(",") if item.strip())
    )
    allowed = {"openai", "deepseek", "local"}
    unknown = sorted(set(providers) - allowed)
    if unknown:
        raise ConfigurationError(f"unknown provider(s): {', '.join(unknown)}")
    return providers


def _parse_bool(raw: str, field_name: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{field_name} must be a boolean")


def _optional_absolute_path(raw: str, field_name: str) -> Path | None:
    value = raw.strip()
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        raise ConfigurationError(f"{field_name} must be absolute")
    return path


def _optional_identifier(raw: str, field_name: str) -> str | None:
    value = raw.strip()
    if not value:
        return None
    if _IDENTIFIER.fullmatch(value) is None:
        raise ConfigurationError(f"{field_name} must be a safe identifier")
    return value


def _parse_body_limit(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError("MYUNA_HTTP_MAX_BODY_BYTES must be an integer") from exc
    if not 1024 <= value <= 1_048_576:
        raise ConfigurationError(
            "MYUNA_HTTP_MAX_BODY_BYTES must be between 1024 and 1048576"
        )
    return value


def _parse_context_window(max_messages_raw: str, max_characters_raw: str) -> ContextWindowPolicy:
    try:
        max_messages = int(max_messages_raw)
    except ValueError as exc:
        raise ConfigurationError("MYUNA_CONTEXT_MAX_MESSAGES must be an integer") from exc
    try:
        max_characters = int(max_characters_raw)
    except ValueError as exc:
        raise ConfigurationError("MYUNA_CONTEXT_MAX_CHARACTERS must be an integer") from exc
    try:
        return ContextWindowPolicy(
            max_messages=max_messages,
            max_characters=max_characters,
        )
    except ContextWindowPolicyError as exc:
        raise ConfigurationError(str(exc)) from None


def _parse_prompt_budget(
    definition_prompt_raw: str,
    model_input_raw: str,
) -> PromptBudgetPolicy:
    try:
        definition_prompt_max_characters = int(definition_prompt_raw)
    except ValueError as exc:
        raise ConfigurationError(
            "MYUNA_DEFINITION_PROMPT_MAX_CHARACTERS must be an integer"
        ) from exc
    try:
        model_input_max_characters = int(model_input_raw)
    except ValueError as exc:
        raise ConfigurationError(
            "MYUNA_MODEL_INPUT_MAX_CHARACTERS must be an integer"
        ) from exc
    try:
        return PromptBudgetPolicy(
            definition_prompt_max_characters=definition_prompt_max_characters,
            model_input_max_characters=model_input_max_characters,
        )
    except PromptBudgetPolicyError as exc:
        raise ConfigurationError(str(exc)) from None


def _parse_owner_memory_timeout(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(
            "MYUNA_OWNER_MEMORY_TIMEOUT_MS must be an integer"
        ) from exc
    if not 100 <= value <= 3000:
        raise ConfigurationError(
            "MYUNA_OWNER_MEMORY_TIMEOUT_MS must be between 100 and 3000"
        )
    return value


def _parse_owner_profile_timeout(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(
            "MYUNA_OWNER_PROFILE_TIMEOUT_MS must be an integer"
        ) from exc
    if not 50 <= value <= 3000:
        raise ConfigurationError(
            "MYUNA_OWNER_PROFILE_TIMEOUT_MS must be between 50 and 3000"
        )
    return value


def _parse_owner_profile_write_timeout(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(
            "MYUNA_OWNER_PROFILE_WRITE_TIMEOUT_MS must be an integer"
        ) from exc
    if not 1_000 <= value <= 180_000:
        raise ConfigurationError(
            "MYUNA_OWNER_PROFILE_WRITE_TIMEOUT_MS must be between 1000 and 180000"
        )
    return value


def _optional_sha256(raw: str, field_name: str) -> str | None:
    value = raw.strip().upper()
    if not value:
        return None
    if re.fullmatch(r"[0-9A-F]{64}", value) is None:
        raise ConfigurationError(f"{field_name} must be a SHA-256 hex digest")
    return value


def _optional_aware_datetime(raw: str, field_name: str) -> datetime | None:
    value = raw.strip()
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ConfigurationError(f"{field_name} must be an ISO-8601 datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ConfigurationError(f"{field_name} must include a timezone offset")
    return parsed


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    source = dict(os.environ if environ is None else environ)
    environment = source.get("MYUNA_ENV", "dev").strip().lower()
    if environment not in VALID_ENVIRONMENTS:
        raise ConfigurationError("MYUNA_ENV must be dev, staging, or prod")

    bind_host = source.get("MYUNA_BIND_HOST", "127.0.0.1").strip()
    if bind_host not in LOOPBACK_HOSTS:
        raise ConfigurationError(
            "bootstrap service may only bind to loopback; "
            "external exposure requires an approved ADR"
        )

    port = _parse_port(source.get("MYUNA_PORT", "18080"))
    data_dir = Path(source.get("MYUNA_DATA_DIR", f"/var/lib/myuna/{environment}"))
    log_dir = Path(source.get("MYUNA_LOG_DIR", f"/var/log/myuna/{environment}"))
    release = _optional_identifier(
        source.get("MYUNA_DEFINITION_RELEASE", ""),
        "MYUNA_DEFINITION_RELEASE",
    )
    definition_path = _optional_absolute_path(
        source.get("MYUNA_DEFINITION_PATH", ""),
        "MYUNA_DEFINITION_PATH",
    )
    capability_manifest_path = _optional_absolute_path(
        source.get("MYUNA_CAPABILITY_MANIFEST", ""),
        "MYUNA_CAPABILITY_MANIFEST",
    )
    providers = _parse_providers(source.get("MYUNA_PROVIDERS_ENABLED", ""))
    local_provider_base_url: str | None = None
    local_provider_model = LOCAL_MODEL_ALIAS
    local_provider_timeout_seconds = 120.0
    if "local" in providers:
        try:
            local_provider_base_url = normalize_loopback_base_url(
                source.get("MYUNA_LOCAL_PROVIDER_BASE_URL", "").strip()
            )
            local_provider_model = source.get(
                "MYUNA_LOCAL_PROVIDER_MODEL",
                LOCAL_MODEL_ALIAS,
            ).strip()
            get_model_spec(local_provider_model, provider="local")
            local_provider_timeout_seconds = float(
                source.get("MYUNA_LOCAL_PROVIDER_TIMEOUT_SECONDS", "120")
            )
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from None
        if not 1 <= local_provider_timeout_seconds <= 300:
            raise ConfigurationError(
                "MYUNA_LOCAL_PROVIDER_TIMEOUT_SECONDS must be between 1 and 300"
            )
    dev_token_credential = _optional_identifier(
        source.get("MYUNA_DEV_TOKEN_CREDENTIAL", ""),
        "MYUNA_DEV_TOKEN_CREDENTIAL",
    )
    try:
        http_client_credentials = parse_http_client_credentials(
            source.get("MYUNA_HTTP_CLIENT_CREDENTIALS", "")
        )
    except HttpClientAuthError as exc:
        raise ConfigurationError(str(exc)) from None
    if dev_token_credential and http_client_credentials:
        raise ConfigurationError(
            "legacy and channel-scoped HTTP credentials cannot be mixed"
        )
    http_max_body_bytes = _parse_body_limit(
        source.get("MYUNA_HTTP_MAX_BODY_BYTES", "65536")
    )
    context_window = _parse_context_window(
        source.get("MYUNA_CONTEXT_MAX_MESSAGES", "12"),
        source.get("MYUNA_CONTEXT_MAX_CHARACTERS", "16000"),
    )
    prompt_budget = _parse_prompt_budget(
        source.get(
            "MYUNA_DEFINITION_PROMPT_MAX_CHARACTERS",
            str(DEFAULT_DEFINITION_PROMPT_MAX_CHARACTERS),
        ),
        source.get(
            "MYUNA_MODEL_INPUT_MAX_CHARACTERS",
            str(DEFAULT_MODEL_INPUT_MAX_CHARACTERS),
        ),
    )
    memory_worker_enabled = _parse_bool(
        source.get("MYUNA_MEMORY_WORKER_ENABLED", "false"),
        "MYUNA_MEMORY_WORKER_ENABLED",
    )
    memory_worker_socket = Path(
        source.get(
            "MYUNA_MEMORY_WORKER_SOCKET",
            "/run/myuna-retrieval-dev/worker.sock",
        )
    )
    memory_synthetic_only = _parse_bool(
        source.get("MYUNA_MEMORY_SYNTHETIC_ONLY", "true"),
        "MYUNA_MEMORY_SYNTHETIC_ONLY",
    )
    memory_synthetic_fixture = _optional_absolute_path(
        source.get("MYUNA_MEMORY_SYNTHETIC_FIXTURE", ""),
        "MYUNA_MEMORY_SYNTHETIC_FIXTURE",
    )
    memory_synthetic_fixture_sha256 = _optional_sha256(
        source.get("MYUNA_MEMORY_SYNTHETIC_FIXTURE_SHA256", ""),
        "MYUNA_MEMORY_SYNTHETIC_FIXTURE_SHA256",
    )
    memory_synthetic_at = _optional_aware_datetime(
        source.get("MYUNA_MEMORY_SYNTHETIC_AT", ""),
        "MYUNA_MEMORY_SYNTHETIC_AT",
    )
    owner_memory_read_enabled = _parse_bool(
        source.get("MYUNA_OWNER_MEMORY_READ_ENABLED", "false"),
        "MYUNA_OWNER_MEMORY_READ_ENABLED",
    )
    owner_memory_protocol = source.get(
        "MYUNA_OWNER_MEMORY_PROTOCOL",
        "v1",
    ).strip().lower()
    if owner_memory_protocol not in OWNER_MEMORY_PROTOCOLS:
        raise ConfigurationError("MYUNA_OWNER_MEMORY_PROTOCOL must be v1 or v2")
    owner_memory_worker_socket = Path(
        source.get(
            "MYUNA_OWNER_MEMORY_WORKER_SOCKET",
            str(OWNER_MEMORY_PROTOCOLS[owner_memory_protocol]),
        )
    )
    owner_memory_timeout_ms = _parse_owner_memory_timeout(
        source.get("MYUNA_OWNER_MEMORY_TIMEOUT_MS", "1200")
    )
    owner_profile_read_enabled = _parse_bool(
        source.get("MYUNA_OWNER_PROFILE_READ_ENABLED", "false"),
        "MYUNA_OWNER_PROFILE_READ_ENABLED",
    )
    owner_profile_worker_socket = Path(
        source.get(
            "MYUNA_OWNER_PROFILE_WORKER_SOCKET",
            str(OWNER_PROFILE_SOCKET_V1),
        )
    )
    owner_profile_timeout_ms = _parse_owner_profile_timeout(
        source.get("MYUNA_OWNER_PROFILE_TIMEOUT_MS", "500")
    )
    owner_profile_capability_profile_path = _optional_absolute_path(
        source.get("MYUNA_OWNER_PROFILE_CAPABILITY_PROFILE", ""),
        "MYUNA_OWNER_PROFILE_CAPABILITY_PROFILE",
    )
    owner_profile_provider_allowlist = _parse_providers(
        source.get("MYUNA_OWNER_PROFILE_PROVIDER_ALLOWLIST", "")
    )
    if set(owner_profile_provider_allowlist) - {"local", "openai"}:
        raise ConfigurationError(
            "Owner Profile provider allowlist may contain only local or openai"
        )
    owner_profile_write_enabled = _parse_bool(
        source.get("MYUNA_OWNER_PROFILE_WRITE_ENABLED", "false"),
        "MYUNA_OWNER_PROFILE_WRITE_ENABLED",
    )
    owner_profile_write_worker_socket = Path(
        source.get(
            "MYUNA_OWNER_PROFILE_WRITE_WORKER_SOCKET",
            str(OWNER_PROFILE_WRITE_SOCKET_V1),
        )
    )
    owner_profile_write_timeout_ms = _parse_owner_profile_write_timeout(
        source.get("MYUNA_OWNER_PROFILE_WRITE_TIMEOUT_MS", "150000")
    )
    if memory_worker_enabled and environment != "dev":
        raise ConfigurationError("Stage 5 retrieval worker may only be enabled in dev")
    if memory_worker_enabled and not memory_synthetic_only:
        raise ConfigurationError("Stage 5 retrieval worker must remain synthetic-only")
    if not memory_worker_socket.is_absolute():
        raise ConfigurationError("MYUNA_MEMORY_WORKER_SOCKET must be absolute")
    if memory_worker_enabled and not all(
        (memory_synthetic_fixture, memory_synthetic_fixture_sha256, memory_synthetic_at)
    ):
        raise ConfigurationError(
            "synthetic worker activation requires a fixture path, checksum, and fixed test time"
        )
    if owner_memory_read_enabled and environment != "dev":
        raise ConfigurationError("Owner Memory read-only retrieval may only be enabled in dev")
    if owner_memory_read_enabled and memory_worker_enabled:
        raise ConfigurationError(
            "synthetic and real Owner Memory runtimes cannot be enabled together"
        )
    if not owner_memory_worker_socket.is_absolute():
        raise ConfigurationError("MYUNA_OWNER_MEMORY_WORKER_SOCKET must be absolute")
    if (
        owner_memory_read_enabled
        and owner_memory_worker_socket != OWNER_MEMORY_PROTOCOLS[owner_memory_protocol]
    ):
        raise ConfigurationError(
            "Owner Memory protocol requires its matching fixed local worker socket"
        )
    if not owner_profile_worker_socket.is_absolute():
        raise ConfigurationError("MYUNA_OWNER_PROFILE_WORKER_SOCKET must be absolute")
    if owner_profile_read_enabled:
        if environment != "dev":
            raise ConfigurationError("Owner Profile retrieval may only be enabled in dev")
        if memory_worker_enabled or owner_memory_read_enabled:
            raise ConfigurationError(
                "Owner Profile cannot coexist with synthetic or legacy Owner Memory"
            )
        if owner_profile_worker_socket != OWNER_PROFILE_SOCKET_V1:
            raise ConfigurationError(
                "Owner Profile retrieval requires its fixed local worker socket"
            )
        if owner_profile_capability_profile_path is None:
            raise ConfigurationError(
                "Owner Profile retrieval requires a channel capability profile"
            )
        if not owner_profile_provider_allowlist:
            raise ConfigurationError(
                "Owner Profile retrieval requires an explicit provider allowlist"
            )
    if not owner_profile_write_worker_socket.is_absolute():
        raise ConfigurationError(
            "MYUNA_OWNER_PROFILE_WRITE_WORKER_SOCKET must be absolute"
        )
    if owner_profile_write_enabled:
        if not owner_profile_read_enabled:
            raise ConfigurationError(
                "Owner Profile write requires Owner Profile read retrieval"
            )
        if owner_profile_write_worker_socket != OWNER_PROFILE_WRITE_SOCKET_V1:
            raise ConfigurationError(
                "Owner Profile write requires its fixed local worker socket"
            )
        if owner_profile_provider_allowlist != ("local",):
            raise ConfigurationError(
                "Owner Profile write requires a local-only provider allowlist"
            )

    return Settings(
        environment=environment,
        bind_host=bind_host,
        port=port,
        data_dir=data_dir,
        log_dir=log_dir,
        definition_release=release,
        definition_path=definition_path,
        capability_manifest_path=capability_manifest_path,
        enabled_providers=providers,
        dev_token_credential=dev_token_credential,
        http_client_credentials=http_client_credentials,
        http_max_body_bytes=http_max_body_bytes,
        conversation_max_messages=context_window.max_messages,
        conversation_max_characters=context_window.max_characters,
        memory_worker_enabled=memory_worker_enabled,
        memory_worker_socket=memory_worker_socket,
        memory_synthetic_only=memory_synthetic_only,
        memory_synthetic_fixture=memory_synthetic_fixture,
        memory_synthetic_fixture_sha256=memory_synthetic_fixture_sha256,
        memory_synthetic_at=memory_synthetic_at,
        owner_memory_read_enabled=owner_memory_read_enabled,
        owner_memory_protocol=owner_memory_protocol,
        owner_memory_worker_socket=owner_memory_worker_socket,
        owner_memory_timeout_ms=owner_memory_timeout_ms,
        definition_prompt_max_characters=(
            prompt_budget.definition_prompt_max_characters
        ),
        model_input_max_characters=prompt_budget.model_input_max_characters,
        owner_profile_read_enabled=owner_profile_read_enabled,
        owner_profile_worker_socket=owner_profile_worker_socket,
        owner_profile_timeout_ms=owner_profile_timeout_ms,
        owner_profile_capability_profile_path=(
            owner_profile_capability_profile_path
        ),
        owner_profile_provider_allowlist=owner_profile_provider_allowlist,
        owner_profile_write_enabled=owner_profile_write_enabled,
        owner_profile_write_worker_socket=owner_profile_write_worker_socket,
        owner_profile_write_timeout_ms=owner_profile_write_timeout_ms,
        local_provider_base_url=local_provider_base_url,
        local_provider_model=local_provider_model,
        local_provider_timeout_seconds=local_provider_timeout_seconds,
    )
