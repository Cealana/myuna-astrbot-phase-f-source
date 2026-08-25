from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping
import re

from .errors import (
    InvalidOperationArgumentsError,
    OperationNotAllowedError,
    UnknownOperationError,
)
from .models import OperationOrigin, OperationRequest, RiskLevel


class ArgumentKind(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"


@dataclass(frozen=True, slots=True)
class ArgumentField:
    name: str
    kind: ArgumentKind
    required: bool = False
    minimum: int | None = None
    maximum: int | None = None
    max_length: int = 256
    pattern: str | None = None
    allowed_values: tuple[str, ...] = ()

    def validate(self, value: Any) -> None:
        if self.kind is ArgumentKind.STRING:
            if not isinstance(value, str):
                raise InvalidOperationArgumentsError(f"{self.name} must be a string")
            if not value or len(value) > self.max_length:
                raise InvalidOperationArgumentsError(
                    f"{self.name} must contain 1-{self.max_length} characters"
                )
            if self.pattern is not None and re.fullmatch(self.pattern, value) is None:
                raise InvalidOperationArgumentsError(f"{self.name} has an invalid format")
            if self.allowed_values and value not in self.allowed_values:
                raise InvalidOperationArgumentsError(f"{self.name} is not allowlisted")
            return
        if self.kind is ArgumentKind.INTEGER:
            if isinstance(value, bool) or not isinstance(value, int):
                raise InvalidOperationArgumentsError(f"{self.name} must be an integer")
            if self.minimum is not None and value < self.minimum:
                raise InvalidOperationArgumentsError(f"{self.name} is below the minimum")
            if self.maximum is not None and value > self.maximum:
                raise InvalidOperationArgumentsError(f"{self.name} exceeds the maximum")
            return
        if self.kind is ArgumentKind.BOOLEAN:
            if not isinstance(value, bool):
                raise InvalidOperationArgumentsError(f"{self.name} must be boolean")
            return
        raise InvalidOperationArgumentsError(f"{self.name} has an unsupported schema")


@dataclass(frozen=True, slots=True)
class OperationDefinition:
    name: str
    allowed_targets: frozenset[str]
    allowed_origins: frozenset[OperationOrigin]
    risk_level: RiskLevel
    requires_approval: bool
    max_timeout_seconds: int
    max_output_characters: int
    supports_cancellation: bool
    allowed_in_recovery: bool
    retry_safe: bool
    handler_id: str
    arguments: tuple[ArgumentField, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.allowed_targets or not self.allowed_origins:
            raise ValueError("operation definitions require target and origin allowlists")
        if not 1 <= self.max_timeout_seconds <= 3600:
            raise ValueError("operation timeout is outside the supported range")
        if not 1 <= self.max_output_characters <= 4096:
            raise ValueError("operation output limit is outside the supported range")
        names = tuple(argument.name for argument in self.arguments)
        if len(names) != len(set(names)):
            raise ValueError("operation argument names must be unique")
        if self.risk_level is RiskLevel.FORBIDDEN:
            raise ValueError("forbidden operations must not enter the executable catalog")

    def validate_arguments(self, values: Mapping[str, Any]) -> None:
        schema = {argument.name: argument for argument in self.arguments}
        unknown = set(values) - set(schema)
        if unknown:
            raise InvalidOperationArgumentsError("operation contains unsupported arguments")
        missing = {
            argument.name
            for argument in self.arguments
            if argument.required and argument.name not in values
        }
        if missing:
            raise InvalidOperationArgumentsError("operation is missing required arguments")
        for name, value in values.items():
            schema[name].validate(value)


FORBIDDEN_OPERATION_NAMES = frozenset(
    {
        "docker.socket",
        "policy.disable",
        "policy.modify",
        "shell.execute",
        "shell.reverse",
        "sudo.execute",
        "windows.powershell",
    }
)


class OperationCatalog:
    """Deterministic server-side catalog; callers cannot add targets or lower risk."""

    def __init__(self, definitions: tuple[OperationDefinition, ...]) -> None:
        by_name: dict[str, OperationDefinition] = {}
        for definition in definitions:
            if definition.name in by_name:
                raise ValueError("duplicate operation definition")
            by_name[definition.name] = definition
        self._by_name = by_name

    def resolve(self, name: str) -> OperationDefinition:
        if name in FORBIDDEN_OPERATION_NAMES:
            raise OperationNotAllowedError("operation is forbidden")
        definition = self._by_name.get(name)
        if definition is None:
            raise UnknownOperationError("operation is not in the allowlisted catalog")
        return definition

    def validate(self, request: OperationRequest) -> OperationDefinition:
        definition = self.resolve(request.operation)
        if request.target not in definition.allowed_targets:
            raise OperationNotAllowedError("operation target is not allowlisted")
        if request.origin not in definition.allowed_origins:
            raise OperationNotAllowedError("operation origin is not allowlisted")
        if request.timeout_seconds > definition.max_timeout_seconds:
            raise InvalidOperationArgumentsError("requested timeout exceeds the catalog limit")
        definition.validate_arguments(request.arguments)
        return definition

    def all_definitions(self) -> tuple[OperationDefinition, ...]:
        return tuple(self._by_name[name] for name in sorted(self._by_name))


ALL_NORMAL_ORIGINS = frozenset({OperationOrigin.MYUNA, OperationOrigin.CEALANA_REMOTE})
ALL_QUERY_ORIGINS = frozenset(
    {OperationOrigin.MYUNA, OperationOrigin.CEALANA_REMOTE, OperationOrigin.RECOVERY}
)
RECOVERY_ORIGINS = frozenset({OperationOrigin.CEALANA_REMOTE, OperationOrigin.RECOVERY})

MYUNA_TARGET = "myuna-core@qq.service"
WORKER_TARGETS = frozenset(
    {
        "myuna-owner-memory-shadow-dev.service",
        "myuna-turn-route-shadow-dev.service",
    }
)
SERVICE_TARGETS = frozenset(
    {
        MYUNA_TARGET,
        "myuna-owner-memory-shadow-dev.service",
        "myuna-qq-owner-runtime-dev.service",
        "myuna-turn-route-shadow-dev.service",
        "minecraft.service",
    }
)


def _definition(
    name: str,
    targets: frozenset[str],
    origins: frozenset[OperationOrigin],
    risk: RiskLevel,
    *,
    approval: bool = False,
    timeout: int = 30,
    output: int = 2048,
    cancellation: bool = False,
    recovery: bool = False,
    retry_safe: bool = True,
    arguments: tuple[ArgumentField, ...] = (),
) -> OperationDefinition:
    return OperationDefinition(
        name=name,
        allowed_targets=targets,
        allowed_origins=origins,
        risk_level=risk,
        requires_approval=approval,
        max_timeout_seconds=timeout,
        max_output_characters=output,
        supports_cancellation=cancellation,
        allowed_in_recovery=recovery,
        retry_safe=retry_safe,
        handler_id=f"catalog.{name}.v1",
        arguments=arguments,
    )


DEFAULT_OPERATION_CATALOG = OperationCatalog(
    (
        _definition(
            "myuna.health",
            frozenset({MYUNA_TARGET}),
            ALL_QUERY_ORIGINS,
            RiskLevel.LEVEL_0,
            recovery=True,
        ),
        _definition(
            "myuna.status",
            frozenset({MYUNA_TARGET}),
            ALL_QUERY_ORIGINS,
            RiskLevel.LEVEL_0,
            recovery=True,
        ),
        _definition(
            "myuna.recent_logs",
            frozenset({MYUNA_TARGET}),
            ALL_QUERY_ORIGINS,
            RiskLevel.LEVEL_0,
            output=4096,
            recovery=True,
            arguments=(
                ArgumentField("lines", ArgumentKind.INTEGER, minimum=1, maximum=200),
                ArgumentField("since_minutes", ArgumentKind.INTEGER, minimum=1, maximum=1440),
                ArgumentField("contains", ArgumentKind.STRING, max_length=64),
            ),
        ),
        _definition(
            "worker.list",
            frozenset({"myuna-workers"}),
            ALL_QUERY_ORIGINS,
            RiskLevel.LEVEL_0,
            recovery=True,
        ),
        _definition(
            "worker.status",
            WORKER_TARGETS,
            ALL_QUERY_ORIGINS,
            RiskLevel.LEVEL_0,
            recovery=True,
        ),
        _definition(
            "host.metrics",
            frozenset({"server-ubuntu", "windows-host"}),
            ALL_QUERY_ORIGINS,
            RiskLevel.LEVEL_0,
            recovery=True,
        ),
        _definition(
            "disk.usage",
            frozenset({"volume.c", "volume.d", "wsl.server-ubuntu"}),
            ALL_QUERY_ORIGINS,
            RiskLevel.LEVEL_0,
            recovery=True,
        ),
        _definition(
            "port.inspect",
            frozenset(
                {
                    "loopback:18081",
                    "loopback:25565",
                    "tailscale:3389",
                }
            ),
            ALL_QUERY_ORIGINS,
            RiskLevel.LEVEL_0,
            recovery=True,
        ),
        _definition(
            "service.status",
            SERVICE_TARGETS,
            ALL_QUERY_ORIGINS,
            RiskLevel.LEVEL_0,
            recovery=True,
        ),
        _definition(
            "worker.restart",
            WORKER_TARGETS,
            ALL_NORMAL_ORIGINS,
            RiskLevel.LEVEL_2,
            approval=True,
            timeout=120,
            retry_safe=False,
        ),
        _definition(
            "myuna.restart",
            frozenset({MYUNA_TARGET}),
            ALL_NORMAL_ORIGINS,
            RiskLevel.LEVEL_2,
            approval=True,
            timeout=120,
            retry_safe=False,
        ),
        _definition(
            "service.restart",
            SERVICE_TARGETS,
            ALL_NORMAL_ORIGINS,
            RiskLevel.LEVEL_2,
            approval=True,
            timeout=180,
            retry_safe=False,
        ),
        _definition(
            "operation.cancel",
            frozenset({"active-operation"}),
            ALL_QUERY_ORIGINS,
            RiskLevel.LEVEL_2,
            approval=True,
            timeout=30,
            recovery=True,
            retry_safe=False,
            arguments=(
                ArgumentField(
                    "operation_id",
                    ArgumentKind.STRING,
                    required=True,
                    max_length=128,
                    pattern=r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",
                ),
            ),
        ),
        _definition(
            "recovery.check_myuna",
            frozenset({MYUNA_TARGET}),
            RECOVERY_ORIGINS,
            RiskLevel.LEVEL_0,
            recovery=True,
        ),
        _definition(
            "recovery.collect_diagnostics",
            frozenset({MYUNA_TARGET}),
            RECOVERY_ORIGINS,
            RiskLevel.LEVEL_1,
            timeout=180,
            output=4096,
            cancellation=True,
            recovery=True,
        ),
        _definition(
            "recovery.restart_myuna",
            frozenset({MYUNA_TARGET}),
            RECOVERY_ORIGINS,
            RiskLevel.LEVEL_2,
            approval=True,
            timeout=180,
            recovery=True,
            retry_safe=False,
        ),
        _definition(
            "recovery.verify_myuna",
            frozenset({MYUNA_TARGET}),
            RECOVERY_ORIGINS,
            RiskLevel.LEVEL_0,
            recovery=True,
        ),
        _definition(
            "recovery.rollback_last_known_good_config",
            frozenset({MYUNA_TARGET}),
            RECOVERY_ORIGINS,
            RiskLevel.LEVEL_2,
            approval=True,
            timeout=300,
            recovery=True,
            retry_safe=False,
            arguments=(
                ArgumentField(
                    "backup_id",
                    ArgumentKind.STRING,
                    required=True,
                    max_length=128,
                    pattern=r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",
                ),
                ArgumentField(
                    "expected_sha256",
                    ArgumentKind.STRING,
                    required=True,
                    max_length=64,
                    pattern=r"[0-9a-f]{64}",
                ),
            ),
        ),
    )
)
