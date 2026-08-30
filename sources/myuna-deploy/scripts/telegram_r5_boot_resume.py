#!/usr/bin/env python3
"""Deterministically route the verified Telegram Owner runtime after boot.

This controller has no arbitrary command or path interface.  It recreates the
ephemeral container signing file, starts the pre-installed runtime socket, and
starts the pinned AstrBot compose service.  It never sends a message or calls a
model.  A failed attempt stops only the Telegram runtime chain and exits
non-zero so systemd's bounded retry policy can fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import subprocess
import tempfile
import time
from typing import Callable, Mapping


CONFIG_PATH = Path("/etc/myuna-telegram-gateway/r5-resume-v1.json")
RUNTIME_CONFIG = Path("/etc/myuna-telegram-gateway/owner-runtime-v1.json")
RUNTIME_MARKER = Path("/etc/myuna-telegram-gateway/runtime-approved")
SECRET_ROOT = Path("/etc/myuna-telegram-gateway/secrets")
AUTHORITY_SIGNING = SECRET_ROOT / "channel-signing-v1"
RUNTIME_ROOT = Path("/run/myuna-telegram-gateway")
MEDIA_AUTH_RUNTIME_ROOT = Path("/run/myuna-telegram-media-auth")
EPHEMERAL_SIGNING = RUNTIME_ROOT / "container-channel-signing-v1"
TMPFILES_CONFIG = Path("/etc/tmpfiles.d/myuna-telegram-gateway.conf")
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/r5-resume")
RECEIPT = STATE_ROOT / "LAST_SUCCESS.json"
RUNTIME_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
RUNTIME_SERVICE = "myuna-telegram-owner-runtime-dev.service"
CHALLENGE_SOCKET = "myuna-telegram-owner-challenge-dev.socket"
CHALLENGE_SERVICE = "myuna-telegram-owner-challenge-dev.service"
CONTAINER = "myuna-astrbot-telegram-dev"
ARCHIVE_PREFIX = f"{CONTAINER}.pre-"
NETWORK = "myuna-astrbot-telegram-dev"
COMPOSE_PROJECT = "myuna-telegram-r5-v1"
COMPOSE_SERVICE = "astrbot-telegram"
EXPECTED_RESTART_POLICY = "on-failure"
EXPECTED_RESTART_MAXIMUM_RETRY_COUNT = 3
EXPECTED_IMAGE_PREFIX = "myuna/astrbot-phase-f-deterministic@sha256:"
EXPECTED_IMAGE = (
    "soulter/astrbot@sha256:"
    "7546bddf1040419a455dd1ca683a5e9cf84436bbd85de17c7ac626d3af7affe4"
)
SCHEMA = "myuna.telegram.r5-boot-resume-config.v1"
RECEIPT_SCHEMA = "myuna.telegram.r5-boot-resume-receipt.v2"
FIXED_OWNER_CHAIN = (
    "telegram_r5_boot_resume.main",
    "activate_p07_owner_private_memory_v1.fixed_owner_entry",
    "activate_p07_owner_private_memory_v1.run_checkpointed_stage",
)
CONTROLLER_RELEASE_ENV = "MYUNA_PHASE_F_CONTROLLER_RELEASE_SHA256"
CONTROLLER_CONFIG_ENV = "MYUNA_PHASE_F_CONTROLLER_CONFIG_SHA256"
CONTROLLER_AUTHORITY_ENV = "MYUNA_PHASE_F_CONTROLLER_AUTHORITY_SHA256"
CONTROLLER_RELEASE_SCHEMA = "myuna.telegram.r5-controller-release.v3"
ATTEMPT5_ENTRY_PLAN_SHA256 = (
    "bed60d0c4f567e389d0c5aa54b0300944f668c577b70d07ad268c9cec653d21a"
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class ResumeRejected(RuntimeError):
    """A deterministic precondition or postcondition was rejected."""


def _termination_requested(signum: int, _frame: object) -> None:
    raise ResumeRejected(f"termination_requested:{signum}")


@dataclass(frozen=True)
class ResumeConfig:
    gateway_release: str
    compose_file: Path
    channel_root: Path
    plugin_root: Path

    @classmethod
    def from_payload(cls, payload: object) -> "ResumeConfig":
        if not isinstance(payload, dict) or set(payload) != {
            "channel_root",
            "compose_file",
            "gateway_release",
            "plugin_root",
            "schema",
        }:
            raise ResumeRejected("resume_config_shape_rejected")
        if payload["schema"] != SCHEMA:
            raise ResumeRejected("resume_config_schema_rejected")
        release = payload["gateway_release"]
        if not isinstance(release, str) or _DIGEST.fullmatch(release) is None:
            raise ResumeRejected("gateway_release_rejected")
        release_root = Path("/opt/myuna/telegram-gateway/releases") / release
        expected_compose = release_root / "channels/astrbot-telegram/compose.dev.yml"
        expected_plugin = (
            release_root
            / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
        )
        if payload["compose_file"] != expected_compose.as_posix():
            raise ResumeRejected("compose_path_rejected")
        if payload["plugin_root"] != expected_plugin.as_posix():
            raise ResumeRejected("plugin_path_rejected")
        if payload["channel_root"] != "/srv/myuna/channels/astrbot-telegram/dev":
            raise ResumeRejected("channel_root_rejected")
        return cls(
            gateway_release=release,
            compose_file=expected_compose,
            channel_root=Path(payload["channel_root"]),
            plugin_root=expected_plugin,
        )


@dataclass(frozen=True)
class ContainerRecord:
    name: str
    status: str
    project: str
    service: str
    restart_policy: str
    restart_maximum_retry_count: int


@dataclass(frozen=True, slots=True)
class PhaseFNetworkProjection:
    network_id: str
    name: str
    driver: str
    internal: bool
    attachable: bool
    ingress: bool
    enable_ipv6: bool
    options_digest: str
    labels_digest: str
    ipam_digest: str
    member_container_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.network_id or self.name != NETWORK or not self.driver:
            raise ResumeRejected("phase_f_network_identity_rejected")
        for value in (self.internal, self.attachable, self.ingress, self.enable_ipv6):
            if type(value) is not bool:
                raise ResumeRejected("phase_f_network_type_rejected")
        for value in (self.options_digest, self.labels_digest, self.ipam_digest):
            if _DIGEST.fullmatch(value) is None:
                raise ResumeRejected("phase_f_network_digest_rejected")
        if self.member_container_ids != tuple(sorted(set(self.member_container_ids))):
            raise ResumeRejected("phase_f_network_members_rejected")


@dataclass(frozen=True, slots=True)
class PhaseFContainerProjection:
    container_id: str
    name: str
    image: str
    status: str
    health: str
    restart_policy: str
    restart_maximum_retry_count: int
    project: str
    service: str
    plan_digest: str
    target_config_digest: str
    user: str
    command_digest: str
    host_config_digest: str
    mounts_digest: str
    networks_digest: str
    network_names: tuple[str, ...]
    effect_digest: str = ""
    effect_environment_digest: str = ""
    effect_host_digest: str = ""
    effect_mounts_digest: str = ""

    def __post_init__(self) -> None:
        if not self.container_id or not self.name or not self.image or not self.status:
            raise ResumeRejected("phase_f_container_identity_rejected")
        if type(self.restart_maximum_retry_count) is not int or self.restart_maximum_retry_count < 0:
            raise ResumeRejected("phase_f_container_restart_rejected")
        for value in (
            self.command_digest,
            self.host_config_digest,
            self.mounts_digest,
            self.networks_digest,
        ):
            if _DIGEST.fullmatch(value) is None:
                raise ResumeRejected("phase_f_container_digest_rejected")
        for optional in (self.plan_digest, self.target_config_digest):
            if optional and _DIGEST.fullmatch(optional) is None:
                raise ResumeRejected("phase_f_container_label_rejected")
        for optional in (
            self.effect_digest,
            self.effect_environment_digest,
            self.effect_host_digest,
            self.effect_mounts_digest,
        ):
            if optional and _DIGEST.fullmatch(optional) is None:
                raise ResumeRejected("phase_f_container_effect_rejected")
        if self.network_names != tuple(sorted(set(self.network_names))):
            raise ResumeRejected("phase_f_container_networks_rejected")


@dataclass(frozen=True, slots=True)
class PhaseFTargetContainer:
    plan_digest: str
    target_config_digest: str
    image: str
    user: str
    channel_root: Path
    plugin_root: Path
    signing_secret: Path
    runtime_root: Path
    media_auth_runtime_root: Path
    archive_name: str
    effect: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if _DIGEST.fullmatch(self.plan_digest) is None or _DIGEST.fullmatch(self.target_config_digest) is None:
            raise ResumeRejected("phase_f_target_digest_rejected")
        if (
            self.image != EXPECTED_IMAGE
            and not re.fullmatch(
                re.escape(EXPECTED_IMAGE_PREFIX) + r"[0-9a-f]{64}",
                self.image,
            )
            or re.fullmatch(r"[0-9]+:[0-9]+", self.user) is None
            or not self.archive_name.startswith(ARCHIVE_PREFIX)
        ):
            raise ResumeRejected("phase_f_target_identity_rejected")
        suffix = self.archive_name.removeprefix(ARCHIVE_PREFIX)
        if re.fullmatch(r"[0-9a-f]{16}", suffix) is None:
            raise ResumeRejected("phase_f_archive_name_rejected")
        for path in (
            self.channel_root,
            self.plugin_root,
            self.signing_secret,
            self.runtime_root,
            self.media_auth_runtime_root,
        ):
            if not path.is_absolute():
                raise ResumeRejected("phase_f_target_path_rejected")
        if self.effect is not None:
            _validate_phase_f_target_effect(self)


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    check: bool = True,
    timeout: int = 180,
) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        shell=False,
    )
    if check and result.returncode != 0:
        raise ResumeRejected(
            f"fixed_command_failed:{Path(args[0]).name}:{result.returncode}"
        )
    return result.stdout.strip()


def _phase_f_digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical(value)).hexdigest()


def _phase_f_json_lines(output: str, count: int) -> tuple[object, ...]:
    lines = output.splitlines()
    if len(lines) != count:
        raise ResumeRejected("phase_f_docker_projection_shape_rejected")
    try:
        return tuple(json.loads(line) for line in lines)
    except json.JSONDecodeError as exc:
        raise ResumeRejected("phase_f_docker_projection_decode_rejected") from exc


def phase_f_network_projection(
    *, runner: Callable[..., str] | None = None
) -> PhaseFNetworkProjection | None:
    fixed_runner = run if runner is None else runner
    output = fixed_runner(
        [
            "/usr/bin/docker",
            "network",
            "inspect",
            "--format",
            "{{json .Id}}\n{{json .Name}}\n{{json .Driver}}\n{{json .Internal}}\n"
            "{{json .Attachable}}\n{{json .Ingress}}\n{{json .EnableIPv6}}\n"
            "{{json .Options}}\n{{json .Labels}}\n{{json .IPAM}}\n{{json .Containers}}",
            NETWORK,
        ],
        check=False,
    )
    if output == "":
        return None
    (
        network_id,
        name,
        driver,
        internal,
        attachable,
        ingress,
        enable_ipv6,
        options,
        labels,
        ipam,
        containers,
    ) = _phase_f_json_lines(output, 11)
    if not isinstance(containers, dict) or not all(isinstance(key, str) and key for key in containers):
        raise ResumeRejected("phase_f_network_members_rejected")
    if not all(type(value) is bool for value in (internal, attachable, ingress, enable_ipv6)):
        raise ResumeRejected("phase_f_network_type_rejected")
    if not all(isinstance(value, str) for value in (network_id, name, driver)):
        raise ResumeRejected("phase_f_network_type_rejected")
    return PhaseFNetworkProjection(
        network_id=network_id,
        name=name,
        driver=driver,
        internal=internal,
        attachable=attachable,
        ingress=ingress,
        enable_ipv6=enable_ipv6,
        options_digest=_phase_f_digest("myuna.phase-f.network-options.v1", options),
        labels_digest=_phase_f_digest("myuna.phase-f.network-labels.v1", labels),
        ipam_digest=_phase_f_digest("myuna.phase-f.network-ipam.v1", ipam),
        member_container_ids=tuple(sorted(containers)),
    )


def phase_f_container_projection(
    name: str, *, runner: Callable[..., str] | None = None
) -> PhaseFContainerProjection | None:
    if name != CONTAINER and not name.startswith(ARCHIVE_PREFIX):
        raise ResumeRejected("phase_f_container_name_rejected")
    fixed_runner = run if runner is None else runner
    output = fixed_runner(
        [
            "/usr/bin/docker",
            "container",
            "inspect",
            "--format",
            "{{json .Id}}\n{{json .Name}}\n{{json .Config.Image}}\n{{json .State.Status}}\n"
            "{{json .State}}\n"
            "{{json .HostConfig.RestartPolicy.Name}}\n"
            "{{json .HostConfig.RestartPolicy.MaximumRetryCount}}\n"
            "{{json (index .Config.Labels \"com.docker.compose.project\")}}\n"
            "{{json (index .Config.Labels \"com.docker.compose.service\")}}\n"
            "{{json (index .Config.Labels \"myuna.phase-f.plan-digest\")}}\n"
            "{{json (index .Config.Labels \"myuna.phase-f.target-config-digest\")}}\n"
            "{{json (index .Config.Labels \"myuna.phase-f.target-effect-digest\")}}\n"
            "{{json .Config.User}}\n{{json .Config.Entrypoint}}\n{{json .Config.Cmd}}\n"
            "{{json .Config.Env}}\n{{json .Config.Healthcheck}}\n{{json .Config.StopTimeout}}\n"
            "{{json .HostConfig}}\n{{json .Mounts}}\n{{json .NetworkSettings.Networks}}",
            name,
        ],
        check=False,
    )
    if output == "":
        return None
    values = _phase_f_json_lines(output, 21)
    (
        container_id,
        observed_name,
        image,
        status,
        state,
        restart_policy,
        restart_maximum_retry_count,
        project,
        service,
        plan_digest,
        target_config_digest,
        effect_digest,
        user,
        entrypoint,
        command,
        environment,
        healthcheck,
        stop_timeout,
        host_config,
        mounts,
        networks,
    ) = values
    strings = (container_id, observed_name, image, status, restart_policy, user)
    if not all(isinstance(value, str) for value in strings):
        raise ResumeRejected("phase_f_container_type_rejected")
    if not isinstance(state, dict):
        raise ResumeRejected("phase_f_container_health_rejected")
    health_state = state.get("Health")
    if health_state is None:
        if status not in {"created", "exited"}:
            raise ResumeRejected("phase_f_container_health_rejected")
        health = ""
    else:
        if (
            not isinstance(health_state, dict)
            or not isinstance(health_state.get("Status"), str)
        ):
            raise ResumeRejected("phase_f_container_health_rejected")
        health = health_state["Status"]
    optional_strings = (project, service, plan_digest, target_config_digest, effect_digest)
    if not all(value is None or isinstance(value, str) for value in optional_strings):
        raise ResumeRejected("phase_f_container_type_rejected")
    if type(restart_maximum_retry_count) is not int or restart_maximum_retry_count < 0:
        raise ResumeRejected("phase_f_container_restart_rejected")
    if not isinstance(networks, dict) or not all(isinstance(key, str) and key for key in networks):
        raise ResumeRejected("phase_f_container_networks_rejected")
    if type(environment) is not list or not all(
        isinstance(value, str) for value in environment
    ):
        raise ResumeRejected("phase_f_container_environment_rejected")
    if healthcheck is not None and not isinstance(healthcheck, dict):
        raise ResumeRejected("phase_f_container_healthcheck_rejected")
    if stop_timeout is not None and type(stop_timeout) is not int:
        raise ResumeRejected("phase_f_container_stop_timeout_rejected")
    if not isinstance(host_config, dict):
        raise ResumeRejected("phase_f_container_host_config_rejected")
    if type(mounts) is not list or not all(
        isinstance(value, dict) for value in mounts
    ):
        raise ResumeRejected("phase_f_container_mounts_rejected")
    try:
        stable_mounts = sorted(mounts, key=canonical)
    except (TypeError, ValueError) as exc:
        raise ResumeRejected("phase_f_container_mounts_rejected") from exc
    stable_host_config = {key: value for key, value in host_config.items() if key != "RestartPolicy"}
    return PhaseFContainerProjection(
        container_id=container_id,
        name=observed_name.removeprefix("/"),
        image=image,
        status=status,
        health=health,
        restart_policy=restart_policy,
        restart_maximum_retry_count=restart_maximum_retry_count,
        project="" if project is None else project,
        service="" if service is None else service,
        plan_digest="" if plan_digest is None else plan_digest,
        target_config_digest="" if target_config_digest is None else target_config_digest,
        user=user,
        command_digest=_phase_f_digest(
            "myuna.phase-f.container-command.v1",
            {"command": command, "entrypoint": entrypoint},
        ),
        host_config_digest=_phase_f_digest("myuna.phase-f.container-host-config.v1", stable_host_config),
        mounts_digest=_phase_f_digest("myuna.phase-f.container-mounts.v1", stable_mounts),
        networks_digest=_phase_f_digest("myuna.phase-f.container-networks.v1", networks),
        network_names=tuple(sorted(networks)),
        effect_digest="" if effect_digest is None else effect_digest,
        effect_environment_digest=_phase_f_digest(
            "phase_f_attempt5_target_environment_v1",
            _phase_f_observed_effect_environment(environment),
        ),
        effect_host_digest=_phase_f_digest(
            "phase_f_attempt5_target_host_v1",
            _phase_f_observed_effect_host(host_config, healthcheck, stop_timeout),
        ),
        effect_mounts_digest=_phase_f_digest(
            "phase_f_attempt5_target_mounts_v1",
            _phase_f_observed_effect_mounts(mounts),
        ),
    )


def phase_f_require_external_network(
    expected: PhaseFNetworkProjection,
    *, runner: Callable[..., str] | None = None,
) -> PhaseFNetworkProjection:
    first = phase_f_network_projection(runner=runner)
    second = phase_f_network_projection(runner=runner)
    if first is None or first != second or first != expected:
        raise ResumeRejected("phase_f_external_network_not_ready")
    return first


def _phase_f_same_network_object(
    expected: PhaseFNetworkProjection,
    observed: PhaseFNetworkProjection | None,
) -> bool:
    if observed is None:
        return False
    fields = (
        "network_id",
        "name",
        "driver",
        "internal",
        "attachable",
        "ingress",
        "enable_ipv6",
        "options_digest",
        "labels_digest",
        "ipam_digest",
    )
    return all(getattr(expected, field) == getattr(observed, field) for field in fields)


def _phase_f_same_object(
    expected: PhaseFContainerProjection,
    observed: PhaseFContainerProjection | None,
    *, name: str,
    allow_status_change: bool = False,
    allow_policy_change: bool = False,
    allow_network_runtime_change: bool = False,
) -> bool:
    if observed is None:
        return False
    fields = (
        "container_id",
        "image",
        "project",
        "service",
        "plan_digest",
        "target_config_digest",
        "user",
        "command_digest",
        "host_config_digest",
        "mounts_digest",
        "network_names",
        "effect_digest",
    )
    if not allow_network_runtime_change:
        fields = (*fields, "networks_digest")
    if observed.name != name or any(getattr(observed, field) != getattr(expected, field) for field in fields):
        return False
    if not allow_status_change and (observed.status, observed.health) != (expected.status, expected.health):
        return False
    if not allow_policy_change and (
        observed.restart_policy,
        observed.restart_maximum_retry_count,
    ) != (expected.restart_policy, expected.restart_maximum_retry_count):
        return False
    return True


def phase_f_network_identity_sha256(projection: PhaseFNetworkProjection) -> str:
    return _phase_f_digest(
        "myuna.phase-f.network-identity.v1",
        {
            "attachable": projection.attachable,
            "driver": projection.driver,
            "enable_ipv6": projection.enable_ipv6,
            "ingress": projection.ingress,
            "internal": projection.internal,
            "ipam_digest": projection.ipam_digest,
            "labels_digest": projection.labels_digest,
            "name": projection.name,
            "network_id": projection.network_id,
            "options_digest": projection.options_digest,
        },
    )


def phase_f_container_identity_sha256(
    projection: PhaseFContainerProjection,
) -> str:
    return _phase_f_digest(
        "myuna.phase-f.container-identity.v1",
        {
            "command_digest": projection.command_digest,
            "container_id": projection.container_id,
            "effect_digest": projection.effect_digest,
            "host_config_digest": projection.host_config_digest,
            "image": projection.image,
            "mounts_digest": projection.mounts_digest,
            "name": projection.name,
            "network_names": list(projection.network_names),
            "networks_digest": projection.networks_digest,
            "plan_digest": projection.plan_digest,
            "project": projection.project,
            "restart_maximum_retry_count": projection.restart_maximum_retry_count,
            "restart_policy": projection.restart_policy,
            "service": projection.service,
            "target_config_digest": projection.target_config_digest,
            "user": projection.user,
        },
    )

def phase_f_stop_container_exact(
    expected: PhaseFContainerProjection,
    *, name: str,
    runner: Callable[..., str] | None = None,
) -> PhaseFContainerProjection:
    fixed_runner = run if runner is None else runner
    observed = phase_f_container_projection(name, runner=fixed_runner)
    if not _phase_f_same_object(expected, observed, name=name, allow_status_change=True):
        raise ResumeRejected("phase_f_stop_identity_rejected")
    assert observed is not None
    if observed.status in {"created", "exited"}:
        return observed
    if observed.status != "running":
        raise ResumeRejected("phase_f_stop_state_ambiguous")
    fixed_runner(["/usr/bin/docker", "container", "stop", "--time", "30", observed.container_id])
    after = phase_f_container_projection(name, runner=fixed_runner)
    if not _phase_f_same_object(expected, after, name=name, allow_status_change=True) or after is None or after.status not in {"created", "exited"}:
        raise ResumeRejected("phase_f_stop_poststate_rejected")
    return after


def phase_f_rename_container_exact(
    expected: PhaseFContainerProjection,
    *, source_name: str,
    target_name: str,
    runner: Callable[..., str] | None = None,
) -> PhaseFContainerProjection:
    fixed_runner = run if runner is None else runner
    source = phase_f_container_projection(source_name, runner=fixed_runner)
    target = phase_f_container_projection(target_name, runner=fixed_runner)
    if target is not None:
        if source is None and _phase_f_same_object(expected, target, name=target_name, allow_status_change=True):
            return target
        raise ResumeRejected("phase_f_rename_collision_ambiguous")
    if not _phase_f_same_object(expected, source, name=source_name, allow_status_change=True):
        raise ResumeRejected("phase_f_rename_identity_rejected")
    assert source is not None
    if source.status not in {"created", "exited"}:
        raise ResumeRejected("phase_f_rename_state_rejected")
    fixed_runner(["/usr/bin/docker", "container", "rename", source.container_id, target_name])
    after_source = phase_f_container_projection(source_name, runner=fixed_runner)
    after_target = phase_f_container_projection(target_name, runner=fixed_runner)
    if after_source is not None or not _phase_f_same_object(expected, after_target, name=target_name, allow_status_change=True):
        raise ResumeRejected("phase_f_rename_poststate_rejected")
    assert after_target is not None
    return after_target


def _phase_f_effect_environment() -> dict[str, object]:
    return {
        "env_file": "/etc/myuna/secrets/gemini-api-key-telegram-gateway.env",
        "explicit": [
            "HOME=/AstrBot/data/home",
            "MYUNA_GATEWAY_CHANNEL_INSTANCE=telegram-owner-dev",
            (
                "MYUNA_GATEWAY_SIGNING_SECRET="
                "/run/secrets/myuna-telegram-channel-signing-v1"
            ),
            "MYUNA_GATEWAY_SOCKET=/run/myuna-telegram-gateway/owner.sock",
            "MYUNA_MEDIA_SHADOW_SOCKET=/run/myuna-telegram-media-auth/shadow.sock",
            "PYTHONDONTWRITEBYTECODE=1",
            "TZ=Asia/Shanghai",
        ],
    }


def _phase_f_effect_host(user: str) -> dict[str, object]:
    if re.fullmatch(r"[0-9]+:[0-9]+", user) is None:
        raise ResumeRejected("phase_f_target_identity_rejected")
    uid, gid = user.split(":", 1)
    return {
        "cap_drop": ["ALL"],
        "cpus": "1.00",
        "health": {
            "command": (
                "python -c \"import socket; "
                "s=socket.create_connection(('127.0.0.1',6185),3); s.close()\""
            ),
            "interval": "15s",
            "retries": 12,
            "start_period": "45s",
            "timeout": "5s",
        },
        "init": True,
        "log": {"driver": "json-file", "max_file": "5", "max_size": "10m"},
        "memory": "1024m",
        "pids_limit": 192,
        "publish": "127.0.0.1:6285:6185",
        "restart": {"maximum_retry_count": 0, "name": "no"},
        "security_opt": ["no-new-privileges=true"],
        "stop_timeout": 30,
        "tmpfs": f"/tmp:rw,nosuid,nodev,noexec,size=128m,uid={uid},gid={gid}",
    }


def _phase_f_effect_mounts(target: PhaseFTargetContainer) -> list[dict[str, object]]:
    return [
        {
            "destination": "/AstrBot/data",
            "readonly": False,
            "source": (target.channel_root / "astrbot-data").as_posix(),
        },
        {
            "destination": "/AstrBot/data/plugins/astrbot_plugin_myuna_telegram_gateway",
            "readonly": True,
            "source": target.plugin_root.as_posix(),
        },
        {
            "destination": "/run/secrets/myuna-telegram-channel-signing-v1",
            "readonly": True,
            "source": target.signing_secret.as_posix(),
        },
        {
            "destination": "/run/myuna-telegram-gateway",
            "readonly": True,
            "source": target.runtime_root.as_posix(),
        },
        {
            "destination": "/run/myuna-telegram-media-auth",
            "readonly": True,
            "source": target.media_auth_runtime_root.as_posix(),
        },
    ]


def _phase_f_observed_effect_environment(values: list[str]) -> list[str]:
    names = {
        row.split("=", 1)[0]
        for row in _phase_f_effect_environment()["explicit"]
    }
    selected = [row for row in values if row.split("=", 1)[0] in names]
    if len(selected) != len(names) or len({row.split("=", 1)[0] for row in selected}) != len(names):
        return []
    return sorted(selected)


def _phase_f_observed_effect_mounts(
    mounts: list[dict[str, object]],
) -> list[dict[str, object]]:
    projected: list[dict[str, object]] = []
    for row in mounts:
        source = row.get("Source")
        destination = row.get("Destination")
        rw = row.get("RW")
        if type(source) is not str or type(destination) is not str or type(rw) is not bool:
            return []
        projected.append(
            {"destination": destination, "readonly": not rw, "source": source}
        )
    destination_order = (
        "/AstrBot/data",
        "/AstrBot/data/plugins/astrbot_plugin_myuna_telegram_gateway",
        "/run/secrets/myuna-telegram-channel-signing-v1",
        "/run/myuna-telegram-gateway",
        "/run/myuna-telegram-media-auth",
    )
    if (
        len(projected) != len(destination_order)
        or {str(row["destination"]) for row in projected} != set(destination_order)
    ):
        return []
    by_destination = {str(row["destination"]): row for row in projected}
    if len(by_destination) != len(projected):
        return []
    return [by_destination[destination] for destination in destination_order]


def _phase_f_duration(value: object) -> str:
    if type(value) is not int or value < 0 or value % 1_000_000_000:
        return "invalid"
    return f"{value // 1_000_000_000}s"


def _phase_f_observed_effect_host(
    host: dict[str, object],
    healthcheck: dict[str, object] | None,
    stop_timeout: int | None,
) -> dict[str, object]:
    restart = host.get("RestartPolicy")
    log = host.get("LogConfig")
    ports = host.get("PortBindings")
    tmpfs = host.get("Tmpfs")
    test = None if healthcheck is None else healthcheck.get("Test")
    log_config = None if not isinstance(log, dict) else log.get("Config")
    cap_drop = host.get("CapDrop")
    security_opt = host.get("SecurityOpt")
    if not (
        isinstance(restart, dict)
        and isinstance(log, dict)
        and isinstance(ports, dict)
        and isinstance(tmpfs, dict)
        and isinstance(test, list)
        and len(test) == 2
        and test[0] == "CMD-SHELL"
        and isinstance(test[1], str)
        and isinstance(log_config, dict)
        and isinstance(cap_drop, list)
        and isinstance(security_opt, list)
    ):
        return {}
    bindings = ports.get("6185/tcp")
    if not (
        isinstance(bindings, list)
        and len(bindings) == 1
        and isinstance(bindings[0], dict)
    ):
        return {}
    tmp = tmpfs.get("/tmp")
    if not isinstance(tmp, str):
        return {}
    nano_cpus = host.get("NanoCpus")
    memory = host.get("Memory")
    if type(nano_cpus) is not int or type(memory) is not int:
        return {}
    return {
        "cap_drop": sorted(cap_drop),
        "cpus": f"{nano_cpus / 1_000_000_000:.2f}",
        "health": {
            "command": test[1],
            "interval": _phase_f_duration(healthcheck.get("Interval")),
            "retries": healthcheck.get("Retries"),
            "start_period": _phase_f_duration(healthcheck.get("StartPeriod")),
            "timeout": _phase_f_duration(healthcheck.get("Timeout")),
        },
        "init": host.get("Init"),
        "log": {
            "driver": log.get("Type"),
            "max_file": log_config.get("max-file"),
            "max_size": log_config.get("max-size"),
        },
        "memory": f"{memory // (1024 * 1024)}m",
        "pids_limit": host.get("PidsLimit"),
        "publish": (
            f"{bindings[0].get('HostIp')}:{bindings[0].get('HostPort')}:6185"
        ),
        "restart": {
            "maximum_retry_count": restart.get("MaximumRetryCount"),
            "name": restart.get("Name"),
        },
        "security_opt": sorted(security_opt),
        "stop_timeout": stop_timeout,
        "tmpfs": "/tmp:" + tmp,
    }


def _validate_phase_f_target_effect(target: PhaseFTargetContainer) -> None:
    effect = target.effect
    if type(effect) is not dict:
        raise ResumeRejected("phase_f_target_effect_rejected")
    assert isinstance(effect, dict)
    body = {key: effect[key] for key in effect if key != "effect_sha256"}
    digests = (
        "archive_projection_sha256",
        "command_sha256",
        "create_arguments_sha256",
        "environment_sha256",
        "host_sha256",
        "mounts_sha256",
        "network_projection_sha256",
        "network_sha256",
    )
    if set(effect) != {
        "archive_container_id", "archive_name", "archive_projection_sha256",
        "attempt", "command", "command_sha256", "container_name",
        "create_arguments_sha256", "effect_sha256", "environment",
        "environment_sha256", "host", "host_sha256", "image", "mounts",
        "mounts_sha256", "network_name", "network_projection_sha256",
        "network_sha256", "plan_digest", "project", "service",
        "target_config_digest", "user", "writer",
    } or any(
        type(effect.get(key)) is not str
        or _DIGEST.fullmatch(str(effect.get(key))) is None
        for key in (*digests, "effect_sha256")
    ):
        raise ResumeRejected("phase_f_target_effect_rejected")
    expected = {
        "archive_container_id": effect["archive_container_id"],
        "archive_name": target.archive_name,
        "archive_projection_sha256": effect["archive_projection_sha256"],
        "attempt": 5,
        "command": {"command": ["python", "main.py"], "entrypoint": None},
        "container_name": CONTAINER,
        "environment": _phase_f_effect_environment(),
        "host": _phase_f_effect_host(target.user),
        "image": target.image,
        "mounts": _phase_f_effect_mounts(target),
        "network_name": NETWORK,
        "network_projection_sha256": effect["network_projection_sha256"],
        "plan_digest": ATTEMPT5_ENTRY_PLAN_SHA256,
        "project": COMPOSE_PROJECT,
        "service": COMPOSE_SERVICE,
        "target_config_digest": target.target_config_digest,
        "user": target.user,
        "writer": False,
    }
    if (
        type(effect["archive_container_id"]) is not str
        or not effect["archive_container_id"]
        or target.plan_digest != ATTEMPT5_ENTRY_PLAN_SHA256
    ):
        raise ResumeRejected("phase_f_target_effect_rejected")
    expected["command_sha256"] = _phase_f_digest(
        "myuna.phase-f.container-command.v1", expected["command"]
    )
    expected["environment_sha256"] = _phase_f_digest(
        "phase_f_attempt5_target_environment_v1",
        sorted(expected["environment"]["explicit"]),
    )
    expected["host_sha256"] = _phase_f_digest(
        "phase_f_attempt5_target_host_v1", expected["host"]
    )
    expected["mounts_sha256"] = _phase_f_digest(
        "phase_f_attempt5_target_mounts_v1", expected["mounts"]
    )
    expected["network_sha256"] = _phase_f_digest(
        "phase_f_attempt5_target_network_v1",
        {
            "name": expected["network_name"],
            "projection_sha256": expected["network_projection_sha256"],
        },
    )
    expected["create_arguments_sha256"] = _phase_f_digest(
        "phase_f_attempt5_target_create_arguments_v1",
        _phase_f_base_create_arguments(target),
    )
    if body != expected or effect["effect_sha256"] != _phase_f_digest(
        "phase_f_attempt5_target_effect_v1", expected
    ):
        raise ResumeRejected("phase_f_target_effect_rejected")


def _phase_f_effect_host_digest_with_restart(
    effect: dict[str, object],
    restart_policy: str,
    restart_maximum_retry_count: int,
) -> str:
    host = effect["host"]
    assert isinstance(host, dict)
    transitioned = {
        **host,
        "restart": {
            "maximum_retry_count": restart_maximum_retry_count,
            "name": restart_policy,
        },
    }
    return _phase_f_digest("phase_f_attempt5_target_host_v1", transitioned)


def phase_f_target_matches_authority(
    authority: PhaseFTargetContainer,
    observed: PhaseFContainerProjection | None,
    *,
    network: PhaseFNetworkProjection | None,
    expected_container_id: str | None = None,
) -> bool:
    """Admit one dynamic TARGET through the complete sealed source projection."""

    if observed is None or network is None:
        return False
    try:
        _validate_phase_f_target_effect(authority)
    except ResumeRejected:
        return False
    effect = authority.effect
    assert isinstance(effect, dict)
    if expected_container_id is not None and (
        not expected_container_id or observed.container_id != expected_container_id
    ):
        return False
    expected = {
        "command_digest": effect["command_sha256"],
        "effect_digest": effect["effect_sha256"],
        "effect_environment_digest": effect["environment_sha256"],
        "effect_mounts_digest": effect["mounts_sha256"],
        "image": authority.image,
        "name": CONTAINER,
        "network_names": (NETWORK,),
        "plan_digest": authority.plan_digest,
        "project": COMPOSE_PROJECT,
        "service": COMPOSE_SERVICE,
        "target_config_digest": authority.target_config_digest,
        "user": authority.user,
    }
    if any(getattr(observed, key) != value for key, value in expected.items()):
        return False
    if (
        phase_f_network_identity_sha256(network)
        != effect["network_projection_sha256"]
        or network.member_container_ids not in {(), (observed.container_id,)}
    ):
        return False
    pre_policy_digest = str(effect["host_sha256"])
    post_policy_digest = _phase_f_effect_host_digest_with_restart(
        effect,
        EXPECTED_RESTART_POLICY,
        EXPECTED_RESTART_MAXIMUM_RETRY_COUNT,
    )
    return (
        observed.status in {"created", "exited", "running"}
        and (
            observed.restart_policy,
            observed.restart_maximum_retry_count,
            observed.effect_host_digest,
        )
        in {
            ("no", 0, pre_policy_digest),
            (
                EXPECTED_RESTART_POLICY,
                EXPECTED_RESTART_MAXIMUM_RETRY_COUNT,
                post_policy_digest,
            ),
        }
    )


def _phase_f_base_create_arguments(target: PhaseFTargetContainer) -> list[str]:
    data_root = target.channel_root / "astrbot-data"
    return [
        "/usr/bin/docker", "container", "create",
        "--name", CONTAINER,
        "--user", target.user,
        "--init",
        "--restart", "no",
        "--env-file", "/etc/myuna/secrets/gemini-api-key-telegram-gateway.env",
        "--env", "HOME=/AstrBot/data/home",
        "--env", "MYUNA_GATEWAY_CHANNEL_INSTANCE=telegram-owner-dev",
        "--env", "MYUNA_GATEWAY_SIGNING_SECRET=/run/secrets/myuna-telegram-channel-signing-v1",
        "--env", "MYUNA_GATEWAY_SOCKET=/run/myuna-telegram-gateway/owner.sock",
        "--env", "MYUNA_MEDIA_SHADOW_SOCKET=/run/myuna-telegram-media-auth/shadow.sock",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--env", "TZ=Asia/Shanghai",
        "--publish", "127.0.0.1:6285:6185",
        "--mount", f"type=bind,src={data_root},dst=/AstrBot/data",
        "--mount", f"type=bind,src={target.plugin_root},dst=/AstrBot/data/plugins/astrbot_plugin_myuna_telegram_gateway,readonly",
        "--mount", f"type=bind,src={target.signing_secret},dst=/run/secrets/myuna-telegram-channel-signing-v1,readonly",
        "--mount", f"type=bind,src={target.runtime_root},dst=/run/myuna-telegram-gateway,readonly",
        "--mount", f"type=bind,src={target.media_auth_runtime_root},dst=/run/myuna-telegram-media-auth,readonly",
        "--network", NETWORK,
        "--security-opt", "no-new-privileges=true",
        "--cap-drop", "ALL",
        "--pids-limit", "192",
        "--memory", "1024m",
        "--cpus", "1.00",
        "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size=128m,uid={target.user.split(':', 1)[0]},gid={target.user.split(':', 1)[1]}",
        "--stop-timeout", "30",
        "--health-cmd", "python -c \"import socket; s=socket.create_connection(('127.0.0.1',6185),3); s.close()\"",
        "--health-interval", "15s",
        "--health-timeout", "5s",
        "--health-retries", "12",
        "--health-start-period", "45s",
        "--log-driver", "json-file",
        "--log-opt", "max-size=10m",
        "--log-opt", "max-file=5",
        "--label", f"com.docker.compose.project={COMPOSE_PROJECT}",
        "--label", f"com.docker.compose.service={COMPOSE_SERVICE}",
        "--label", f"myuna.phase-f.plan-digest={target.plan_digest}",
        "--label", f"myuna.phase-f.target-config-digest={target.target_config_digest}",
        target.image,
    ]


def _phase_f_create_arguments(target: PhaseFTargetContainer) -> list[str]:
    arguments = _phase_f_base_create_arguments(target)
    if target.effect is None:
        return arguments
    _validate_phase_f_target_effect(target)
    effect_digest = str(target.effect["effect_sha256"])
    arguments[-1:-1] = [
        "--label",
        "myuna.phase-f.target-effect-digest=" + effect_digest,
    ]
    return arguments


def _phase_f_numeric_access(
    checks: tuple[tuple[str, Path, int], ...],
    *,
    uid: int,
    gid: int,
) -> dict[str, bool]:
    """Evaluate exact POSIX access as the target identity with no extra groups."""

    read_descriptor, write_descriptor = os.pipe()
    try:
        child = os.fork()
    except OSError as exc:
        os.close(read_descriptor)
        os.close(write_descriptor)
        raise ResumeRejected("phase_f_runtime_access_rejected") from exc
    if child == 0:
        try:
            os.close(read_descriptor)
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            result = {
                role: os.access(path, mode)
                for role, path, mode in checks
            }
            payload = canonical(result)
        except BaseException:
            payload = b""
        try:
            os.write(write_descriptor, payload)
        finally:
            os.close(write_descriptor)
            os._exit(0)
    os.close(write_descriptor)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(read_descriptor, 4096)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(read_descriptor)
    _, status = os.waitpid(child, 0)
    if status != 0:
        raise ResumeRejected("phase_f_runtime_access_rejected")
    try:
        value = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResumeRejected("phase_f_runtime_access_rejected") from exc
    roles = {role for role, _path, _mode in checks}
    if (
        type(value) is not dict
        or set(value) != roles
        or any(type(item) is not bool for item in value.values())
    ):
        raise ResumeRejected("phase_f_runtime_access_rejected")
    return value


def _phase_f_runtime_access_projection(
    target: PhaseFTargetContainer,
    *,
    runner: Callable[..., str] | None = None,
    probe_uid: int | None = None,
    probe_gid: int | None = None,
) -> dict[str, bool]:
    """Bind source identity to exact host metadata and effective permissions."""

    if target.effect is not None:
        _validate_phase_f_target_effect(target)
    uid_text, gid_text = target.user.split(":", 1)
    uid, gid = int(uid_text), int(gid_text)
    fixed_runner = run if runner is None else runner
    output = fixed_runner(
        ["/usr/bin/docker", "info", "--format", "{{json .SecurityOptions}}"],
        check=False,
    )
    security_options = _phase_f_json_lines(output, 1)[0] if output else None
    if (
        not isinstance(security_options, list)
        or not all(isinstance(value, str) for value in security_options)
        or any("userns" in value.lower() for value in security_options)
        or "--group-add" in _phase_f_base_create_arguments(target)
    ):
        raise ResumeRejected("phase_f_runtime_identity_model_rejected")

    socket_path = target.runtime_root / "owner.sock"
    specifications = (
        ("channel_data", target.channel_root / "astrbot-data", "directory", uid, gid, 0o700, os.R_OK | os.W_OK | os.X_OK),
        ("plugin_release", target.plugin_root, "directory", 0, gid, 0o550, os.R_OK | os.X_OK),
        ("signing_secret", target.signing_secret, "regular", uid, gid, 0o400, os.R_OK),
        ("runtime_root", target.runtime_root, "directory", 0, gid, 0o750, os.R_OK | os.X_OK),
        ("media_runtime_root", target.media_auth_runtime_root, "directory", uid, gid, 0o750, os.R_OK | os.X_OK),
        ("runtime_socket", socket_path, "socket", 0, gid, 0o660, os.W_OK),
    )
    checks: list[tuple[str, Path, int]] = []
    for role, path, kind, expected_uid, expected_gid, mode, access_mode in specifications:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ResumeRejected("phase_f_runtime_resource_metadata_rejected") from exc
        kind_matches = {
            "directory": stat.S_ISDIR(metadata.st_mode),
            "regular": stat.S_ISREG(metadata.st_mode),
            "socket": stat.S_ISSOCK(metadata.st_mode),
        }[kind]
        if (
            path.is_symlink()
            or not kind_matches
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_nlink < 1
            or kind != "directory" and metadata.st_nlink != 1
        ):
            raise ResumeRejected("phase_f_runtime_resource_metadata_rejected")
        try:
            acl = os.getxattr(path, "system.posix_acl_access", follow_symlinks=False)
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                raise ResumeRejected("phase_f_runtime_resource_acl_rejected") from exc
        else:
            if acl:
                raise ResumeRejected("phase_f_runtime_resource_acl_rejected")
        checks.append((role, path, access_mode))
    return _phase_f_numeric_access(
        tuple(checks),
        uid=uid if probe_uid is None else probe_uid,
        gid=gid if probe_gid is None else probe_gid,
    )


def _phase_f_require_runtime_compatibility(
    target: PhaseFTargetContainer,
    *,
    runner: Callable[..., str] | None = None,
) -> None:
    projection = _phase_f_runtime_access_projection(target, runner=runner)
    if not all(projection.values()):
        raise ResumeRejected("phase_f_runtime_access_rejected")


def phase_f_create_target_stopped(
    target: PhaseFTargetContainer,
    *, expected_network: PhaseFNetworkProjection,
    archived_old: PhaseFContainerProjection,
    runner: Callable[..., str] | None = None,
) -> PhaseFContainerProjection:
    fixed_runner = run if runner is None else runner
    effect = target.effect
    if effect is not None:
        _validate_phase_f_target_effect(target)
        if (
            phase_f_network_identity_sha256(expected_network)
            != effect["network_projection_sha256"]
            or archived_old.container_id != effect["archive_container_id"]
            or archived_old.name != effect["archive_name"]
            or phase_f_container_identity_sha256(archived_old)
            != effect["archive_projection_sha256"]
        ):
            raise ResumeRejected("phase_f_target_effect_prestate_rejected")
    _phase_f_require_runtime_compatibility(target, runner=fixed_runner)
    phase_f_require_external_network(expected_network, runner=fixed_runner)
    if expected_network.member_container_ids:
        raise ResumeRejected("phase_f_create_network_prestate_rejected")
    if phase_f_container_projection(CONTAINER, runner=fixed_runner) is not None:
        raise ResumeRejected("phase_f_create_canonical_collision")
    archived = phase_f_container_projection(target.archive_name, runner=fixed_runner)
    if not _phase_f_same_object(archived_old, archived, name=target.archive_name, allow_status_change=True):
        raise ResumeRejected("phase_f_create_archive_drift")
    if effect is not None and (
        archived is None
        or phase_f_container_identity_sha256(archived)
        != effect["archive_projection_sha256"]
    ):
        raise ResumeRejected("phase_f_target_effect_archive_rejected")
    fixed_runner(_phase_f_create_arguments(target))
    created = phase_f_container_projection(CONTAINER, runner=fixed_runner)
    if (
        created is None
        or created.name != CONTAINER
        or created.image != target.image
        or created.status not in {"created", "exited"}
        or created.restart_policy != "no"
        or created.restart_maximum_retry_count != 0
        or created.project != COMPOSE_PROJECT
        or created.service != COMPOSE_SERVICE
        or created.plan_digest != target.plan_digest
        or created.target_config_digest != target.target_config_digest
        or created.user != target.user
        or effect is not None
        and (
            created.effect_digest != effect["effect_sha256"]
            or created.command_digest != effect["command_sha256"]
            or created.effect_environment_digest != effect["environment_sha256"]
            or created.effect_host_digest != effect["host_sha256"]
            or created.effect_mounts_digest != effect["mounts_sha256"]
        )
        or created.network_names != (NETWORK,)
    ):
        raise ResumeRejected("phase_f_create_poststate_rejected")
    after_network = phase_f_network_projection(runner=fixed_runner)
    if (
        not _phase_f_same_network_object(expected_network, after_network)
        or after_network is None
        or after_network.member_container_ids
    ):
        raise ResumeRejected("phase_f_create_network_poststate_rejected")
    return created


def phase_f_set_restart_policy_exact(
    expected: PhaseFContainerProjection,
    *, runner: Callable[..., str] | None = None,
) -> PhaseFContainerProjection:
    fixed_runner = run if runner is None else runner
    observed = phase_f_container_projection(CONTAINER, runner=fixed_runner)
    if not _phase_f_same_object(expected, observed, name=CONTAINER, allow_policy_change=True):
        raise ResumeRejected("phase_f_policy_identity_rejected")
    assert observed is not None
    if (observed.restart_policy, observed.restart_maximum_retry_count) == (
        EXPECTED_RESTART_POLICY,
        EXPECTED_RESTART_MAXIMUM_RETRY_COUNT,
    ):
        return observed
    if (observed.restart_policy, observed.restart_maximum_retry_count) != ("no", 0):
        raise ResumeRejected("phase_f_policy_state_ambiguous")
    fixed_runner([
        "/usr/bin/docker", "container", "update",
        "--restart", f"{EXPECTED_RESTART_POLICY}:{EXPECTED_RESTART_MAXIMUM_RETRY_COUNT}",
        observed.container_id,
    ])
    after = phase_f_container_projection(CONTAINER, runner=fixed_runner)
    if not _phase_f_same_object(expected, after, name=CONTAINER, allow_policy_change=True) or after is None or (
        after.restart_policy,
        after.restart_maximum_retry_count,
    ) != (EXPECTED_RESTART_POLICY, EXPECTED_RESTART_MAXIMUM_RETRY_COUNT):
        raise ResumeRejected("phase_f_policy_poststate_rejected")
    return after


def phase_f_start_container_exact(
    expected: PhaseFContainerProjection,
    *, runner: Callable[..., str] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> PhaseFContainerProjection:
    fixed_runner = run if runner is None else runner
    observed = phase_f_container_projection(CONTAINER, runner=fixed_runner)
    if not _phase_f_same_object(
        expected, observed, name=CONTAINER,
        allow_status_change=True, allow_network_runtime_change=True,
    ):
        raise ResumeRejected("phase_f_start_identity_rejected")
    assert observed is not None
    if observed.status == "running" and observed.health == "healthy":
        return observed
    if observed.status not in {"created", "exited"}:
        raise ResumeRejected("phase_f_start_state_ambiguous")
    fixed_runner(["/usr/bin/docker", "container", "start", observed.container_id])
    for index in range(13):
        after = phase_f_container_projection(CONTAINER, runner=fixed_runner)
        if after is None:
            raise ResumeRejected("phase_f_start_poststate_missing")
        if not _phase_f_same_object(
            expected, after, name=CONTAINER,
            allow_status_change=True, allow_network_runtime_change=True,
        ):
            raise ResumeRejected("phase_f_start_poststate_identity_rejected")
        if after.status == "running" and after.health == "healthy":
            return after
        if after.status != "running" or after.health not in {"", "starting"}:
            raise ResumeRejected("phase_f_start_poststate_state_rejected")
        if index < 12:
            sleeper(5.0)
    raise ResumeRejected("phase_f_start_health_timeout")


def phase_f_restore_old_running_exact(
    expected: PhaseFContainerProjection,
    *, runner: Callable[..., str] | None = None,
) -> PhaseFContainerProjection:
    fixed_runner = run if runner is None else runner
    observed = phase_f_container_projection(CONTAINER, runner=fixed_runner)
    if not _phase_f_same_object(
        expected, observed, name=CONTAINER,
        allow_status_change=True, allow_network_runtime_change=True,
    ):
        raise ResumeRejected("phase_f_old_start_identity_rejected")
    assert observed is not None
    if expected.status in {"created", "exited"}:
        if observed.status not in {"created", "exited"}:
            raise ResumeRejected("phase_f_old_stopped_state_rejected")
        return observed
    if expected.status != "running":
        raise ResumeRejected("phase_f_old_prestate_rejected")
    if observed.status == "running":
        return observed
    if observed.status not in {"created", "exited"}:
        raise ResumeRejected("phase_f_old_start_state_ambiguous")
    fixed_runner(["/usr/bin/docker", "container", "start", observed.container_id])
    after = phase_f_container_projection(CONTAINER, runner=fixed_runner)
    if not _phase_f_same_object(
        expected, after, name=CONTAINER,
        allow_status_change=True, allow_network_runtime_change=True,
    ) or after is None or after.status != "running":
        raise ResumeRejected("phase_f_old_start_poststate_rejected")
    return after


def phase_f_remove_container_exact(
    expected: PhaseFContainerProjection,
    *, expected_network: PhaseFNetworkProjection,
    runner: Callable[..., str] | None = None,
) -> None:
    fixed_runner = run if runner is None else runner
    observed = phase_f_container_projection(CONTAINER, runner=fixed_runner)
    if observed is None:
        phase_f_require_external_network(expected_network, runner=fixed_runner)
        return
    if not _phase_f_same_object(expected, observed, name=CONTAINER, allow_status_change=True, allow_policy_change=True):
        raise ResumeRejected("phase_f_remove_identity_rejected")
    if observed.status not in {"created", "exited"}:
        raise ResumeRejected("phase_f_remove_state_rejected")
    fixed_runner(["/usr/bin/docker", "container", "rm", observed.container_id])
    if phase_f_container_projection(CONTAINER, runner=fixed_runner) is not None:
        raise ResumeRejected("phase_f_remove_poststate_rejected")
    network = phase_f_network_projection(runner=fixed_runner)
    if not _phase_f_same_network_object(expected_network, network) or network is None or (
        network.network_id,
        network.name,
        network.driver,
        network.internal,
        network.attachable,
        network.ingress,
        network.enable_ipv6,
        network.options_digest,
        network.labels_digest,
        network.ipam_digest,
    ) != (
        expected_network.network_id,
        expected_network.name,
        expected_network.driver,
        expected_network.internal,
        expected_network.attachable,
        expected_network.ingress,
        expected_network.enable_ipv6,
        expected_network.options_digest,
        expected_network.labels_digest,
        expected_network.ipam_digest,
    ) or network.member_container_ids != expected_network.member_container_ids:
        raise ResumeRejected("phase_f_remove_network_poststate_rejected")


def read_config(path: Path = CONFIG_PATH) -> ResumeConfig:
    if path.is_symlink() or not path.is_file():
        raise ResumeRejected("resume_config_path_rejected")
    metadata = path.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ResumeRejected("resume_config_metadata_rejected")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResumeRejected("resume_config_decode_rejected") from exc
    return ResumeConfig.from_payload(payload)


def protected_file(path: Path, mode: int, *, uid: int = 0) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    metadata = path.stat()
    return metadata.st_uid == uid and stat.S_IMODE(metadata.st_mode) == mode


def protected_directory(path: Path, mode: int, *, uid: int, gid: int) -> bool:
    if path.is_symlink() or not path.is_dir():
        return False
    metadata = path.stat()
    return (
        metadata.st_uid == uid
        and metadata.st_gid == gid
        and stat.S_IMODE(metadata.st_mode) == mode
    )


def write_atomic(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def binding_verified() -> bool:
    sql = """
SELECT count(*)::text || '|' || min(binding_status)
FROM myuna_identity.account_binding
WHERE binding_id='binding-astrbot-telegram-owner-cealana'
  AND principal_id='principal-owner-cealana'
  AND namespace_id='ns-owner-cealana-private'
  AND channel_kind='astrbot_telegram';
"""
    result = subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            "postgres",
            "--",
            "/usr/bin/psql",
            "-X",
            "-At",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            "myuna_dev",
        ],
        input=sql,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "1|verified"


def unit_active(unit: str) -> bool:
    return run(["/usr/bin/systemctl", "is-active", unit], check=False) == "active"


def core_transport_ready() -> bool:
    """Check only whether Core accepts a loopback TCP connection.

    Core's HTTP health endpoints emit audit records, so the boot controller
    must not call them.  This probe sends no application bytes.
    """

    try:
        with socket.create_connection(("127.0.0.1", 18081), timeout=3):
            pass
        return True
    except OSError:
        return False


def stage_ephemeral_signing(uid: int, gid: int) -> None:
    payload = bytearray(AUTHORITY_SIGNING.read_bytes())
    try:
        if len(payload) < 32:
            raise ResumeRejected("signing_secret_rejected")
        write_atomic(EPHEMERAL_SIGNING, bytes(payload), mode=0o400, uid=uid, gid=gid)
    finally:
        for index in range(len(payload)):
            payload[index] = 0


def clear_docker_created_placeholder(path: Path = EPHEMERAL_SIGNING) -> None:
    """Remove only Docker's exact, empty bind-source placeholder directory.

    Docker with an ``unless-stopped`` container may run before this controller
    after a cold boot.  When the bind source does not yet exist, Docker creates
    an empty root-owned 0755 directory and the container then fails because the
    destination expects a file.  No other directory shape is safe to remove.
    """

    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        raise ResumeRejected("ephemeral_signing_symlink_rejected")
    if path.is_file():
        return
    if not path.is_dir() or os.path.ismount(path):
        raise ResumeRejected("ephemeral_signing_type_rejected")
    metadata = path.stat()
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or any(path.iterdir())
    ):
        raise ResumeRejected("ephemeral_placeholder_metadata_rejected")
    path.rmdir()


def compose_environment(config: ResumeConfig, uid: int, gid: int) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "CHANNEL_GID": str(gid),
            "CHANNEL_MEDIA_AUTH_RUNTIME_ROOT": MEDIA_AUTH_RUNTIME_ROOT.as_posix(),
            "CHANNEL_PLUGIN_ROOT": config.plugin_root.as_posix(),
            "CHANNEL_ROOT": config.channel_root.as_posix(),
            "CHANNEL_RUNTIME_ROOT": RUNTIME_ROOT.as_posix(),
            "CHANNEL_SIGNING_SECRET_PATH": EPHEMERAL_SIGNING.as_posix(),
            "CHANNEL_UID": str(uid),
            "COMPOSE_PROJECT_NAME": COMPOSE_PROJECT,
        }
    )
    return environment


def container_inventory() -> tuple[ContainerRecord, ...]:
    names: set[str] = set()
    for container_filter in (
        f"label=com.docker.compose.service={COMPOSE_SERVICE}",
        f"name={CONTAINER}",
    ):
        output = run(
            [
                "/usr/bin/docker",
                "container",
                "ls",
                "-a",
                "--filter",
                container_filter,
                "--format",
                "{{.Names}}",
            ]
        )
        names.update(line for line in output.splitlines() if line)
    records: list[ContainerRecord] = []
    for name in sorted(names):
        if name != CONTAINER and not name.startswith(ARCHIVE_PREFIX):
            raise ResumeRejected("unexpected_telegram_container_name")
        fields = run(
            [
                "/usr/bin/docker",
                "container",
                "inspect",
                "--format",
                "{{.Name}}|{{.State.Status}}|"
                '{{index .Config.Labels "com.docker.compose.project"}}|'
                '{{index .Config.Labels "com.docker.compose.service"}}|'
                "{{.HostConfig.RestartPolicy.Name}}|"
                "{{.HostConfig.RestartPolicy.MaximumRetryCount}}",
                name,
            ]
        ).split("|")
        if len(fields) != 6:
            raise ResumeRejected("container_inventory_shape_rejected")
        try:
            maximum_retry_count = int(fields[5])
        except ValueError as exc:
            raise ResumeRejected("container_restart_count_rejected") from exc
        records.append(
            ContainerRecord(
                name=fields[0].removeprefix("/"),
                status=fields[1],
                project="" if fields[2] == "<no value>" else fields[2],
                service="" if fields[3] == "<no value>" else fields[3],
                restart_policy=fields[4],
                restart_maximum_retry_count=maximum_retry_count,
            )
        )
    return tuple(records)


def validate_container_inventory(records: tuple[ContainerRecord, ...]) -> None:
    exact_count = 0
    for record in records:
        if record.name == CONTAINER:
            exact_count += 1
            if (
                record.project != COMPOSE_PROJECT
                or record.service != COMPOSE_SERVICE
                or record.restart_policy != EXPECTED_RESTART_POLICY
                or record.restart_maximum_retry_count
                != EXPECTED_RESTART_MAXIMUM_RETRY_COUNT
            ):
                raise ResumeRejected("managed_container_contract_rejected")
            continue
        if not record.name.startswith(ARCHIVE_PREFIX):
            raise ResumeRejected("unexpected_telegram_container_name")
        if (
            record.status not in {"created", "dead", "exited"}
            or record.restart_policy != "no"
            or record.restart_maximum_retry_count != 0
        ):
            raise ResumeRejected("archived_container_contract_rejected")
    if exact_count > 1:
        raise ResumeRejected("managed_container_count_rejected")


def container_state() -> str:
    return run(
        [
            "/usr/bin/docker",
            "container",
            "inspect",
            "--format",
            "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|"
            "{{.Config.Image}}|{{.HostConfig.RestartPolicy.Name}}|"
            "{{.HostConfig.RestartPolicy.MaximumRetryCount}}|"
            '{{index .Config.Labels "com.docker.compose.project"}}|'
            '{{index .Config.Labels "com.docker.compose.service"}}',
            CONTAINER,
        ],
        check=False,
    )


def stop_failed_chain(config: ResumeConfig, environment: dict[str, str]) -> None:
    run(
        [
            "/usr/bin/docker",
            "compose",
            "-f",
            config.compose_file.as_posix(),
            "stop",
            "--timeout",
            "30",
            COMPOSE_SERVICE,
        ],
        env=environment,
        cwd=config.compose_file.parent,
        check=False,
        timeout=90,
    )
    run(["/usr/bin/systemctl", "stop", RUNTIME_SERVICE], check=False)
    run(["/usr/bin/systemctl", "stop", RUNTIME_SOCKET], check=False)
    if EPHEMERAL_SIGNING.is_file() and not EPHEMERAL_SIGNING.is_symlink():
        EPHEMERAL_SIGNING.unlink()
    elif EPHEMERAL_SIGNING.is_dir() and not EPHEMERAL_SIGNING.is_symlink():
        metadata = EPHEMERAL_SIGNING.stat()
        if (
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o755
            and not any(EPHEMERAL_SIGNING.iterdir())
            and not os.path.ismount(EPHEMERAL_SIGNING)
        ):
            EPHEMERAL_SIGNING.rmdir()


def validate_persistent_prestate(config: ResumeConfig) -> None:
    service = pwd.getpwnam("myuna-gateway-telegram")
    if not protected_file(CONFIG_PATH, 0o600):
        raise ResumeRejected("resume_config_metadata_rejected")
    if not protected_file(RUNTIME_MARKER, 0o400):
        raise ResumeRejected("runtime_marker_rejected")
    if not protected_file(RUNTIME_CONFIG, 0o640):
        raise ResumeRejected("runtime_config_rejected")
    if any(
        not protected_file(SECRET_ROOT / name, 0o600)
        for name in (
            "bot-token-v1",
            "channel-signing-v1",
            "core-token-v1",
            "identity-pepper-v1",
        )
    ):
        raise ResumeRejected("secret_metadata_rejected")
    if not config.compose_file.is_file() or config.compose_file.is_symlink():
        raise ResumeRejected("compose_file_rejected")
    if not config.plugin_root.is_dir() or config.plugin_root.is_symlink():
        raise ResumeRejected("plugin_root_rejected")
    if not config.channel_root.is_dir() or config.channel_root.is_symlink():
        raise ResumeRejected("channel_data_rejected")
    if service.pw_uid == 0 or service.pw_gid == 0:
        raise ResumeRejected("service_identity_rejected")
    if not binding_verified():
        raise ResumeRejected("owner_binding_rejected")
    if unit_active(CHALLENGE_SOCKET) or unit_active(CHALLENGE_SERVICE):
        raise ResumeRejected("challenge_runtime_active")


def persist_receipt(config: ResumeConfig, *, started_at: str) -> None:
    service = pwd.getpwnam("myuna-gateway-telegram")
    receipt = {
        "binding_status": "verified",
        "capabilities_changed": False,
        "container": "running_healthy",
        "compose_project": COMPOSE_PROJECT,
        "core_http_health_called": False,
        "core_readiness": "loopback_tcp_connect_only",
        "gateway_release": config.gateway_release,
        "message_model_memory_tool_calls": False,
        "runtime_service": "active",
        "runtime_socket": "active",
        "schema": RECEIPT_SCHEMA,
        "started_at": started_at,
        "status": "TELEGRAM_R5_RESUME_READY_NO_AUDIT",
    }
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(STATE_ROOT, service.pw_uid, service.pw_gid)
    os.chmod(STATE_ROOT, 0o750)
    write_atomic(
        RECEIPT,
        canonical(receipt),
        mode=0o440,
        uid=service.pw_uid,
        gid=service.pw_gid,
    )


def _retired_direct_resume() -> int:
    """The accepted-main direct R5 orchestrator is not an admission route."""

    raise ResumeRejected("phase_f_direct_resume_retired")


def _release_member(root: Path, relative: str) -> tuple[bytes, os.stat_result]:
    path = Path(relative)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != relative
        or not path.parts
    ):
        raise ResumeRejected("fixed_controller_member_path_rejected")
    current = root
    for part in path.parts[:-1]:
        current = current / part
        metadata = current.lstat()
        if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ResumeRejected("fixed_controller_member_path_rejected")
    selected = root / path
    try:
        descriptor = os.open(
            selected,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise ResumeRejected("fixed_controller_member_rejected") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ResumeRejected("fixed_controller_member_rejected")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise ResumeRejected("fixed_controller_member_rejected")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_ctime_ns,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_ctime_ns,
        after.st_mtime_ns,
    ):
        raise ResumeRejected("fixed_controller_member_changed")
    named = selected.lstat()
    if (
        named.st_dev,
        named.st_ino,
        named.st_mode,
        named.st_nlink,
        named.st_size,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
    ):
        raise ResumeRejected("fixed_controller_member_substituted")
    return b"".join(chunks), after


def _controller_manifest(root: Path) -> tuple[dict[str, object], bytes]:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise ResumeRejected("fixed_controller_root_rejected") from exc
    if (
        root.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o555
        or _DIGEST.fullmatch(root.name) is None
    ):
        raise ResumeRejected("fixed_controller_root_rejected")
    payload, member = _release_member(root, "MANIFEST.json")
    if (
        stat.S_IMODE(member.st_mode) != 0o444
        or sha256(payload).hexdigest() != root.name
        or not payload.endswith(b"\n")
        or b"\r" in payload
        or b"\x00" in payload
    ):
        raise ResumeRejected("fixed_controller_manifest_rejected")
    try:
        document = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResumeRejected("fixed_controller_manifest_rejected") from exc
    if type(document) is not dict or canonical(document) != payload:
        raise ResumeRejected("fixed_controller_manifest_rejected")
    return document, payload


def fixed_controller_authority_sha256(
    document: Mapping[str, object],
    release_digest: str,
    config_sha256: str,
) -> str:
    files = document.get("files")
    if (
        _DIGEST.fullmatch(release_digest) is None
        or _DIGEST.fullmatch(config_sha256) is None
        or type(files) is not list
        or not files
    ):
        raise ResumeRejected("fixed_controller_authority_rejected")
    body = {
        "config_sha256": config_sha256,
        "controller_builder_sha256": document.get("controller_builder_sha256"),
        "core_commit": document.get("core_commit"),
        "core_tree": document.get("core_tree"),
        "deploy_commit": document.get("deploy_commit"),
        "deploy_parent": document.get("deploy_parent"),
        "deploy_tree": document.get("deploy_tree"),
        "member_set_sha256": sha256(canonical(files)).hexdigest(),
        "owner_chain": list(FIXED_OWNER_CHAIN),
        "release_sha256": release_digest,
        "source_receipt_sha256": document.get("paired_source_receipt_sha256"),
    }
    for key in (
        "config_sha256",
        "controller_builder_sha256",
        "member_set_sha256",
        "release_sha256",
        "source_receipt_sha256",
    ):
        if type(body[key]) is not str or _DIGEST.fullmatch(str(body[key])) is None:
            raise ResumeRejected("fixed_controller_authority_rejected")
    return sha256(
        b"myuna.phase-f.fixed-product-controller-authority.v1\0"
        + canonical(body)
    ).hexdigest()


def verify_fixed_controller_release(
    release_root: Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    document, _manifest = _controller_manifest(release_root)
    required = {
        "controller_builder",
        "controller_builder_sha256",
        "core_commit",
        "core_import_closure",
        "core_tree",
        "deploy_commit",
        "deploy_parent",
        "deploy_tree",
        "files",
        "fixed_product_authority",
        "forbidden_modules",
        "owner_chain",
        "paired_builder",
        "paired_builder_sha256",
        "paired_source_package_sha256",
        "paired_source_receipt_sha256",
        "schema",
        "source_receipt",
    }
    if (
        set(document) != required
        or document["schema"] != CONTROLLER_RELEASE_SCHEMA
        or document["owner_chain"] != list(FIXED_OWNER_CHAIN)
    ):
        raise ResumeRejected("fixed_controller_manifest_shape_rejected")
    files = document["files"]
    assert isinstance(files, list)
    destinations: set[str] = set()
    for value in files:
        if type(value) is not dict or set(value) != {
            "blob",
            "bytes",
            "content_sha256",
            "destination",
            "installed_mode",
            "mode",
            "source",
        }:
            raise ResumeRejected("fixed_controller_member_schema_rejected")
        destination = value["destination"]
        if type(destination) is not str or destination in destinations:
            raise ResumeRejected("fixed_controller_member_schema_rejected")
        destinations.add(destination)
        payload, metadata = _release_member(release_root, destination)
        if (
            sha256(payload).hexdigest() != value["content_sha256"]
            or len(payload) != value["bytes"]
            or f"0{stat.S_IMODE(metadata.st_mode):03o}" != value["installed_mode"]
        ):
            raise ResumeRejected("fixed_controller_member_rejected")
    receipt, receipt_metadata = _release_member(
        release_root,
        "CORRESPONDING_SOURCE.json",
    )
    if (
        stat.S_IMODE(receipt_metadata.st_mode) != 0o444
        or sha256(receipt).hexdigest() != document["paired_source_receipt_sha256"]
        or canonical(document["source_receipt"]) != receipt
    ):
        raise ResumeRejected("fixed_controller_source_receipt_rejected")
    expected_files = {
        *destinations,
        "CORRESPONDING_SOURCE.json",
        "MANIFEST.json",
    }
    expected_directories = {"."}
    for destination in expected_files:
        parent = Path(destination).parent
        while parent.as_posix() != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files: set[str] = set()
    actual_directories = {"."}
    for selected in release_root.rglob("*"):
        relative = selected.relative_to(release_root).as_posix()
        try:
            metadata = selected.lstat()
        except OSError as exc:
            raise ResumeRejected("fixed_controller_member_set_rejected") from exc
        if selected.is_symlink():
            raise ResumeRejected("fixed_controller_member_set_rejected")
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o555:
                raise ResumeRejected("fixed_controller_member_set_rejected")
            actual_directories.add(relative)
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            actual_files.add(relative)
        else:
            raise ResumeRejected("fixed_controller_member_set_rejected")
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ResumeRejected("fixed_controller_member_set_rejected")
    authority = document["fixed_product_authority"]
    if type(authority) is not dict:
        raise ResumeRejected("fixed_product_authority_rejected")
    try:
        import p07_owner_private_memory_production_plan as fixed_product
    except ImportError as exc:
        raise ResumeRejected("fixed_product_authority_rejected") from exc
    try:
        validated_authority = fixed_product.validate_source_authority(authority)
    except fixed_product.ProductionPlanRejected as exc:
        raise ResumeRejected("fixed_product_authority_rejected") from exc
    authority = {
        key: validated_authority[key]
        for key in (
            "builder",
            "controller",
            "files",
            "image",
            "parent",
            "releases",
            "schema",
            "source",
        )
    }
    controller = authority.get("controller")
    if type(controller) is not dict:
        raise ResumeRejected("fixed_product_authority_rejected")
    member_set = sha256(canonical(files)).hexdigest()
    if (
        controller.get("member_set_sha256") != member_set
        or controller.get("source_receipt_sha256")
        != document["paired_source_receipt_sha256"]
    ):
        raise ResumeRejected("fixed_product_authority_rejected")
    staging_destinations = {
        destination for destination in destinations if destination.startswith("staging/")
    }
    if staging_destinations != fixed_product.authority_bundle_members(authority):
        raise ResumeRejected("fixed_product_bundle_member_set_rejected")
    source_authority = authority.get("source")
    required_destinations = {
        "activate_p07_owner_private_memory_v1.py",
        "p07_owner_private_memory_production_plan.py",
        "telegram_r5_boot_resume.py",
    }
    forbidden_destinations = {
        "activate_p07_d_generation13_v1.py",
        "p07_d_activation_transaction.py",
        "p07_owner_private_memory_transactional_controller.py",
        "p07_owner_private_memory_transactional_runtime.py",
        "activation_transaction_substrate_v1.py",
    }
    if (
        type(source_authority) is not dict
        or source_authority.get("deploy_commit") != document["deploy_commit"]
        or source_authority.get("deploy_parent") != document["deploy_parent"]
        or source_authority.get("deploy_tree") != document["deploy_tree"]
        or source_authority.get("core_commit") != document["core_commit"]
        or source_authority.get("core_tree") != document["core_tree"]
        or not required_destinations.issubset(destinations)
        or destinations & forbidden_destinations
    ):
        raise ResumeRejected("fixed_product_authority_rejected")
    config_sha = controller.get("config_sha256")
    if type(config_sha) is not str:
        raise ResumeRejected("fixed_product_authority_rejected")
    static_authority = fixed_controller_authority_sha256(
        document,
        release_root.name,
        config_sha,
    )
    source = os.environ if environment is None else environment
    values = (
        source.get(CONTROLLER_RELEASE_ENV),
        source.get(CONTROLLER_CONFIG_ENV),
        source.get(CONTROLLER_AUTHORITY_ENV),
    )
    if values != (None, None, None) and values != (
        release_root.name,
        config_sha,
        static_authority,
    ):
        raise ResumeRejected("fixed_controller_environment_rejected")
    return {
        **authority,
        "authority_sha256": static_authority,
        "release_sha256": release_root.name,
    }


def load_fixed_product_source_authority(
    release_root: Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    verified = verify_fixed_controller_release(
        release_root,
        environment=environment,
    )
    return {
        key: verified[key]
        for key in (
            "builder",
            "controller",
            "files",
            "image",
            "parent",
            "releases",
            "schema",
            "source",
        )
    }


def main() -> int:
    """Route an exact sealed target to the fixed owner before any effect."""

    selected = (
        os.environ.get(CONTROLLER_RELEASE_ENV),
        os.environ.get(CONTROLLER_CONFIG_ENV),
        os.environ.get(CONTROLLER_AUTHORITY_ENV),
    )
    if selected != (None, None, None):
        verify_fixed_controller_release(Path(__file__).resolve().parent)
        from activate_p07_owner_private_memory_v1 import fixed_owner_entry

        return fixed_owner_entry()
    from activate_p07_d_generation13_v1 import controller_entry

    return controller_entry()


if __name__ == "__main__":
    raise SystemExit(main())
