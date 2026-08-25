"""Fixed-path live backend for selected-to-selected Core upgrades.

This module exposes no caller-selected command, unit, path, or shell. It is
repository-only until a later content-addressed executor release is approved.
"""

from __future__ import annotations

from hashlib import sha256
import grp
import http.client
import os
from pathlib import Path
import subprocess
import time
from typing import Mapping, Sequence

from core_release_selector import (
    compute_tree_digest,
    load_runtime_binding,
    parse_json_document,
    validate_immutable_release_tree,
)
from core_release_selector_upgrade import (
    ROLLBACK_BINDING_PATH,
    ROLLBACK_ENV_PATH,
    ROLLBACK_SELECTOR_PATH,
    SELECTOR_DROPIN,
    TARGET_BINDING_PATH,
    TARGET_CREDENTIAL_PATH,
    TARGET_ENV_PATH,
    TARGET_SELECTOR_PATH,
    TELEGRAM_CREDENTIAL_DROPIN,
)
from core_release_selector_upgrade_executor import RuntimeSnapshot, UpgradeBundle


CORE_UNIT = "myuna-core@qq.service"
GATEWAY_SOCKET = "myuna-qq-owner-runtime-dev.socket"
GATEWAY_SERVICE = "myuna-qq-owner-runtime-dev.service"
ALLOWED_UNITS = frozenset({CORE_UNIT, GATEWAY_SOCKET, GATEWAY_SERVICE})
CORE_DROPIN_ROOT = Path("/etc/systemd/system/myuna-core@qq.service.d")
BINDING_PATH = Path("/etc/myuna/core-release-selector/qq.binding.json")
ENVIRONMENT_PATH = Path("/etc/myuna/qq.env")
SELECTOR_PATH = CORE_DROPIN_ROOT / SELECTOR_DROPIN
CREDENTIAL_PATH = CORE_DROPIN_ROOT / TELEGRAM_CREDENTIAL_DROPIN
HEALTH_HOST = "127.0.0.1"
HEALTH_PORT = 18081


class SelectedUpgradeLiveBackendError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise SelectedUpgradeLiveBackendError(code)


def digest_file(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "live_file_rejected")
    return sha256(path.read_bytes()).hexdigest()


def running_state(state: Mapping[str, str]) -> bool:
    return state.get("ActiveState") == "active" and state.get("SubState") == "running"


def socket_ready_state(state: Mapping[str, str]) -> bool:
    return state.get("ActiveState") == "active" and state.get("SubState") in {
        "listening",
        "running",
    }


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class CommandRunner:
    """No-shell subprocess runner for fixed argument vectors."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: int = 30,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        require(
            isinstance(arguments, Sequence)
            and bool(arguments)
            and all(isinstance(item, str) and item for item in arguments),
            "command_arguments_rejected",
        )
        result = subprocess.run(
            list(arguments),
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            shell=False,
            env={
                "LANG": "C.UTF-8",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
        require(
            result.returncode == 0,
            f"command_failed:{Path(arguments[0]).name}:{result.returncode}",
        )
        return result


class FixedSystemdSelectedUpgradeBackend:
    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        wait_timeout_seconds: int = 30,
    ) -> None:
        self.runner = runner or CommandRunner()
        self.wait_timeout_seconds = wait_timeout_seconds
        try:
            self.myuna_gid = grp.getgrnam("myuna").gr_gid
        except KeyError as exc:
            raise SelectedUpgradeLiveBackendError("myuna_group_missing") from exc

    def _systemctl(self, action: str, unit: str | None = None) -> None:
        require(
            action in {"start", "stop", "daemon-reload"},
            "systemctl_action_rejected",
        )
        if action == "daemon-reload":
            require(unit is None, "systemctl_unit_rejected")
            arguments = ["/usr/bin/systemctl", "daemon-reload"]
        else:
            require(unit in ALLOWED_UNITS, "systemctl_unit_rejected")
            arguments = ["/usr/bin/systemctl", action, unit]
        self.runner.run(arguments, timeout_seconds=self.wait_timeout_seconds)

    def _show(self, unit: str, properties: Sequence[str]) -> dict[str, str]:
        require(unit in ALLOWED_UNITS, "systemd_unit_rejected")
        result = self.runner.run(
            [
                "/usr/bin/systemctl",
                "show",
                unit,
                *[f"--property={name}" for name in properties],
            ],
            timeout_seconds=15,
        )
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                name, value = line.split("=", 1)
                values[name] = value
        require(set(values) == set(properties), "systemd_show_rejected")
        return values

    def _state(self, unit: str) -> tuple[str, str]:
        state = self._show(unit, ("ActiveState", "SubState"))
        return state["ActiveState"], state["SubState"]

    def _wait_state(self, unit: str, expected: tuple[str, str]) -> None:
        deadline = time.monotonic() + self.wait_timeout_seconds
        while time.monotonic() < deadline:
            observed = self._state(unit)
            if observed == expected or (
                unit == GATEWAY_SOCKET
                and expected[0] == "active"
                and socket_ready_state(
                    {"ActiveState": observed[0], "SubState": observed[1]}
                )
            ):
                return
            time.sleep(0.1)
        raise SelectedUpgradeLiveBackendError("unit_state_timeout")

    def _dropin_hashes(self) -> dict[str, str]:
        require(
            CORE_DROPIN_ROOT.is_dir() and not CORE_DROPIN_ROOT.is_symlink(),
            "core_dropin_root_rejected",
        )
        result: dict[str, str] = {}
        for path in sorted(CORE_DROPIN_ROOT.iterdir()):
            require(path.is_file() and not path.is_symlink(), "core_dropin_entry_rejected")
            result[path.name] = digest_file(path)
        return result

    def _atomic_replace(
        self,
        destination: Path,
        payload: bytes,
        *,
        mode: int,
        uid: int,
        gid: int,
    ) -> None:
        parent = destination.parent
        require(
            destination.is_absolute()
            and parent.is_dir()
            and not parent.is_symlink()
            and (not destination.exists() or not destination.is_symlink()),
            "atomic_destination_rejected",
        )
        temporary = parent / f".{destination.name}.{os.getpid()}.selected-upgrade.tmp"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, mode)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                require(written > 0, "atomic_write_failed")
                view = view[written:]
            os.fchmod(descriptor, mode)
            os.fchown(descriptor, uid, gid)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, destination)
        fsync_directory(parent)
        require(
            digest_file(destination) == sha256(payload).hexdigest(),
            "atomic_write_verification_failed",
        )

    def _verify_target_release(self, bundle: UpgradeBundle) -> None:
        binding = load_runtime_binding(
            parse_json_document(bundle.payloads[TARGET_BINDING_PATH])
        )
        release_root = Path(binding.selected_release.release_path.as_posix())
        validate_immutable_release_tree(release_root, binding.selected_release)
        tree_digest, file_count = compute_tree_digest(release_root)
        require(
            tree_digest == binding.selected_release.tree_sha256
            and file_count == binding.selected_release.file_count,
            "target_release_evidence_rejected",
        )
        verifier = Path(binding.verifier_script_path)
        require(
            digest_file(verifier) == binding.verifier_script_sha256
            == bundle.plan["source"]["verifier_sha256"],
            "target_verifier_rejected",
        )

    def verify_exact_prestate(self, bundle: UpgradeBundle) -> RuntimeSnapshot:
        prestate = bundle.plan["prestate"]
        fragment = Path(self._show(CORE_UNIT, ("FragmentPath",))["FragmentPath"])
        require(
            digest_file(fragment) == prestate["base_unit_sha256"]
            and digest_file(BINDING_PATH) == prestate["binding_sha256"]
            and self._dropin_hashes() == prestate["dropin_sha256"]
            and digest_file(ENVIRONMENT_PATH) == prestate["qq_env_sha256"]
            and not CREDENTIAL_PATH.exists()
            and self._show(CORE_UNIT, ("NeedDaemonReload",))["NeedDaemonReload"]
            == "no",
            "selected_upgrade_prestate_drift",
        )
        states = {
            unit: self._state(unit)
            for unit in (CORE_UNIT, GATEWAY_SOCKET, GATEWAY_SERVICE)
        }
        for unit, observed in states.items():
            expected = prestate["service_states"][unit]
            require(
                observed == (expected["active_state"], expected["sub_state"]),
                "selected_upgrade_service_prestate_drift",
            )
        self._verify_target_release(bundle)
        return RuntimeSnapshot.create(
            core_active=states[CORE_UNIT][0] == "active",
            gateway_socket_active=states[GATEWAY_SOCKET][0] == "active",
            gateway_service_active=states[GATEWAY_SERVICE][0] == "active",
            binding_sha256=prestate["binding_sha256"],
        )

    def quiesce_gateway(self, bundle: UpgradeBundle) -> None:
        for unit in (GATEWAY_SOCKET, GATEWAY_SERVICE, CORE_UNIT):
            if self._state(unit)[0] == "active":
                self._systemctl("stop", unit)
                self._wait_state(unit, ("inactive", "dead"))

    def apply_files(self, bundle: UpgradeBundle) -> None:
        prestate = bundle.plan["prestate"]
        require(
            digest_file(BINDING_PATH) == prestate["binding_sha256"]
            and self._dropin_hashes() == prestate["dropin_sha256"]
            and digest_file(ENVIRONMENT_PATH) == prestate["qq_env_sha256"]
            and not CREDENTIAL_PATH.exists(),
            "selected_upgrade_apply_prestate_drift",
        )
        self._atomic_replace(
            BINDING_PATH,
            bundle.payloads[TARGET_BINDING_PATH],
            mode=0o640,
            uid=0,
            gid=self.myuna_gid,
        )
        self._atomic_replace(
            SELECTOR_PATH,
            bundle.payloads[TARGET_SELECTOR_PATH],
            mode=0o644,
            uid=0,
            gid=0,
        )
        self._atomic_replace(
            ENVIRONMENT_PATH,
            bundle.payloads[TARGET_ENV_PATH],
            mode=0o640,
            uid=0,
            gid=self.myuna_gid,
        )
        self._atomic_replace(
            CREDENTIAL_PATH,
            bundle.payloads[TARGET_CREDENTIAL_PATH],
            mode=0o644,
            uid=0,
            gid=0,
        )

    def daemon_reload(self, bundle: UpgradeBundle) -> None:
        self._systemctl("daemon-reload")

    def start_core(self, bundle: UpgradeBundle) -> None:
        self._systemctl("start", CORE_UNIT)
        self._wait_state(CORE_UNIT, ("active", "running"))

    def _loopback_health(self) -> None:
        deadline = time.monotonic() + self.wait_timeout_seconds
        while True:
            try:
                for path in ("/healthz", "/readyz"):
                    connection = http.client.HTTPConnection(
                        HEALTH_HOST,
                        HEALTH_PORT,
                        timeout=min(5, self.wait_timeout_seconds),
                    )
                    try:
                        connection.request("GET", path)
                        response = connection.getresponse()
                        response.read(4096)
                        require(
                            response.status == 200,
                            "target_loopback_health_not_ready",
                        )
                    finally:
                        connection.close()
                return
            except (
                OSError,
                http.client.HTTPException,
                SelectedUpgradeLiveBackendError,
            ):
                if time.monotonic() >= deadline:
                    raise SelectedUpgradeLiveBackendError(
                        "target_loopback_health_timeout"
                    ) from None
                time.sleep(0.1)

    def verify_target(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None:
        target = bundle.plan["target"]
        binding = load_runtime_binding(
            parse_json_document(bundle.payloads[TARGET_BINDING_PATH])
        )
        release_path = binding.selected_release.release_path.as_posix()
        require(
            self._state(CORE_UNIT) == ("active", "running")
            and self._show(CORE_UNIT, ("NeedDaemonReload",))["NeedDaemonReload"]
            == "no"
            and self._show(CORE_UNIT, ("WorkingDirectory",))["WorkingDirectory"]
            == release_path
            and digest_file(BINDING_PATH)
            == sha256(bundle.payloads[TARGET_BINDING_PATH]).hexdigest()
            and self._dropin_hashes() == target["dropin_sha256"]
            and digest_file(ENVIRONMENT_PATH) == target["qq_env_sha256"],
            "selected_upgrade_target_rejected",
        )
        self._verify_target_release(bundle)
        self._loopback_health()
        self.runner.run(
            [
                "/usr/sbin/runuser",
                "-u",
                "myuna",
                "--",
                "/usr/bin/env",
                f"PYTHONPATH={release_path}/src",
                "/usr/bin/python3",
                binding.verifier_script_path,
                "verify-active",
            ],
            cwd=Path(release_path),
            timeout_seconds=60,
        )

    def restore_gateway(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None:
        if snapshot.gateway_socket_active:
            self._systemctl("start", GATEWAY_SOCKET)
            self._wait_state(GATEWAY_SOCKET, ("active", "listening"))
        if snapshot.gateway_service_active:
            self._systemctl("start", GATEWAY_SERVICE)
            self._wait_state(GATEWAY_SERVICE, ("active", "running"))

    def restore_files(self, bundle: UpgradeBundle) -> None:
        self._atomic_replace(
            BINDING_PATH,
            bundle.payloads[ROLLBACK_BINDING_PATH],
            mode=0o640,
            uid=0,
            gid=self.myuna_gid,
        )
        self._atomic_replace(
            SELECTOR_PATH,
            bundle.payloads[ROLLBACK_SELECTOR_PATH],
            mode=0o644,
            uid=0,
            gid=0,
        )
        self._atomic_replace(
            ENVIRONMENT_PATH,
            bundle.payloads[ROLLBACK_ENV_PATH],
            mode=0o640,
            uid=0,
            gid=self.myuna_gid,
        )
        if CREDENTIAL_PATH.exists():
            require(
                digest_file(CREDENTIAL_PATH)
                == sha256(bundle.payloads[TARGET_CREDENTIAL_PATH]).hexdigest(),
                "rollback_credential_drift",
            )
            CREDENTIAL_PATH.unlink()
            fsync_directory(CORE_DROPIN_ROOT)

    def restore_prestate(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None:
        if self._state(CORE_UNIT)[0] == "active":
            self._systemctl("stop", CORE_UNIT)
            self._wait_state(CORE_UNIT, ("inactive", "dead"))
        if snapshot.core_active:
            self._systemctl("start", CORE_UNIT)
            self._wait_state(CORE_UNIT, ("active", "running"))
        self.restore_gateway(bundle, snapshot)
