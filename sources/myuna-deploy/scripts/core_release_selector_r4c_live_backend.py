"""Restricted live backend for the journaled R4C executor.

All service names and runtime paths are fixed constants.  No model or caller
supplies a command, unit name, destination path, environment variable, or
script body.  The backend is imported by the CLI only after the explicit live
execution gate has been satisfied.
"""

from __future__ import annotations

from hashlib import sha256
import grp
import os
from pathlib import Path
import subprocess
import time
from typing import Mapping, Sequence

from core_release_selector import parse_json_document
import core_release_selector_transaction as transaction_v1
from core_release_selector_r4c_executor import (
    R4CExecutionError,
    RuntimeSnapshot,
    TransactionBundle,
)


CORE_UNIT = "myuna-core@qq.service"
GATEWAY_SOCKET_UNIT = "myuna-qq-owner-runtime-dev.socket"
GATEWAY_SERVICE_UNIT = "myuna-qq-owner-runtime-dev.service"
CORE_DROPIN_ROOT = Path("/etc/systemd/system/myuna-core@qq.service.d")
RUNTIME_BINDING_PATH = Path("/etc/myuna/core-release-selector/qq.binding.json")
_ALLOWED_UNITS = {CORE_UNIT, GATEWAY_SOCKET_UNIT, GATEWAY_SERVICE_UNIT}
_GATEWAY_SOCKET_READY_SUBSTATES = frozenset({"listening", "running"})


class LiveBackendError(R4CExecutionError):
    """A deterministic live observation or mutation rejection."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise LiveBackendError(code)


def _sha256_file(path: Path) -> str:
    _require(
        path.is_file() and not path.is_symlink(),
        "live_file_rejected",
    )
    return sha256(path.read_bytes()).hexdigest()


def _running_state(state: Mapping[str, str]) -> bool:
    """Return whether a regular service-like unit is active and running."""

    return (
        state.get("ActiveState") == "active"
        and state.get("SubState") == "running"
    )


def _gateway_socket_ready_state(state: Mapping[str, str]) -> bool:
    """Return whether the fixed Gateway Socket can safely accept/start work.

    A systemd socket is normally ``active/listening`` before its triggered
    service starts and may report ``active/running`` once the service is
    connected.  Both are ready states for the socket-only stage.  No other
    active substate is accepted.
    """

    return (
        state.get("ActiveState") == "active"
        and state.get("SubState") in _GATEWAY_SOCKET_READY_SUBSTATES
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class CommandRunner:
    """Subprocess runner that never invokes a shell."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: int = 30,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        _require(
            isinstance(arguments, Sequence)
            and bool(arguments)
            and all(isinstance(item, str) and item != "" for item in arguments),
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
        )
        if result.returncode != 0:
            raise LiveBackendError(
                f"command_failed:{Path(arguments[0]).name}:{result.returncode}"
            )
        return result


class SystemdFilesystemBackend:
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
            raise LiveBackendError("myuna_group_missing") from exc

    def _systemctl(self, action: str, unit: str | None = None) -> None:
        _require(
            action
            in {
                "start",
                "stop",
                "restart",
                "daemon-reload",
            },
            "systemctl_action_rejected",
        )
        if action == "daemon-reload":
            _require(unit is None, "systemctl_unit_rejected")
            arguments = ["/usr/bin/systemctl", "daemon-reload"]
        else:
            _require(unit in _ALLOWED_UNITS, "systemctl_unit_rejected")
            arguments = ["/usr/bin/systemctl", action, unit]
        self.runner.run(arguments, timeout_seconds=self.wait_timeout_seconds)

    def _show(self, unit: str, properties: Sequence[str]) -> dict[str, str]:
        _require(unit in _ALLOWED_UNITS, "systemd_unit_rejected")
        result = self.runner.run(
            [
                "/usr/bin/systemctl",
                "show",
                unit,
                *[f"--property={name}" for name in properties],
            ],
            timeout_seconds=15,
        )
        output: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" not in line:
                continue
            name, value = line.split("=", 1)
            output[name] = value
        _require(set(output) == set(properties), "systemd_show_rejected")
        return output

    def _is_active(self, unit: str) -> bool:
        state = self._show(unit, ("ActiveState", "SubState"))
        return _running_state(state)

    def _is_gateway_socket_ready(self) -> bool:
        state = self._show(
            GATEWAY_SOCKET_UNIT,
            ("ActiveState", "SubState"),
        )
        return _gateway_socket_ready_state(state)

    def _wait_active(self, unit: str, expected: bool) -> None:
        deadline = time.monotonic() + self.wait_timeout_seconds
        while time.monotonic() < deadline:
            if self._is_active(unit) is expected:
                return
            time.sleep(0.1)
        raise LiveBackendError("unit_state_timeout")

    def _wait_gateway_socket_ready(self, expected: bool) -> None:
        deadline = time.monotonic() + self.wait_timeout_seconds
        while time.monotonic() < deadline:
            if self._is_gateway_socket_ready() is expected:
                return
            time.sleep(0.1)
        raise LiveBackendError("gateway_socket_state_timeout")

    def _unit_fragment_and_dropins(
        self,
        unit: str,
    ) -> tuple[str, dict[str, str]]:
        state = self._show(unit, ("FragmentPath", "DropInPaths"))
        fragment = Path(state["FragmentPath"])
        fragment_hash = _sha256_file(fragment)
        dropins: dict[str, str] = {}
        for raw_path in state["DropInPaths"].split():
            path = Path(raw_path)
            name = path.name
            _require(
                name not in dropins and path.parent.is_dir(),
                "systemd_dropin_inventory_rejected",
            )
            dropins[name] = _sha256_file(path)
        return fragment_hash, dict(sorted(dropins.items()))

    def _core_dropin_hashes(self) -> dict[str, str]:
        _require(
            CORE_DROPIN_ROOT.is_dir() and not CORE_DROPIN_ROOT.is_symlink(),
            "core_dropin_root_rejected",
        )
        hashes: dict[str, str] = {}
        for path in sorted(CORE_DROPIN_ROOT.iterdir()):
            _require(
                path.is_file() and not path.is_symlink(),
                "core_dropin_entry_rejected",
            )
            hashes[path.name] = _sha256_file(path)
        return hashes

    def _need_daemon_reload(self, unit: str) -> bool:
        return self._show(unit, ("NeedDaemonReload",))["NeedDaemonReload"] != "no"

    def _restart_count(self, unit: str) -> int:
        value = self._show(unit, ("NRestarts",))["NRestarts"]
        _require(value.isdigit(), "restart_count_rejected")
        return int(value)

    def _working_directory(self, unit: str) -> str:
        return self._show(unit, ("WorkingDirectory",))["WorkingDirectory"]

    def _verify_gateway_contract(
        self,
        bundle: TransactionBundle,
        *,
        require_active: bool,
    ) -> None:
        gateway = bundle.plan["gateway"]
        socket = gateway["socket"]
        service_fragment, service_dropins = self._unit_fragment_and_dropins(
            GATEWAY_SERVICE_UNIT
        )
        socket_fragment, socket_dropins = self._unit_fragment_and_dropins(
            GATEWAY_SOCKET_UNIT
        )
        socket_state = self._show(
            GATEWAY_SOCKET_UNIT,
            ("UnitFileState", "Listen", "Triggers"),
        )
        service_state = self._show(
            GATEWAY_SERVICE_UNIT,
            ("TriggeredBy",),
        )
        listen = socket_state["Listen"].removesuffix(" (Stream)")
        _require(
            service_fragment == gateway["fragment_sha256"]
            and service_dropins == gateway["dropin_sha256"]
            and socket_fragment == socket["fragment_sha256"]
            and socket_dropins == socket["dropin_sha256"]
            and socket_state["UnitFileState"] == socket["unit_file_state"]
            and listen == socket["listen_stream"]
            and socket_state["Triggers"] == GATEWAY_SERVICE_UNIT
            and service_state["TriggeredBy"] == GATEWAY_SOCKET_UNIT,
            "gateway_contract_drift",
        )
        if require_active:
            _require(
                self._is_active(GATEWAY_SOCKET_UNIT)
                and self._is_active(GATEWAY_SERVICE_UNIT),
                "gateway_not_active",
            )

    def verify_exact_prestate(self, bundle: TransactionBundle) -> RuntimeSnapshot:
        plan = bundle.plan
        prestate = plan["prestate"]
        core_fragment, _ = self._unit_fragment_and_dropins(CORE_UNIT)
        _require(
            core_fragment == prestate["base_template_sha256"]
            and self._core_dropin_hashes() == prestate["dropin_sha256"]
            and not RUNTIME_BINDING_PATH.exists()
            and not self._need_daemon_reload(CORE_UNIT)
            and self._is_active(CORE_UNIT),
            "core_prestate_drift",
        )
        self._verify_gateway_contract(bundle, require_active=True)
        return RuntimeSnapshot.create(
            core_restart_count=self._restart_count(CORE_UNIT),
            core_active=True,
            gateway_socket_active=True,
            gateway_service_active=True,
        )

    def stop_gateway_socket(self, bundle: TransactionBundle) -> None:
        self._systemctl("stop", GATEWAY_SOCKET_UNIT)

    def verify_gateway_socket_inactive(self, bundle: TransactionBundle) -> None:
        self._wait_gateway_socket_ready(False)

    def stop_gateway_service(self, bundle: TransactionBundle) -> None:
        self._systemctl("stop", GATEWAY_SERVICE_UNIT)

    def verify_gateway_service_inactive(self, bundle: TransactionBundle) -> None:
        self._wait_active(GATEWAY_SERVICE_UNIT, False)

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
        _require(
            destination.is_absolute()
            and parent.is_dir()
            and not parent.is_symlink()
            and (not destination.exists() or not destination.is_symlink()),
            "atomic_destination_rejected",
        )
        temporary = parent / f".{destination.name}.{os.getpid()}.r4c.tmp"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, mode)
        try:
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise LiveBackendError("atomic_write_failed")
                    view = view[written:]
                os.fchmod(descriptor, mode)
                os.fchown(descriptor, uid, gid)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, destination)
        except Exception:
            if temporary.exists() and not temporary.is_symlink():
                temporary.unlink()
            raise
        _fsync_directory(parent)
        _require(
            _sha256_file(destination) == sha256(payload).hexdigest(),
            "atomic_write_verification_failed",
        )

    def apply_core_files(self, bundle: TransactionBundle) -> None:
        plan = bundle.plan
        prestate = plan["prestate"]
        target = plan["target"]
        _require(
            self._core_dropin_hashes() == prestate["dropin_sha256"]
            and not RUNTIME_BINDING_PATH.exists(),
            "core_apply_prestate_drift",
        )
        final = bundle.final_dropins
        _require(
            {name: sha256(payload).hexdigest() for name, payload in final.items()}
            == target["final_dropin_sha256"],
            "final_dropin_payload_rejected",
        )
        self._atomic_replace(
            RUNTIME_BINDING_PATH,
            bundle.runtime_binding,
            mode=0o640,
            uid=0,
            gid=self.myuna_gid,
        )
        for name in sorted(target["write_dropin_sha256"]):
            _require(name in final, "write_dropin_missing")
            self._atomic_replace(
                CORE_DROPIN_ROOT / name,
                final[name],
                mode=0o644,
                uid=0,
                gid=0,
            )
        for name in target["delete_dropins"]:
            path = CORE_DROPIN_ROOT / name
            _require(
                _sha256_file(path) == prestate["dropin_sha256"][name],
                "delete_dropin_precondition_rejected",
            )
            path.unlink()
            _fsync_directory(CORE_DROPIN_ROOT)
        _require(
            self._core_dropin_hashes() == target["final_dropin_sha256"]
            and _sha256_file(RUNTIME_BINDING_PATH)
            == sha256(bundle.runtime_binding).hexdigest(),
            "core_apply_postcondition_rejected",
        )

    def daemon_reload(self, bundle: TransactionBundle) -> None:
        self._systemctl("daemon-reload")

    def restart_core(self, bundle: TransactionBundle) -> None:
        self._systemctl("restart", CORE_UNIT)
        self._wait_active(CORE_UNIT, True)

    def verify_target_core(
        self,
        bundle: TransactionBundle,
        snapshot: RuntimeSnapshot,
        *,
        enforce_restart_budget: bool = True,
    ) -> None:
        target = bundle.plan["target"]
        restart_count = self._restart_count(CORE_UNIT)
        _require(
            self._is_active(CORE_UNIT)
            and not self._need_daemon_reload(CORE_UNIT)
            and self._working_directory(CORE_UNIT) == target["release_path"]
            and (
                not enforce_restart_budget
                or snapshot.core_restart_count
                <= restart_count
                <= snapshot.core_restart_count + 1
            )
            and self._core_dropin_hashes() == target["final_dropin_sha256"]
            and _sha256_file(RUNTIME_BINDING_PATH)
            == sha256(bundle.runtime_binding).hexdigest(),
            "target_core_postcondition_rejected",
        )
        binding = parse_json_document(bundle.runtime_binding)
        verifier = Path(binding["verifier_script_path"])
        pythonpath = f"{target['release_path']}/src"
        self.runner.run(
            [
                "/usr/sbin/runuser",
                "-u",
                "myuna",
                "--",
                "/usr/bin/env",
                f"PYTHONPATH={pythonpath}",
                "/usr/bin/python3",
                verifier.as_posix(),
                "verify-active",
            ],
            cwd=Path(target["release_path"]),
            timeout_seconds=60,
        )

    def start_gateway_socket(self, bundle: TransactionBundle) -> None:
        self._systemctl("start", GATEWAY_SOCKET_UNIT)

    def verify_gateway_socket_active(self, bundle: TransactionBundle) -> None:
        self._wait_gateway_socket_ready(True)
        self._verify_gateway_contract(bundle, require_active=False)

    def start_gateway_service(self, bundle: TransactionBundle) -> None:
        _require(
            self._is_gateway_socket_ready(),
            "gateway_socket_must_precede_service",
        )
        self._systemctl("start", GATEWAY_SERVICE_UNIT)

    def verify_gateway_service_active(self, bundle: TransactionBundle) -> None:
        self._wait_active(GATEWAY_SERVICE_UNIT, True)
        self._verify_gateway_contract(bundle, require_active=True)

    def restore_core_files(self, bundle: TransactionBundle) -> None:
        rollback = bundle.rollback_dropins
        final = bundle.final_dropins
        current = self._core_dropin_hashes()
        _require(
            set(current) <= set(rollback) | set(final),
            "rollback_unrecognized_dropin_rejected",
        )
        for name, payload in sorted(rollback.items()):
            self._atomic_replace(
                CORE_DROPIN_ROOT / name,
                payload,
                mode=0o644,
                uid=0,
                gid=0,
            )
        for name in sorted(set(final) - set(rollback)):
            path = CORE_DROPIN_ROOT / name
            if path.exists():
                _require(not path.is_symlink(), "rollback_dropin_rejected")
                path.unlink()
                _fsync_directory(CORE_DROPIN_ROOT)
        if RUNTIME_BINDING_PATH.exists():
            _require(
                RUNTIME_BINDING_PATH.is_file()
                and not RUNTIME_BINDING_PATH.is_symlink(),
                "rollback_binding_rejected",
            )
            RUNTIME_BINDING_PATH.unlink()
            _fsync_directory(RUNTIME_BINDING_PATH.parent)
        _require(
            self._core_dropin_hashes() == bundle.plan["prestate"]["dropin_sha256"]
            and not RUNTIME_BINDING_PATH.exists(),
            "rollback_file_postcondition_rejected",
        )

    def verify_rollback_core(
        self,
        bundle: TransactionBundle,
        snapshot: RuntimeSnapshot,
    ) -> None:
        prestate = bundle.plan["prestate"]
        _require(
            self._is_active(CORE_UNIT)
            and not self._need_daemon_reload(CORE_UNIT)
            and self._working_directory(CORE_UNIT)
            == prestate["effective_working_directory"]
            and self._core_dropin_hashes() == prestate["dropin_sha256"]
            and not RUNTIME_BINDING_PATH.exists(),
            "rollback_core_postcondition_rejected",
        )
