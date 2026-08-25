"""Sandbox-only filesystem/systemd-shaped backend for selected Core upgrades.

The sandbox root must not be `/`. Lifecycle effects are delegated to injected
protocols; this module contains no subprocess or live systemd implementation.
"""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
from typing import Mapping, Protocol

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


class SandboxBackendError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise SandboxBackendError(code)


def digest_path(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


class LifecycleRunner(Protocol):
    def state(self, unit: str) -> tuple[str, str]: ...

    def start(self, unit: str) -> None: ...

    def stop(self, unit: str) -> None: ...

    def daemon_reload(self) -> None: ...


class ReleaseVerifier(Protocol):
    def verify(self, release_root: Path, expected: Mapping[str, object]) -> None: ...


class FakeLifecycleRunner:
    def __init__(self, states: Mapping[str, tuple[str, str]]) -> None:
        self.states = dict(states)
        self.events: list[str] = []
        self.daemon_reload_count = 0

    def state(self, unit: str) -> tuple[str, str]:
        self.events.append("state:" + unit)
        return self.states[unit]

    def start(self, unit: str) -> None:
        self.events.append("start:" + unit)
        if unit.endswith(".socket"):
            self.states[unit] = ("active", "listening")
        else:
            self.states[unit] = ("active", "running")

    def stop(self, unit: str) -> None:
        self.events.append("stop:" + unit)
        self.states[unit] = ("inactive", "dead")

    def daemon_reload(self) -> None:
        self.events.append("daemon_reload")
        self.daemon_reload_count += 1


class FakeReleaseVerifier:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, dict[str, object]]] = []

    def verify(self, release_root: Path, expected: Mapping[str, object]) -> None:
        require(release_root.is_dir(), "sandbox_release_missing")
        marker = release_root / "TREE_SHA256"
        require(
            marker.read_text(encoding="utf-8").strip() == expected["tree_sha256"],
            "sandbox_release_digest_rejected",
        )
        self.calls.append((release_root, dict(expected)))


class SandboxFilesystemBackend:
    def __init__(
        self,
        *,
        root: Path,
        runner: LifecycleRunner,
        verifier: ReleaseVerifier,
    ) -> None:
        require(root.is_absolute(), "sandbox_root_must_be_absolute")
        require(not root.is_symlink(), "sandbox_root_symlink_rejected")
        resolved = root.resolve()
        require(resolved != Path("/"), "live_root_forbidden_in_r2c")
        require(resolved.is_dir(), "sandbox_root_rejected")
        self.root = resolved
        self.runner = runner
        self.verifier = verifier
        self._snapshot: RuntimeSnapshot | None = None
        self._prestate_service_states: dict[str, tuple[str, str]] = {}

    def _path(self, absolute: str) -> Path:
        require(
            absolute.startswith("/") and ".." not in Path(absolute).parts,
            "sandbox_path_rejected",
        )
        path = self.root / absolute.lstrip("/")
        require(path.resolve().is_relative_to(self.root), "sandbox_path_escape_rejected")
        return path

    @property
    def binding(self) -> Path:
        return self._path("/etc/myuna/core-release-selector/qq.binding.json")

    @property
    def selector(self) -> Path:
        return self._path(
            "/etc/systemd/system/myuna-core@qq.service.d/" + SELECTOR_DROPIN
        )

    @property
    def credential(self) -> Path:
        return self._path(
            "/etc/systemd/system/myuna-core@qq.service.d/"
            + TELEGRAM_CREDENTIAL_DROPIN
        )

    @property
    def environment(self) -> Path:
        return self._path("/etc/myuna/qq.env")

    def _require_regular(self, path: Path, expected_sha256: str) -> None:
        require(path.is_file() and not path.is_symlink(), "sandbox_file_rejected")
        require(digest_path(path) == expected_sha256, "sandbox_file_digest_rejected")

    def _atomic_replace(self, path: Path, payload: bytes, mode: int) -> None:
        require(
            path.parent.is_dir() and not path.parent.is_symlink(),
            "sandbox_parent_rejected",
        )
        temporary = path.parent / ("." + path.name + ".selected-upgrade.tmp")
        require(not temporary.exists(), "sandbox_temporary_preexists")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                require(written > 0, "sandbox_write_failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        path.chmod(mode)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def verify_exact_prestate(self, bundle: UpgradeBundle) -> RuntimeSnapshot:
        plan = bundle.plan
        prestate = plan["prestate"]
        self._require_regular(self.binding, prestate["binding_sha256"])
        self._require_regular(
            self.selector,
            prestate["dropin_sha256"][SELECTOR_DROPIN],
        )
        self._require_regular(self.environment, prestate["qq_env_sha256"])
        require(not self.credential.exists(), "sandbox_credential_preexists")
        states = {
            unit: self.runner.state(unit)
            for unit in (CORE_UNIT, GATEWAY_SOCKET, GATEWAY_SERVICE)
        }
        for unit, actual in states.items():
            expected = prestate["service_states"][unit]
            require(
                actual == (expected["active_state"], expected["sub_state"]),
                "sandbox_service_prestate_rejected",
            )
        target = plan["target"]["selected_release"]
        release_root = self._path(
            "/srv/myuna/releases/core/" + target["tree_sha256"]
        )
        self.verifier.verify(release_root, target)
        self._prestate_service_states = states
        snapshot = RuntimeSnapshot.create(
            core_active=states[CORE_UNIT][0] == "active",
            gateway_socket_active=states[GATEWAY_SOCKET][0] == "active",
            gateway_service_active=states[GATEWAY_SERVICE][0] == "active",
            binding_sha256=prestate["binding_sha256"],
        )
        self._snapshot = snapshot
        return snapshot

    def quiesce_gateway(self, bundle: UpgradeBundle) -> None:
        if self.runner.state(GATEWAY_SOCKET)[0] == "active":
            self.runner.stop(GATEWAY_SOCKET)
        if self.runner.state(GATEWAY_SERVICE)[0] == "active":
            self.runner.stop(GATEWAY_SERVICE)
        require(
            self.runner.state(GATEWAY_SOCKET)[0] == "inactive",
            "sandbox_gateway_socket_not_stopped",
        )
        require(
            self.runner.state(GATEWAY_SERVICE)[0] == "inactive",
            "sandbox_gateway_service_not_stopped",
        )
        if self.runner.state(CORE_UNIT)[0] == "active":
            self.runner.stop(CORE_UNIT)

    def apply_files(self, bundle: UpgradeBundle) -> None:
        self._atomic_replace(self.binding, bundle.payloads[TARGET_BINDING_PATH], 0o640)
        self._atomic_replace(self.selector, bundle.payloads[TARGET_SELECTOR_PATH], 0o644)
        self._atomic_replace(self.environment, bundle.payloads[TARGET_ENV_PATH], 0o640)
        self._atomic_replace(
            self.credential,
            bundle.payloads[TARGET_CREDENTIAL_PATH],
            0o644,
        )

    def daemon_reload(self, bundle: UpgradeBundle) -> None:
        self.runner.daemon_reload()

    def start_core(self, bundle: UpgradeBundle) -> None:
        self.runner.start(CORE_UNIT)

    def verify_target(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None:
        target = bundle.plan["target"]
        self._require_regular(
            self.binding,
            sha256(bundle.payloads[TARGET_BINDING_PATH]).hexdigest(),
        )
        self._require_regular(self.selector, target["selector_dropin_sha256"])
        self._require_regular(self.environment, target["qq_env_sha256"])
        self._require_regular(
            self.credential,
            target["telegram_credential_dropin_sha256"],
        )
        require(
            self.runner.state(CORE_UNIT) == ("active", "running"),
            "sandbox_target_core_not_active",
        )
        release = target["selected_release"]
        self.verifier.verify(
            self._path("/srv/myuna/releases/core/" + release["tree_sha256"]),
            release,
        )

    def restore_gateway(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None:
        if snapshot.gateway_socket_active:
            self.runner.start(GATEWAY_SOCKET)
        if snapshot.gateway_service_active:
            self.runner.start(GATEWAY_SERVICE)

    def restore_files(self, bundle: UpgradeBundle) -> None:
        self._atomic_replace(
            self.binding,
            bundle.payloads[ROLLBACK_BINDING_PATH],
            0o640,
        )
        self._atomic_replace(
            self.selector,
            bundle.payloads[ROLLBACK_SELECTOR_PATH],
            0o644,
        )
        self._atomic_replace(
            self.environment,
            bundle.payloads[ROLLBACK_ENV_PATH],
            0o640,
        )
        if self.credential.exists():
            require(
                self.credential.is_file() and not self.credential.is_symlink(),
                "sandbox_credential_rejected",
            )
            self.credential.unlink()

    def restore_prestate(self, bundle: UpgradeBundle, snapshot: RuntimeSnapshot) -> None:
        if self.runner.state(CORE_UNIT)[0] == "active":
            self.runner.stop(CORE_UNIT)
        if snapshot.core_active:
            self.runner.start(CORE_UNIT)
        self.restore_gateway(bundle, snapshot)
