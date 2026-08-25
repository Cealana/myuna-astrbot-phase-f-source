#!/usr/bin/env python3
"""Rollback-bound P08 private-service activation contract.

The activator deliberately refuses to select a Telegram runtime or plugin.  It
requires those already-selected immutable artifacts to contain the exact P08
client source bound by the P08 release.  A combined T2 coordinator must roll
back that prerequisite independently if P08 activation fails.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Callable, Mapping


PLAN_SCHEMA = "myuna.p08-active-temporal-activation-plan.v1"
SELECTOR_SCHEMA = "myuna.p08-active-temporal-selector.v1"
RELEASE_SCHEMA = "myuna.p08-active-temporal-code-release.v2"
GATEWAY_RELEASE_SCHEMA = "myuna.p07-hybrid-telegram-runtime.v2"
SAFE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

SERVICE = "myuna-active-temporal-context-v1.service"
SOCKET = "myuna-active-temporal-context-v1.socket"
CONFIG_ROOT = Path("/etc/myuna-active-temporal-context-v1")
SELECTOR_JSON = CONFIG_ROOT / "selector.json"
SELECTOR_ENV = CONFIG_ROOT / "selector.env"
UNIT_ROOT = Path("/etc/systemd/system")
STATE_ROOT = Path("/var/lib/myuna-active-temporal-context-v1")
RELEASE_ROOT = Path("/opt/myuna/active-temporal/releases")
BACKUP_ROOT = Path("/var/lib/myuna-activation-backups/p08-active-temporal-v1")
SYSTEMD_SOURCE = Path("systemd")
SERVICE_SOURCE = SYSTEMD_SOURCE / SERVICE
SOCKET_SOURCE = SYSTEMD_SOURCE / SOCKET
SYSUSERS_SOURCE = SYSTEMD_SOURCE / "myuna-active-temporal-context-v1.sysusers.conf"
TMPFILES_SOURCE = SYSTEMD_SOURCE / "myuna-active-temporal-context-v1.tmpfiles.conf"


class ActivationRejected(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ActivationRejected(code)


def digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(payload), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _load_json(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), "file_type_rejected")
        payload = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationRejected("json_rejected") from exc
    require(isinstance(payload, dict), "json_rejected")
    return payload


def _inventory(root: Path) -> list[dict[str, object]]:
    result = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.name == "manifest.json":
            continue
        relative = path.relative_to(root).as_posix()
        require("__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}, "cache_rejected")
        require(not path.is_symlink(), "symlink_rejected")
        result.append(
            {"path": relative, "size": path.stat().st_size, "sha256": digest_file(path)}
        )
    return result


def validate_release(root: Path) -> dict[str, object]:
    manifest = _load_json(root / "manifest.json")
    require(manifest.get("schema") == RELEASE_SCHEMA, "release_schema_rejected")
    require(SAFE_COMMIT.fullmatch(str(manifest.get("core_commit"))) is not None, "core_commit_rejected")
    require(SAFE_COMMIT.fullmatch(str(manifest.get("deploy_commit"))) is not None, "deploy_commit_rejected")
    require(manifest.get("files") == _inventory(root), "release_inventory_rejected")
    client = manifest.get("gateway_client")
    require(
        isinstance(client, dict)
        and set(client) == {"runtime_path", "sha256", "source_path"}
        and client.get("source_path") == "scripts/p08_temporal_gateway_v1.py"
        and client.get("runtime_path") == "runtime/p08_temporal_gateway_v1.py"
        and HEX64.fullmatch(str(client.get("sha256"))) is not None,
        "gateway_client_contract_rejected",
    )
    require(
        digest_file(root / str(client["source_path"])) == client["sha256"],
        "gateway_client_digest_rejected",
    )
    return manifest


def validate_gateway_runtime(
    root: Path,
    *,
    client_sha256: str,
    core_commit: str,
    deploy_commit: str,
) -> str:
    manifest = _load_json(root / "P07_HYBRID_MANIFEST.json")
    release_digest = manifest.get("release_digest")
    unsigned = {key: value for key, value in manifest.items() if key != "release_digest"}
    require(
        manifest.get("schema") == GATEWAY_RELEASE_SCHEMA
        and HEX64.fullmatch(str(release_digest)) is not None
        and release_digest == root.name
        and release_digest == digest_bytes(canonical(unsigned) + b"\n")
        and manifest.get("source_core_commit") == core_commit
        and manifest.get("source_deploy_commit") == deploy_commit,
        "gateway_manifest_rejected",
    )
    files = manifest.get("files")
    require(isinstance(files, dict), "gateway_manifest_rejected")
    observed: dict[str, dict[str, object]] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative == "P07_HYBRID_MANIFEST.json":
            continue
        require(not path.is_symlink(), "gateway_runtime_symlink_rejected")
        observed[relative] = {
            "sha256": digest_file(path),
            "size": path.stat().st_size,
        }
    require(files == observed, "gateway_runtime_inventory_rejected")
    client = root / "runtime/p08_temporal_gateway_v1.py"
    gateway = root / "runtime/telegram_owner_runtime_gateway.py"
    require(client.is_file() and gateway.is_file(), "gateway_runtime_missing")
    require(digest_file(client) == client_sha256, "gateway_client_mismatch")
    client_row = files.get("runtime/p08_temporal_gateway_v1.py")
    require(
        isinstance(client_row, dict) and client_row.get("sha256") == client_sha256,
        "gateway_manifest_client_mismatch",
    )
    gateway_source = gateway.read_text("utf-8")
    require("from p08_temporal_gateway_v1 import" in gateway_source, "gateway_wiring_missing")
    return digest_bytes(canonical(manifest))


def validate_plugin(root: Path) -> str:
    protocol = root / "myuna_telegram_gateway/protocol.py"
    main = root / "myuna_telegram_gateway/main.py"
    require(protocol.is_file() and main.is_file(), "plugin_inventory_rejected")
    source = protocol.read_text("utf-8")
    require("temporal_command_is_explicit" in source, "plugin_temporal_admission_missing")
    return digest_bytes(
        canonical(
            {
                "main": digest_file(main),
                "protocol": digest_file(protocol),
            }
        )
    )


def _projection(path: Path) -> dict[str, object]:
    if not path.exists() and not path.is_symlink():
        return {"state": "absent"}
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), "prestate_type_rejected")
    return {
        "state": "present",
        "sha256": digest_file(path),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


@dataclass(frozen=True, slots=True)
class ActivationPlan:
    payload: dict[str, object]

    @property
    def digest(self) -> str:
        return digest_bytes(canonical(self.payload))

    def as_payload(self) -> dict[str, object]:
        return {
            "schema": PLAN_SCHEMA,
            "plan_digest": self.digest,
            **self.payload,
        }


def prepare_plan(
    *,
    release: Path,
    gateway_runtime: Path,
    plugin: Path,
    root: Path = Path("/"),
) -> ActivationPlan:
    manifest = validate_release(release)
    client = manifest["gateway_client"]
    assert isinstance(client, dict)
    gateway_manifest_digest = validate_gateway_runtime(
        gateway_runtime,
        client_sha256=str(client["sha256"]),
        core_commit=str(manifest["core_commit"]),
        deploy_commit=str(manifest["deploy_commit"]),
    )
    plugin_digest = validate_plugin(plugin)
    release_digest = digest_bytes(canonical(manifest))
    target = RELEASE_ROOT / release_digest
    rooted = lambda absolute: absolute if root == Path("/") else root / str(absolute).lstrip("/")
    require(not rooted(STATE_ROOT).exists() and not rooted(STATE_ROOT).is_symlink(), "state_preexisting")
    payload = {
        "release_digest": release_digest,
        "release_source": str(release.resolve()),
        "release_target": str(target),
        "core_commit": manifest["core_commit"],
        "deploy_commit": manifest["deploy_commit"],
        "gateway_runtime": str(gateway_runtime.resolve()),
        "gateway_manifest_digest": gateway_manifest_digest,
        "gateway_client_sha256": client["sha256"],
        "plugin": str(plugin.resolve()),
        "plugin_digest": plugin_digest,
        "state_prestate": "absent",
        "files_prestate": {
            str(path): _projection(rooted(path))
            for path in (
                SELECTOR_JSON,
                SELECTOR_ENV,
                UNIT_ROOT / SERVICE,
                UNIT_ROOT / SOCKET,
            )
        },
    }
    require(
        all(
            projection.get("state") == "absent"
            for projection in payload["files_prestate"].values()
        ),
        "activation_prestate_not_empty",
    )
    return ActivationPlan(payload)


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chown(path, 0, 0)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


Runner = Callable[[list[str]], None]


def _run(command: list[str]) -> None:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode != 0:
        raise ActivationRejected("command_failed")


def _restore_projection(path: Path, projection: Mapping[str, object], backup: Path) -> None:
    if projection.get("state") == "absent":
        path.unlink(missing_ok=True)
        return
    source = backup / digest_bytes(str(path).encode("utf-8"))
    require(source.is_file(), "rollback_backup_missing")
    _atomic_write(path, source.read_bytes(), int(projection["mode"]))
    os.chown(path, int(projection["uid"]), int(projection["gid"]))


def _validate_state_files(root: Path, *, service_uid: int) -> None:
    require(root.is_dir() and not root.is_symlink(), "state_root_rejected")
    root_metadata = root.lstat()
    require(
        root_metadata.st_uid == service_uid
        and stat.S_IMODE(root_metadata.st_mode) == 0o700,
        "state_root_permission_rejected",
    )
    expected = {"temporal-context.sqlite3", "trusted-time.sqlite3"}
    observed = {path.name for path in root.iterdir()}
    require(observed == expected, "state_inventory_rejected")
    for name in sorted(expected):
        path = root / name
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode)
            and not path.is_symlink()
            and metadata.st_uid == service_uid
            and stat.S_IMODE(metadata.st_mode) == 0o600,
            "state_file_permission_rejected",
        )


def execute_plan(
    plan_payload: Mapping[str, object],
    *,
    runner: Runner = _run,
) -> dict[str, object]:
    require(os.geteuid() == 0, "root_required")
    raw = dict(plan_payload)
    digest = raw.pop("plan_digest", None)
    require(raw.pop("schema", None) == PLAN_SCHEMA, "plan_schema_rejected")
    require(digest == digest_bytes(canonical(raw)), "plan_digest_rejected")
    release = Path(str(raw["release_source"]))
    gateway = Path(str(raw["gateway_runtime"]))
    plugin = Path(str(raw["plugin"]))
    fresh = prepare_plan(release=release, gateway_runtime=gateway, plugin=plugin)
    require(fresh.digest == digest, "plan_drifted")
    backup = BACKUP_ROOT / str(digest)
    require(not backup.exists() and not backup.is_symlink(), "backup_preexisting")
    backup.mkdir(parents=True, mode=0o700)
    os.chown(backup, 0, 0)
    prestate = raw["files_prestate"]
    assert isinstance(prestate, dict)
    for text, projection in prestate.items():
        path = Path(text)
        assert isinstance(projection, dict)
        if projection.get("state") == "present":
            (backup / digest_bytes(text.encode("utf-8"))).write_bytes(path.read_bytes())
    target = Path(str(raw["release_target"]))
    state_created = False
    try:
        require(not target.exists() and not target.is_symlink(), "target_release_preexisting")
        shutil.copytree(release, target, symlinks=False)
        for path in [target, *target.rglob("*")]:
            require(not path.is_symlink(), "installed_symlink_rejected")
            os.chown(path, 0, 0)
            os.chmod(path, 0o555 if path.is_dir() else 0o444)
        sysusers = target / SYSUSERS_SOURCE
        tmpfiles = target / TMPFILES_SOURCE
        runner(["/usr/bin/systemd-sysusers", str(sysusers)])
        runner(["/usr/bin/systemd-tmpfiles", "--create", str(tmpfiles)])
        service_uid = pwd.getpwnam("myuna_active_temporal").pw_uid
        telegram_uid = pwd.getpwnam("myuna-gateway-telegram").pw_uid
        selector = {
            "schema": SELECTOR_SCHEMA,
            "plan_digest": digest,
            "release_digest": raw["release_digest"],
            "release_path": str(target),
            "core_commit": raw["core_commit"],
            "deploy_commit": raw["deploy_commit"],
            "gateway_manifest_digest": raw["gateway_manifest_digest"],
            "gateway_client_sha256": raw["gateway_client_sha256"],
            "plugin_digest": raw["plugin_digest"],
        }
        _atomic_write(SELECTOR_JSON, canonical(selector) + b"\n", 0o600)
        environment = (
            f"PYTHONPATH={target / 'src'}\n"
            f"MYUNA_P08_STATE_ROOT={STATE_ROOT}\n"
            f"MYUNA_P08_SERVICE_UID={service_uid}\n"
            f"MYUNA_P08_TELEGRAM_UID={telegram_uid}\n"
        ).encode("ascii")
        _atomic_write(SELECTOR_ENV, environment, 0o600)
        _atomic_write(UNIT_ROOT / SERVICE, (target / SERVICE_SOURCE).read_bytes(), 0o644)
        _atomic_write(UNIT_ROOT / SOCKET, (target / SOCKET_SOURCE).read_bytes(), 0o644)
        require(STATE_ROOT.is_dir() and not STATE_ROOT.is_symlink(), "state_root_rejected")
        state_created = True
        runner(
            [
                "/usr/sbin/runuser",
                "-u",
                "myuna_active_temporal",
                "--",
                "/usr/bin/env",
                f"PYTHONPATH={target / 'src'}",
                "PYTHONDONTWRITEBYTECODE=1",
                f"MYUNA_P08_STATE_ROOT={STATE_ROOT}",
                f"MYUNA_P08_SERVICE_UID={service_uid}",
                "/usr/bin/python3",
                "-B",
                "-c",
                (
                    "from pathlib import Path;"
                    "from myuna_core.active_temporal_context.service import initialize_state;"
                    f"initialize_state(Path('{STATE_ROOT}'), expected_uid={service_uid})"
                ),
            ]
        )
        runner(["/usr/bin/systemctl", "daemon-reload"])
        runner(["/usr/bin/systemctl", "enable", "--now", SOCKET])
        runner(["/usr/bin/systemctl", "start", SERVICE])
        runner(["/usr/bin/systemctl", "is-active", "--quiet", SOCKET])
        runner(["/usr/bin/systemctl", "is-active", "--quiet", SERVICE])
        _validate_state_files(STATE_ROOT, service_uid=service_uid)
        runner(
            [
                "/usr/sbin/runuser",
                "-u",
                "myuna_active_temporal",
                "--",
                "/usr/bin/env",
                f"PYTHONPATH={target / 'src'}",
                "PYTHONDONTWRITEBYTECODE=1",
                f"MYUNA_P08_STATE_ROOT={STATE_ROOT}",
                f"MYUNA_P08_SERVICE_UID={service_uid}",
                "/usr/bin/python3",
                "-B",
                "-c",
                (
                    "from myuna_core.active_temporal_context.service import "
                    "build_runtime_from_environment;"
                    "build_runtime_from_environment()"
                ),
            ]
        )
        return {
            "schema": "myuna.p08-active-temporal-activation-receipt.v1",
            "status": "activated",
            "plan_digest": digest,
            "release_digest": raw["release_digest"],
            "model_called": False,
            "channel_called": False,
            "profile_written": False,
            "session_written": False,
            "qq_changed": False,
            "service_active": True,
            "socket_active": True,
            "state_database_count": 2,
        }
    except BaseException:
        try:
            runner(["/usr/bin/systemctl", "stop", SERVICE])
            runner(["/usr/bin/systemctl", "disable", "--now", SOCKET])
            for text, projection in prestate.items():
                assert isinstance(projection, dict)
                _restore_projection(Path(text), projection, backup)
            if state_created and STATE_ROOT.exists():
                preserved = backup / "state-preserved"
                require(not preserved.exists(), "rollback_state_backup_preexisting")
                os.replace(STATE_ROOT, preserved)
                os.chown(preserved, 0, 0)
                os.chmod(preserved, 0o700)
            runner(["/usr/bin/systemctl", "daemon-reload"])
        except BaseException as rollback_error:
            raise ActivationRejected("rollback_failed") from rollback_error
        raise


def rollback_activated_plan(
    plan_payload: Mapping[str, object],
    *,
    runner: Runner = _run,
) -> dict[str, object]:
    """Restore the exact absent P08 prestate after a combined-phase failure.

    The installed immutable release and rollback evidence are preserved.  State
    is moved intact into the plan-addressed backup and is never deleted.
    """

    require(os.geteuid() == 0, "root_required")
    raw = dict(plan_payload)
    plan_digest = raw.pop("plan_digest", None)
    require(raw.pop("schema", None) == PLAN_SCHEMA, "plan_schema_rejected")
    require(plan_digest == digest_bytes(canonical(raw)), "plan_digest_rejected")
    backup = BACKUP_ROOT / str(plan_digest)
    require(backup.is_dir() and not backup.is_symlink(), "rollback_backup_missing")
    prestate = raw.get("files_prestate")
    require(isinstance(prestate, dict), "rollback_prestate_rejected")
    runner(["/usr/bin/systemctl", "stop", SERVICE])
    runner(["/usr/bin/systemctl", "disable", "--now", SOCKET])
    for text, projection in prestate.items():
        require(isinstance(text, str) and isinstance(projection, dict), "rollback_prestate_rejected")
        _restore_projection(Path(text), projection, backup)
    if STATE_ROOT.exists() or STATE_ROOT.is_symlink():
        require(STATE_ROOT.is_dir() and not STATE_ROOT.is_symlink(), "rollback_state_rejected")
        preserved = backup / "state-preserved-after-combined-rollback"
        require(not preserved.exists() and not preserved.is_symlink(), "rollback_state_backup_preexisting")
        os.replace(STATE_ROOT, preserved)
        os.chown(preserved, 0, 0)
        os.chmod(preserved, 0o700)
    runner(["/usr/bin/systemctl", "daemon-reload"])
    require(not STATE_ROOT.exists() and not STATE_ROOT.is_symlink(), "rollback_state_still_selected")
    for text, projection in prestate.items():
        path = Path(text)
        assert isinstance(projection, dict)
        require(_projection(path) == projection, "rollback_projection_rejected")
    return {
        "schema": "myuna.p08-active-temporal-rollback-receipt.v1",
        "status": "rolled_back",
        "plan_digest": plan_digest,
        "state_preserved": True,
        "model_called": False,
        "channel_called": False,
        "profile_written": False,
        "session_written": False,
        "qq_changed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--release", type=Path, required=True)
    preflight.add_argument("--gateway-runtime", type=Path, required=True)
    preflight.add_argument("--plugin", type=Path, required=True)
    activate = sub.add_parser("activate")
    activate.add_argument("--plan", type=Path, required=True)
    values = parser.parse_args()
    if values.command == "preflight":
        plan = prepare_plan(
            release=values.release.resolve(),
            gateway_runtime=values.gateway_runtime.resolve(),
            plugin=values.plugin.resolve(),
        )
        print(json.dumps(plan.as_payload(), separators=(",", ":"), sort_keys=True))
        return 0
    payload = _load_json(values.plan.resolve())
    receipt = execute_plan(payload)
    print(json.dumps(receipt, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
