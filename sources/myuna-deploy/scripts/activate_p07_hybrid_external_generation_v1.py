#!/usr/bin/env python3
"""One-attempt, exact-prestate P07 hybrid activation with automatic rollback."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import grp
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
import time

from core_release_selector import (
    ReleaseEvidence,
    SelectionCandidate,
    build_binding_intent,
    canonical_json_bytes,
    compute_tree_digest,
    load_runtime_binding,
    parse_json_document,
    render_runtime_binding,
    render_selector_dropin,
    validate_immutable_release_tree,
)
from p07_credential_binding import (
    CredentialBindingRejected,
    canonical_hybrid_gate,
    verify_strict_binding,
)
from p07_d_generation13_release_set import phase_f_selected_target
from p09_v7_phase1_packaging_contract import (
    SUPPORTED_RUNTIME_PROFILES as V7_RUNTIME_PROFILES,
    V7PackagingContractRejected,
    projection_modules_for as v7_projection_modules_for,
    validate_runtime_contract as validate_v7_runtime_contract,
)


SCHEMA = "myuna.p07-hybrid-external-activation.v1"
CORE_SERVICE = "myuna-core@qq.service"
QQ_SOCKET = "myuna-qq-owner-runtime-dev.socket"
QQ_SERVICE = "myuna-qq-owner-runtime-dev.service"
TELEGRAM_SOCKET = "myuna-telegram-owner-runtime-dev.socket"
TELEGRAM_SERVICE = "myuna-telegram-owner-runtime-dev.service"
PROFILE_SERVICE = "myuna-owner-profile-read-v1.service"
CONTAINER = "myuna-astrbot-telegram-dev"
CORE_RELEASE_ROOT = Path("/srv/myuna/releases/core")
RUNTIME_ROOT = Path("/opt/myuna/context24-gateway/telegram/releases")
PLUGIN_ROOT = Path("/opt/myuna/telegram-gateway/releases")
CORE_BINDING = Path("/etc/myuna/core-release-selector/qq.binding.json")
CORE_SELECTOR = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf"
)
CORE_GATE = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/"
    "zzzzzzzzz-p07-hybrid-external-v1.conf"
)
CORE_CREDENTIAL_SOURCE = Path("/etc/myuna/secrets/deepseek-api-key")
TELEGRAM_CONFIG = Path("/etc/myuna-telegram-gateway/r5-resume-v1.json")
TELEGRAM_DROPIN = Path(
    "/etc/systemd/system/myuna-telegram-owner-runtime-dev.service.d/"
    "zzzzzzzzzzz-p07-hybrid-external-v1.conf"
)
EPOCH_DATABASE = Path(
    "/var/lib/myuna-telegram-gateway/external-context-v1/epoch.db"
)
VERIFIER_SHA256 = "3fab13b7b533c3e93bf5759256ff5153d7bb17aea0fc8307f560e82985a7fcaf"
VERIFIER_PATH = (
    Path("/opt/myuna/core-release-selector/releases")
    / VERIFIER_SHA256
    / "core_release_selector.py"
)
RESUME_CONTROLLER = Path(
    "/opt/myuna/telegram-r5/releases/"
    "06d06baf23e6f97cbfa37e8e6bde12a2fa1d495e7bc0b736239655c05ac57b53/"
    "telegram_r5_boot_resume.py"
)
BACKUP_ROOT = Path("/var/backups/myuna/p07-hybrid-external-v1")
STATE_ROOT = Path("/var/lib/myuna-telegram-gateway/p07-hybrid-external-v1")
RUNTIME_SCHEMA = "myuna.p07-hybrid-telegram-runtime.v2"
PLUGIN_SCHEMA = "myuna.telegram-gateway-release.v1"
BUILD_SCHEMA = "myuna.p07-hybrid-live-build.v1"
P07_RUNTIME_PROFILES = frozenset({"p07-owner-private-memory-v1"})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
TELEGRAM_RUNTIME_USER = "myuna-gateway-telegram"
_IMPORT_CLOSURE_ALGORITHM = "python-ast-local-import-closure-v1"
_FAILURE_GATE_SCHEMA = "myuna.p07-hybrid-startup-failure-gate.v1"
_PHASE_F_CORE_COMMIT = "0d6885192307a75f6948e0085c3ca2c3c9f66676"
_PHASE_F_DEPLOY_COMMIT = "7ff8f35a3e141674d7111a45dd247069d09d445a"


class ActivationRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def failure_gate_code(error: BaseException) -> str:
    code = error.code if isinstance(error, ActivationRejected) else ""
    if code in {
        "runtime_import_closure_rejected",
        "runtime_import_inventory_rejected",
        "runtime_startup_import_rejected",
    }:
        return "import_closure"
    if code in {
        "runtime_candidate_mode_rejected",
        "runtime_candidate_type_rejected",
        "runtime_candidate_symlink_rejected",
        "runtime_startup_permission_rejected",
        "runtime_startup_bytecode_rejected",
    } or (
        isinstance(error, OSError)
        and error.errno in {errno.EACCES, errno.EROFS, errno.EPERM}
    ):
        return "permission_read_only_bytecode"
    if code in {
        "credential_category_rejected",
        "credential_dropin_rejected",
        "credential_binding_permissions_rejected",
        "effective_credential_rejected",
    } or code.startswith("credential_"):
        return "credential_category"
    return "other_startup"


def failure_projection(error: BaseException) -> dict[str, str]:
    return {
        "schema": _FAILURE_GATE_SCHEMA,
        "failure_gate": failure_gate_code(error),
    }


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ActivationRejected(code)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii") + b"\n"


def digest_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def digest_file(path: Path) -> str:
    try:
        return digest_bytes(path.read_bytes())
    except OSError as exc:
        raise ActivationRejected("file_unavailable") from exc


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationRejected("json_document_rejected") from exc
    if not isinstance(value, dict):
        raise ActivationRejected("json_document_rejected")
    return value


def run(arguments: list[str], *, check: bool = True, timeout: int = 240) -> str:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ActivationRejected("fixed_command_unavailable") from exc
    if check and completed.returncode != 0:
        raise ActivationRejected("fixed_command_failed")
    return completed.stdout.strip()


def systemctl(*arguments: str) -> str:
    return run(["/usr/bin/systemctl", *arguments])


def show(unit: str, property_name: str) -> str:
    return systemctl("show", unit, "-p", property_name, "--value")


def active(unit: str) -> bool:
    return subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", unit],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def atomic_write(path: Path, payload: bytes, *, mode: int, gid: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def optional_bytes(path: Path) -> bytes | None:
    if not path.exists() and not path.is_symlink():
        return None
    require(not path.is_symlink() and path.is_file(), "prestate_path_rejected")
    return path.read_bytes()


def restore_optional(path: Path, payload: bytes | None, *, mode: int, gid: int = 0) -> None:
    if payload is None:
        if path.exists() and not path.is_symlink():
            path.unlink()
        return
    atomic_write(path, payload, mode=mode, gid=gid)


def core_evidence(candidate: Path) -> tuple[ReleaseEvidence, bytes, bytes]:
    digest = candidate.name
    require(_DIGEST.fullmatch(digest) is not None, "core_candidate_name_rejected")
    evidence_path = candidate.parent / f"{digest}.evidence.json"
    artifact_path = candidate.parent / f"{digest}.artifact.json"
    receipt_path = candidate.parent / f"{digest}.receipt.json"
    evidence = read_json(evidence_path)
    artifact = artifact_path.read_bytes()
    receipt = receipt_path.read_bytes()
    require(evidence.get("schema") == BUILD_SCHEMA, "core_evidence_schema_rejected")
    require(evidence.get("kind") == "core", "core_evidence_kind_rejected")
    require(evidence.get("tree_sha256") == digest, "core_evidence_digest_rejected")
    require(
        evidence.get("artifact_manifest_sha256") == digest_bytes(artifact),
        "core_artifact_digest_rejected",
    )
    require(
        evidence.get("installation_receipt_sha256") == digest_bytes(receipt),
        "core_receipt_digest_rejected",
    )
    selected = ReleaseEvidence(
        tree_sha256=digest,
        source_commit=str(evidence.get("source_commit")),
        file_count=int(evidence.get("file_count", 0)),
        artifact_manifest_sha256=digest_bytes(artifact),
        installation_receipt_sha256=digest_bytes(receipt),
    )
    require(
        compute_tree_digest(candidate) == (selected.tree_sha256, selected.file_count),
        "core_candidate_tree_rejected",
    )
    return selected, artifact, receipt


def validate_runtime(candidate: Path, core_commit: str, deploy_commit: str) -> str:
    require(not candidate.is_symlink() and candidate.is_dir(), "runtime_candidate_type_rejected")
    manifest = read_json(candidate / "P07_HYBRID_MANIFEST.json")
    require(manifest.get("schema") == RUNTIME_SCHEMA, "runtime_schema_rejected")
    require(manifest.get("release_digest") == candidate.name, "runtime_digest_rejected")
    require(manifest.get("source_core_commit") == core_commit, "runtime_core_commit_rejected")
    require(manifest.get("source_deploy_commit") == deploy_commit, "runtime_commit_rejected")
    files = manifest.get("files")
    require(isinstance(files, dict) and bool(files), "runtime_inventory_rejected")
    expected_paths: set[str] = set()
    for relative, expected in files.items():
        require(isinstance(relative, str) and isinstance(expected, dict), "runtime_inventory_rejected")
        relative_path = Path(relative)
        require(
            not relative_path.is_absolute() and ".." not in relative_path.parts,
            "runtime_inventory_rejected",
        )
        path = candidate / relative
        require(not path.is_symlink() and path.is_file(), "runtime_candidate_type_rejected")
        require(digest_file(path) == expected.get("sha256"), "runtime_file_digest_rejected")
        require(path.stat().st_size == expected.get("size"), "runtime_file_size_rejected")
        expected_paths.add(relative)
    actual_paths: set[str] = set()
    for path in candidate.rglob("*"):
        require(not path.is_symlink(), "runtime_candidate_symlink_rejected")
        require(path.is_dir() or path.is_file(), "runtime_candidate_type_rejected")
        require(
            stat.S_IMODE(path.stat().st_mode) == (0o550 if path.is_dir() else 0o440),
            "runtime_candidate_mode_rejected",
        )
        if path.is_file() and path.name != "P07_HYBRID_MANIFEST.json":
            actual_paths.add(path.relative_to(candidate).as_posix())
    require(
        stat.S_IMODE(candidate.stat().st_mode) == 0o550,
        "runtime_candidate_mode_rejected",
    )
    require(actual_paths == expected_paths, "runtime_import_inventory_rejected")
    require(
        not any(path.name == "__pycache__" or path.suffix == ".pyc" for path in candidate.rglob("*")),
        "runtime_startup_bytecode_rejected",
    )
    closure = manifest.get("core_import_closure")
    require(isinstance(closure, dict), "runtime_import_closure_rejected")
    require(
        closure.get("algorithm") == _IMPORT_CLOSURE_ALGORITHM,
        "runtime_import_closure_rejected",
    )
    roots = closure.get("roots")
    closure_files = closure.get("files")
    require(
        isinstance(roots, list)
        and bool(roots)
        and all(isinstance(item, str) for item in roots)
        and isinstance(closure_files, list)
        and bool(closure_files)
        and all(isinstance(item, str) for item in closure_files),
        "runtime_import_closure_rejected",
    )
    expected_core_paths = {f"runtime/{relative}" for relative in closure_files}
    actual_core_paths = {
        relative for relative in actual_paths if relative.startswith("runtime/myuna_core/")
    }
    require(expected_core_paths == actual_core_paths, "runtime_import_closure_rejected")
    runtime_profile = manifest.get("runtime_profile")
    v7_contract = manifest.get("v7_phase1_contract")
    if runtime_profile is None:
        require(v7_contract is None, "runtime_profile_rejected")
    elif runtime_profile in P07_RUNTIME_PROFILES:
        require(v7_contract is None, "runtime_profile_rejected")
    else:
        require(runtime_profile in V7_RUNTIME_PROFILES, "runtime_profile_rejected")
        try:
            validate_v7_runtime_contract(
                v7_contract,
                runtime_profile=runtime_profile,
                core_commit=core_commit,
                roots=roots,
                core_files=closure_files,
                runtime_files=sorted(actual_paths),
            )
        except V7PackagingContractRejected as exc:
            raise ActivationRejected(exc.code) from exc
    return candidate.name


def _prepare_runtime_smoke_tree(candidate: Path, target: Path, gid: int) -> None:
    shutil.copytree(candidate, target)
    for path in (target, *target.rglob("*")):
        require(not path.is_symlink(), "runtime_candidate_symlink_rejected")
        require(path.is_dir() or path.is_file(), "runtime_candidate_type_rejected")
        os.chown(path, 0, gid)
        os.chmod(path, 0o550 if path.is_dir() else 0o440)


def _runtime_smoke_modules(candidate: Path) -> tuple[str, ...]:
    manifest = read_json(candidate / "P07_HYBRID_MANIFEST.json")
    closure = manifest.get("core_import_closure")
    if not isinstance(closure, dict):
        return ("telegram_owner_runtime_gateway", "myuna_core.external_context")
    files = closure.get("files")
    require(
        isinstance(files, list)
        and bool(files)
        and all(isinstance(item, str) for item in files),
        "runtime_import_closure_rejected",
    )
    entrypoint = "telegram_owner_runtime_gateway"
    modules: set[str] = {entrypoint}
    if manifest.get("runtime_profile") in V7_RUNTIME_PROFILES:
        modules.update(v7_projection_modules_for(manifest["runtime_profile"]))
    for relative in files:
        path = Path(relative)
        require(
            not path.is_absolute()
            and ".." not in path.parts
            and path.suffix == ".py"
            and path.parts
            and path.parts[0] == "myuna_core",
            "runtime_import_closure_rejected",
        )
        if path.name == "__init__.py":
            module_parts = path.parent.parts
        else:
            module_parts = (*path.parent.parts, path.stem)
        modules.add(".".join(module_parts))
    return (entrypoint, *sorted(modules - {entrypoint}))


def verify_runtime_startup_smoke(candidate: Path) -> None:
    try:
        identity = pwd.getpwnam(TELEGRAM_RUNTIME_USER)
    except KeyError as exc:
        raise ActivationRejected("runtime_startup_identity_rejected") from exc
    temporary = Path(tempfile.mkdtemp(prefix="p07-runtime-smoke-"))
    release = temporary / "release"
    try:
        os.chown(temporary, 0, identity.pw_gid)
        os.chmod(temporary, 0o550)
        _prepare_runtime_smoke_tree(candidate, release, identity.pw_gid)
        runtime = release / "runtime"
        modules = _runtime_smoke_modules(candidate)
        program = (
            "import importlib, os, sys\n"
            f"modules = {modules!r}\n"
            "sys.dont_write_bytecode = True\n"
            "assert os.environ.get('PYTHONDONTWRITEBYTECODE') == '1'\n"
            "def deny_network(event, args):\n"
            "    if event.startswith('socket.'):\n"
            "        raise RuntimeError('network_forbidden')\n"
            "sys.addaudithook(deny_network)\n"
            "try:\n"
            "    for module in modules:\n"
            "        importlib.import_module(module)\n"
            "except ModuleNotFoundError:\n"
            "    raise SystemExit(41)\n"
            "except PermissionError:\n"
            "    raise SystemExit(42)\n"
            "except OSError as exc:\n"
            "    raise SystemExit(42 if getattr(exc, 'errno', None) in (13, 30) else 43)\n"
            "except Exception:\n"
            "    raise SystemExit(43)\n"
        )
        completed = subprocess.run(
            [
                "/usr/sbin/runuser",
                "-u",
                TELEGRAM_RUNTIME_USER,
                "--",
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin",
                f"PYTHONPATH={runtime}",
                "PYTHONDONTWRITEBYTECODE=1",
                "MYUNA_SESSION_CONTEXT_STORE=sqlite-v1",
                "MYUNA_P07_HYBRID_EXTERNAL_ENABLED=true",
                "MYUNA_P07_HYBRID_PACING_SECONDS=2",
                "/usr/bin/python3",
                "-B",
                "-c",
                program,
            ],
            check=False,
            cwd=runtime,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        if completed.returncode != 0:
            if completed.returncode == 41:
                raise ActivationRejected("runtime_startup_import_rejected")
            if completed.returncode in {13, 30, 42, 126}:
                raise ActivationRejected("runtime_startup_permission_rejected")
            raise ActivationRejected("runtime_startup_other_rejected")
        require(
            not any(path.name == "__pycache__" or path.suffix == ".pyc" for path in release.rglob("*")),
            "runtime_startup_bytecode_rejected",
        )
    except subprocess.TimeoutExpired as exc:
        raise ActivationRejected("runtime_startup_other_rejected") from exc
    finally:
        shutil.rmtree(temporary)


def validate_plugin(candidate: Path) -> str:
    manifest = read_json(candidate.parent / f"{candidate.name}.manifest.json")
    require(manifest.get("schema") == PLUGIN_SCHEMA, "plugin_schema_rejected")
    require(manifest.get("release_digest") == candidate.name, "plugin_digest_rejected")
    entries = manifest.get("files")
    require(isinstance(entries, list) and bool(entries), "plugin_inventory_rejected")
    expected_paths = set()
    for entry in entries:
        require(isinstance(entry, dict), "plugin_inventory_rejected")
        relative = entry.get("destination")
        require(isinstance(relative, str), "plugin_inventory_rejected")
        path = candidate / relative
        require(not path.is_symlink() and path.is_file(), "plugin_file_rejected")
        require(digest_file(path) == entry.get("sha256"), "plugin_file_digest_rejected")
        require(path.stat().st_size == entry.get("size"), "plugin_file_size_rejected")
        expected_paths.add(relative)
    actual_paths = {
        path.relative_to(candidate).as_posix()
        for path in candidate.rglob("*")
        if path.is_file()
    }
    require(actual_paths == expected_paths, "plugin_file_set_rejected")
    return candidate.name


def render_core_binding(evidence: ReleaseEvidence, plan_digest: str) -> tuple[bytes, bytes]:
    candidate = SelectionCandidate(selected_release=evidence)
    intent = build_binding_intent(
        candidate,
        verifier_script_path=VERIFIER_PATH.as_posix(),
        verifier_script_sha256=VERIFIER_SHA256,
    )
    binding = canonical_json_bytes(
        render_runtime_binding(intent, approval_plan_digest=plan_digest).to_payload()
    )
    selector = render_selector_dropin(candidate).encode("utf-8")
    load_runtime_binding(parse_json_document(binding))
    return binding, selector


def render_core_gate() -> bytes:
    return canonical_hybrid_gate()


def render_telegram_config(plugin_digest: str) -> bytes:
    release = PLUGIN_ROOT / plugin_digest
    return canonical(
        {
            "channel_root": "/srv/myuna/channels/astrbot-telegram/dev",
            "compose_file": (release / "channels/astrbot-telegram/compose.dev.yml").as_posix(),
            "gateway_release": plugin_digest,
            "plugin_root": (
                release / "channels/astrbot-telegram/plugin/myuna_telegram_gateway"
            ).as_posix(),
            "schema": "myuna.telegram.r5-boot-resume-config.v1",
        }
    )


def render_telegram_dropin(runtime_digest: str) -> bytes:
    runtime = RUNTIME_ROOT / runtime_digest / "runtime"
    return (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/python3 {runtime}/telegram_owner_runtime_gateway.py\n"
        f"Environment=PYTHONPATH={runtime}\n"
        "Environment=PYTHONDONTWRITEBYTECODE=1\n"
        "Environment=MYUNA_SESSION_CONTEXT_STORE=sqlite-v1\n"
        "Environment=MYUNA_P07_HYBRID_EXTERNAL_ENABLED=true\n"
        "Environment=MYUNA_P07_HYBRID_PACING_SECONDS=2\n"
    ).encode("ascii")


def container_mounts() -> str:
    return run(
        [
            "/usr/bin/docker", "inspect", CONTAINER, "--format",
            "{{range .Mounts}}{{println .Source .Destination}}{{end}}",
        ]
    )


def container_healthy() -> bool:
    return run(
        [
            "/usr/bin/docker", "inspect", CONTAINER, "--format",
            "{{.State.Status}} {{.State.Health.Status}} {{.RestartCount}}",
        ],
        check=False,
    ) == "running healthy 0"


def run_resume_controller() -> None:
    run(["/usr/bin/python3", str(RESUME_CONTROLLER)], timeout=420)


def verify_credential_binding() -> None:
    try:
        verify_strict_binding(
            Path("/etc/systemd/system/myuna-core@qq.service.d"),
            canonical_dropin="credentials.conf",
            expected_source=CORE_CREDENTIAL_SOURCE,
        )
    except CredentialBindingRejected as exc:
        raise ActivationRejected(exc.code) from exc


def verify_effective_credential() -> None:
    directory = Path(f"/run/credentials/{CORE_SERVICE}")
    credential = directory / "deepseek_api_key"
    metadata = credential.lstat()
    require(
        not credential.is_symlink()
        and stat.S_ISREG(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) & 0o007 == 0,
        "effective_credential_rejected",
    )


def verify_prestate() -> dict[str, object]:
    units = (CORE_SERVICE, QQ_SOCKET, QQ_SERVICE, TELEGRAM_SOCKET, TELEGRAM_SERVICE, PROFILE_SERVICE)
    require(all(active(unit) for unit in units), "live_prestate_rejected")
    require(container_healthy(), "telegram_container_prestate_rejected")
    require(digest_file(VERIFIER_PATH) == VERIFIER_SHA256, "verifier_drifted")
    verify_credential_binding()
    binding = load_runtime_binding(parse_json_document(CORE_BINDING.read_bytes()))
    selected = binding.selected_release
    core_path = CORE_RELEASE_ROOT / selected.tree_sha256
    require(show(CORE_SERVICE, "WorkingDirectory") == core_path.as_posix(), "core_prestate_drifted")
    require(compute_tree_digest(core_path) == (selected.tree_sha256, selected.file_count), "core_prestate_tree_drifted")
    config = read_json(TELEGRAM_CONFIG)
    plugin = config.get("gateway_release")
    require(isinstance(plugin, str) and _DIGEST.fullmatch(plugin) is not None, "plugin_prestate_rejected")
    require(f"/{plugin}/" in container_mounts(), "plugin_mount_prestate_rejected")
    return {
        "core_release": selected.tree_sha256,
        "core_binding_sha256": digest_file(CORE_BINDING),
        "core_selector_sha256": digest_file(CORE_SELECTOR),
        "telegram_config_sha256": digest_file(TELEGRAM_CONFIG),
        "telegram_execstart_sha256": digest_bytes(show(TELEGRAM_SERVICE, "ExecStart").encode()),
        "plugin_release": plugin,
    }


def install_tree(candidate: Path, destination: Path, *, gid: int, directory_mode: int, file_mode: int) -> None:
    if destination.exists():
        require(not destination.is_symlink() and destination.is_dir(), "installed_release_type_rejected")
        return
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name[:12]}-", dir=destination.parent))
    try:
        shutil.copytree(candidate, temporary, dirs_exist_ok=True)
        for path in (temporary, *temporary.rglob("*")):
            require(not path.is_symlink(), "release_symlink_rejected")
            os.chown(path, 0, gid)
            os.chmod(path, directory_mode if path.is_dir() else file_mode)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def tree_inventory(root: Path) -> dict[str, str]:
    require(not root.is_symlink() and root.is_dir(), "release_root_rejected")
    inventory: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "release_symlink_rejected")
        if path.is_file():
            inventory[path.relative_to(root).as_posix()] = digest_file(path)
        else:
            require(path.is_dir(), "release_type_rejected")
    return inventory


def backup(plan: bytes, prestate: dict[str, object]) -> tuple[Path, dict[str, bytes | None]]:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUP_ROOT, 0o700)
    root = BACKUP_ROOT / digest_bytes(plan)
    require(not root.exists(), "activation_attempt_already_exists")
    root.mkdir(mode=0o700)
    payloads = {
        "CORE_BINDING": CORE_BINDING.read_bytes(),
        "CORE_SELECTOR": CORE_SELECTOR.read_bytes(),
        "CORE_GATE": optional_bytes(CORE_GATE),
        "TELEGRAM_CONFIG": TELEGRAM_CONFIG.read_bytes(),
        "TELEGRAM_DROPIN": optional_bytes(TELEGRAM_DROPIN),
    }
    atomic_write(root / "PLAN.json", plan, mode=0o600)
    atomic_write(root / "PRESTATE.json", canonical(prestate), mode=0o600)
    for name, payload in payloads.items():
        if payload is not None:
            atomic_write(root / name, payload, mode=0o600)
    return root, payloads


def quiesce_gateways() -> None:
    systemctl("stop", QQ_SOCKET, TELEGRAM_SOCKET, QQ_SERVICE, TELEGRAM_SERVICE)


def restore_prestate(payloads: dict[str, bytes | None], prestate: dict[str, object]) -> None:
    myuna_gid = grp.getgrnam("myuna").gr_gid
    quiesce_gateways()
    atomic_write(CORE_BINDING, payloads["CORE_BINDING"] or b"", mode=0o640, gid=myuna_gid)
    atomic_write(CORE_SELECTOR, payloads["CORE_SELECTOR"] or b"", mode=0o644)
    restore_optional(CORE_GATE, payloads["CORE_GATE"], mode=0o644)
    atomic_write(TELEGRAM_CONFIG, payloads["TELEGRAM_CONFIG"] or b"", mode=0o600)
    restore_optional(TELEGRAM_DROPIN, payloads["TELEGRAM_DROPIN"], mode=0o644)
    systemctl("daemon-reload")
    systemctl("restart", CORE_SERVICE)
    systemctl("start", QQ_SOCKET, QQ_SERVICE)
    systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)
    run_resume_controller()
    require(show(CORE_SERVICE, "WorkingDirectory").endswith(str(prestate["core_release"])), "rollback_core_rejected")
    require(digest_file(CORE_BINDING) == prestate["core_binding_sha256"], "rollback_binding_rejected")
    require(digest_file(TELEGRAM_CONFIG) == prestate["telegram_config_sha256"], "rollback_telegram_rejected")
    require(str(prestate["plugin_release"]) in container_mounts(), "rollback_plugin_rejected")
    require(container_healthy(), "rollback_container_rejected")


def verify_target(core: ReleaseEvidence, runtime_digest: str, plugin_digest: str) -> dict[str, object]:
    core_path = CORE_RELEASE_ROOT / core.tree_sha256
    require(active(CORE_SERVICE) and active(PROFILE_SERVICE), "core_target_inactive")
    require(active(QQ_SOCKET) and active(QQ_SERVICE), "qq_restore_rejected")
    require(active(TELEGRAM_SOCKET) and active(TELEGRAM_SERVICE), "telegram_target_inactive")
    require(show(CORE_SERVICE, "WorkingDirectory") == core_path.as_posix(), "core_target_rejected")
    require(CORE_GATE.read_bytes() == render_core_gate(), "core_gate_rejected")
    verify_effective_credential()
    verify = subprocess.run(
        ["/usr/bin/python3", str(VERIFIER_PATH), "verify-active"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        cwd=core_path,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": f"{core_path}/src"},
    )
    require(verify.returncode == 0, "core_verifier_rejected")
    require(f"/{runtime_digest}/runtime/telegram_owner_runtime_gateway.py" in show(TELEGRAM_SERVICE, "ExecStart"), "runtime_target_rejected")
    require(TELEGRAM_DROPIN.read_bytes() == render_telegram_dropin(runtime_digest), "runtime_dropin_rejected")
    require(TELEGRAM_CONFIG.read_bytes() == render_telegram_config(plugin_digest), "plugin_config_rejected")
    require(f"/{plugin_digest}/" in container_mounts(), "plugin_mount_rejected")
    require(container_healthy(), "container_target_rejected")
    epoch_parent = EPOCH_DATABASE.parent
    require(epoch_parent.is_dir() and not epoch_parent.is_symlink(), "epoch_path_rejected")
    require(stat.S_IMODE(epoch_parent.stat().st_mode) == 0o700, "epoch_parent_mode_rejected")
    require(EPOCH_DATABASE.is_file() and not EPOCH_DATABASE.is_symlink(), "epoch_database_rejected")
    require(stat.S_IMODE(EPOCH_DATABASE.stat().st_mode) == 0o600, "epoch_database_mode_rejected")
    probe = (
        "from external_context_epoch import ExternalEpochStore;"
        f"s=ExternalEpochStore({str(EPOCH_DATABASE)!r},epoch_id='telegram-owner-private-external-v1');"
        "m=s.public_metadata();"
        "assert m['pending_count']==m['turn_count']==m['summary_count']==0"
    )
    completed = subprocess.run(
        ["/usr/bin/python3", "-B", "-c", probe],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        env={
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": f"{RUNTIME_ROOT / runtime_digest / 'runtime'}:{core_path / 'src'}",
        },
    )
    require(completed.returncode == 0, "epoch_empty_probe_rejected")
    return {
        "core_release": core.tree_sha256,
        "runtime_release": runtime_digest,
        "plugin_release": plugin_digest,
        "epoch_empty": True,
    }


def activate(
    core_candidate: Path,
    runtime_candidate: Path,
    plugin_candidate: Path,
    *,
    core_commit: str,
    deploy_commit: str,
    preflight_only: bool,
) -> dict[str, object]:
    require(os.geteuid() == 0, "root_identity_required")
    require(_COMMIT.fullmatch(core_commit) is not None, "core_commit_rejected")
    require(_COMMIT.fullmatch(deploy_commit) is not None, "deploy_commit_rejected")
    core, artifact, receipt = core_evidence(core_candidate)
    require(core.source_commit == core_commit, "core_commit_drifted")
    runtime_digest = validate_runtime(runtime_candidate, core_commit, deploy_commit)
    verify_runtime_startup_smoke(runtime_candidate)
    plugin_digest = validate_plugin(plugin_candidate)
    if phase_f_selected_target(Path(__file__).resolve().parent):
        raise ActivationRejected("phase_f_canonical_owner_required")
    prestate = verify_prestate()
    plan = canonical(
        {
            "schema": SCHEMA,
            "status": "standing_authority_one_attempt",
            "executor_sha256": digest_file(Path(__file__).resolve()),
            "prestate": prestate,
            "target": {
                "core_release": core.tree_sha256,
                "core_commit": core_commit,
                "runtime_release": runtime_digest,
                "deploy_commit": deploy_commit,
                "plugin_release": plugin_digest,
                "model": "deepseek-v4-flash",
                "channel": "authenticated-telegram-owner-private-only",
                "external_epoch": "new-empty-v1",
                "pacing_seconds": 2,
                "startup_gate_schema": _FAILURE_GATE_SCHEMA,
                "startup_smoke": "passed",
            },
            "boundaries": {
                "legacy_session_migrated": False,
                "qq_config_changed": False,
                "provider_or_channel_probe": False,
                "profile_or_message_content_recorded": False,
            },
            "rollback": {"exact_prestate_bytes": True, "retain_releases": True},
        }
    )
    if preflight_only:
        return {
            "plan_sha256": digest_bytes(plan),
            "startup_smoke": "passed",
            "status": "ready",
        }
    backup_root, payloads = backup(plan, prestate)
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE_ROOT, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    journal = STATE_ROOT / f"JOURNAL-{stamp}-{digest_bytes(plan)[:12]}.json"
    atomic_write(journal, canonical({"schema": SCHEMA, "status": "activating", "plan_sha256": digest_bytes(plan)}), mode=0o600)
    myuna_gid = grp.getgrnam("myuna").gr_gid
    telegram_gid = grp.getgrnam("myuna-gateway-telegram").gr_gid
    mutated = False
    try:
        install_tree(core_candidate, CORE_RELEASE_ROOT / core.tree_sha256, gid=myuna_gid, directory_mode=0o550, file_mode=0o440)
        validate_immutable_release_tree(CORE_RELEASE_ROOT / core.tree_sha256, core)
        install_tree(runtime_candidate, RUNTIME_ROOT / runtime_digest, gid=telegram_gid, directory_mode=0o550, file_mode=0o440)
        install_tree(plugin_candidate, PLUGIN_ROOT / plugin_digest, gid=0, directory_mode=0o555, file_mode=0o444)
        require(
            tree_inventory(runtime_candidate)
            == tree_inventory(RUNTIME_ROOT / runtime_digest),
            "installed_runtime_drifted",
        )
        require(
            tree_inventory(plugin_candidate)
            == tree_inventory(PLUGIN_ROOT / plugin_digest),
            "installed_plugin_drifted",
        )
        quiesce_gateways()
        binding, selector = render_core_binding(core, digest_bytes(plan))
        atomic_write(CORE_BINDING, binding, mode=0o640, gid=myuna_gid)
        atomic_write(CORE_SELECTOR, selector, mode=0o644)
        atomic_write(CORE_GATE, render_core_gate(), mode=0o644)
        atomic_write(TELEGRAM_CONFIG, render_telegram_config(plugin_digest), mode=0o600)
        atomic_write(TELEGRAM_DROPIN, render_telegram_dropin(runtime_digest), mode=0o644)
        mutated = True
        systemctl("daemon-reload")
        systemctl("restart", CORE_SERVICE)
        systemctl("start", QQ_SOCKET, QQ_SERVICE)
        systemctl("start", TELEGRAM_SOCKET, TELEGRAM_SERVICE)
        run_resume_controller()
        deadline = time.monotonic() + 60
        while True:
            try:
                target = verify_target(core, runtime_digest, plugin_digest)
                break
            except ActivationRejected:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)
        payload = {
            "schema": SCHEMA,
            "status": "ACTIVE_WAITING_OWNER_ORGANIC_TELEGRAM_E2E",
            "plan_sha256": digest_bytes(plan),
            "backup": backup_root.name,
            **target,
            "core_commit": core_commit,
            "deploy_commit": deploy_commit,
            "model_called": False,
            "channel_called": False,
            "legacy_session_migrated": False,
            "qq_config_changed": False,
            "profile_content_recorded": False,
            "raw_message_recorded": False,
            "secret_recorded": False,
            "startup_smoke": "passed",
        }
        atomic_write(journal, canonical(payload), mode=0o600)
        atomic_write(STATE_ROOT / f"RECEIPT-{stamp}-{digest_bytes(plan)[:12]}.json", canonical(payload), mode=0o600)
        atomic_write(backup_root / "CORE_ARTIFACT.json", artifact, mode=0o600)
        atomic_write(backup_root / "CORE_INSTALLATION_RECEIPT.json", receipt, mode=0o600)
        return payload
    except Exception as exc:
        if mutated:
            restore_prestate(payloads, prestate)
        atomic_write(
            journal,
            canonical(
                {
                    "schema": SCHEMA,
                    "status": "rolled_back" if mutated else "failed_before_mutation",
                    "plan_sha256": digest_bytes(plan),
                    "rollback": "verified" if mutated else "not_needed",
                    "model_called": False,
                    "channel_called": False,
                    **failure_projection(exc),
                }
            ),
            mode=0o600,
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-candidate", required=True, type=Path)
    parser.add_argument("--runtime-candidate", required=True, type=Path)
    parser.add_argument("--plugin-candidate", required=True, type=Path)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--deploy-commit", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    try:
        result = activate(
            arguments.core_candidate.resolve(),
            arguments.runtime_candidate.resolve(),
            arguments.plugin_candidate.resolve(),
            core_commit=arguments.core_commit,
            deploy_commit=arguments.deploy_commit,
            preflight_only=arguments.preflight_only,
        )
    except (ActivationRejected, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(
            json.dumps(
                {"status": "rejected", **failure_projection(exc)},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
