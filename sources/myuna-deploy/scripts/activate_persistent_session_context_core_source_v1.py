#!/usr/bin/env python3
"""Activate the fixed Core single-attempt and persistent Gateway candidates."""

from __future__ import annotations

import argparse
import grp
import json
import os
import shutil
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path

import activate_persistent_session_context_v1 as gateway
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


CORE_CANDIDATE_DIGEST = (
    "16255b4b61b0a3ac9ce8c1489a6f51faec363a99ff6859f01ce8b1ec6339d9a3"
)
CORE_CANDIDATE_COMMIT = "e97bd22f2e4fe5f187d40d3b89effc72dc3002be"
CORE_CANDIDATE_FILE_COUNT = 193
CORE_BASE_DIGEST = (
    "61b5f55436503cf6a4090083e070388853d3a702cb6d6760afb967a2142a0b23"
)
CORE_BASE_BINDING_SHA256 = (
    "c29db5323c95cedaf1db849f47af1b11f33178ad0ec6004eafdac17347889e13"
)
CORE_BASE_SELECTOR_SHA256 = (
    "646f9e20d2ef8297112ae5522fc8b533afbc62310f21b498ab69afcc6fdaf79e"
)
GATEWAY_CANDIDATE_DIGEST = (
    "a75ebd22247755b19556f11c07807bb08beb76783d40510af647afdde0d552f5"
)
VERIFIER_SHA256 = (
    "3fab13b7b533c3e93bf5759256ff5153d7bb17aea0fc8307f560e82985a7fcaf"
)
VERIFIER_PATH = Path(
    "/opt/myuna/core-release-selector/releases"
) / VERIFIER_SHA256 / "core_release_selector.py"
CORE_RELEASE_ROOT = Path("/srv/myuna/releases/core")
CORE_BINDING = Path("/etc/myuna/core-release-selector/qq.binding.json")
CORE_SELECTOR = Path(
    "/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf"
)
BACKUP_ROOT = Path("/var/backups/myuna/persistent-session-context-v1")


class ActivationRejected(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ActivationRejected(message)


def digest_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _artifact_manifest_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-source-artifact.persistent-session-context-v1",
            "status": "offline_tested_not_installed",
            "tree_digest_algorithm": "myuna-path-content-tree-sha256-v1",
            "tree_sha256": CORE_CANDIDATE_DIGEST,
            "source_commit": CORE_CANDIDATE_COMMIT,
            "file_count": CORE_CANDIDATE_FILE_COUNT,
            "verification": {
                "core_tests": 387,
                "gateway_core_joint_tests": 104,
                "provider_calls": 0,
                "bytecode_files": 0,
            },
        }
    )


def _installation_receipt_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.core-release.inactive-installation.v1",
            "status": "installed_inactive_not_selected",
            "tree_sha256": CORE_CANDIDATE_DIGEST,
            "source_commit": CORE_CANDIDATE_COMMIT,
            "file_count": CORE_CANDIDATE_FILE_COUNT,
            "release_path": (CORE_RELEASE_ROOT / CORE_CANDIDATE_DIGEST).as_posix(),
            "artifact_manifest_sha256": digest_bytes(_artifact_manifest_bytes()),
            "ownership": "root:myuna",
            "directory_mode": "0550",
            "file_mode": "0440",
        }
    )


def target_release_evidence() -> ReleaseEvidence:
    return ReleaseEvidence(
        tree_sha256=CORE_CANDIDATE_DIGEST,
        source_commit=CORE_CANDIDATE_COMMIT,
        file_count=CORE_CANDIDATE_FILE_COUNT,
        artifact_manifest_sha256=digest_bytes(_artifact_manifest_bytes()),
        installation_receipt_sha256=digest_bytes(_installation_receipt_bytes()),
    )


def validate_core_candidate(path: Path) -> None:
    resolved = path.resolve()
    require(
        resolved.name == CORE_CANDIDATE_DIGEST,
        "Core candidate path digest mismatch",
    )
    digest, count = compute_tree_digest(resolved)
    require(
        (digest, count) == (CORE_CANDIDATE_DIGEST, CORE_CANDIDATE_FILE_COUNT),
        "Core candidate tree mismatch",
    )
    completed = subprocess.run(
        [
            "/usr/bin/env",
            "PYTHONDONTWRITEBYTECODE=1",
            f"PYTHONPATH={resolved / 'src'}",
            "/usr/bin/python3",
            "-c",
            (
                "from myuna_core.providers.runtime import "
                "load_deepseek_runtime_settings as load; "
                "assert load({'MYUNA_DEEPSEEK_MAX_ATTEMPTS':'3'}).max_attempts == 1"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    require(completed.returncode == 0, "Core candidate invariant probe failed")


def _validate_core_prestate() -> None:
    require(gateway.is_active(gateway.CORE_SERVICE), "Core is not active")
    require(
        gateway.digest_file(CORE_BINDING) == CORE_BASE_BINDING_SHA256,
        "Core binding drifted",
    )
    require(
        gateway.digest_file(CORE_SELECTOR) == CORE_BASE_SELECTOR_SHA256,
        "Core selector drifted",
    )
    require(
        gateway.systemctl(
            "show",
            "-p",
            "WorkingDirectory",
            "--value",
            gateway.CORE_SERVICE,
            capture=True,
        )
        == (CORE_RELEASE_ROOT / CORE_BASE_DIGEST).as_posix(),
        "Core selected release drifted",
    )
    require(
        VERIFIER_PATH.is_file()
        and gateway.digest_file(VERIFIER_PATH) == VERIFIER_SHA256,
        "Core verifier drifted",
    )


def preflight(core_candidate: Path, gateway_candidate: Path) -> str:
    validate_core_candidate(core_candidate)
    release_digest, _ = gateway.validate_candidate(gateway_candidate)
    require(
        release_digest == GATEWAY_CANDIDATE_DIGEST,
        "Gateway candidate digest mismatch",
    )
    gateway._verify_current_baseline()
    _validate_core_prestate()
    return release_digest


def _install_core_candidate(source: Path) -> Path:
    destination = CORE_RELEASE_ROOT / CORE_CANDIDATE_DIGEST
    evidence = target_release_evidence()
    if destination.exists():
        validate_immutable_release_tree(destination, evidence)
        return destination
    CORE_RELEASE_ROOT.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{CORE_CANDIDATE_DIGEST[:12]}-", dir=CORE_RELEASE_ROOT)
    )
    try:
        shutil.copytree(source.resolve(), temporary, dirs_exist_ok=True)
        myuna_gid = grp.getgrnam("myuna").gr_gid
        for entry in sorted(temporary.rglob("*"), reverse=True):
            os.chown(entry, 0, myuna_gid)
            os.chmod(entry, 0o550 if entry.is_dir() else 0o440)
        os.chown(temporary, 0, myuna_gid)
        os.chmod(temporary, 0o550)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    validate_immutable_release_tree(destination, evidence)
    return destination


def _activation_plan_bytes(gateway_digest: str) -> bytes:
    return canonical_json_bytes(
        {
            "schema": "myuna.persistent-session-context.core-source-live-plan.v1",
            "status": "approved_by_owner",
            "activation_attempt": {
                "ordinal": 2,
                "final_for_candidate": True,
                "executor_sha256": gateway.digest_file(Path(__file__).resolve()),
            },
            "prestate": {
                "core_release": CORE_BASE_DIGEST,
                "core_binding_sha256": CORE_BASE_BINDING_SHA256,
                "core_selector_sha256": CORE_BASE_SELECTOR_SHA256,
                "gateway_release": gateway.BASE_RELEASE_DIGEST,
                "sqlite": "preserve",
            },
            "target": {
                "core_release": CORE_CANDIDATE_DIGEST,
                "core_source_commit": CORE_CANDIDATE_COMMIT,
                "gateway_release": gateway_digest,
                "provider_effective_max_attempts": 1,
                "provider_timeout_seconds": 60,
                "gateway_timeout_seconds": 70,
            },
            "live_scope": {
                "core_restart": 1,
                "channels": ["qq-owner-private", "telegram-owner-private"],
                "recall_e2e_each": 1,
                "provider_attempts_max": 2,
                "incremental_cost_cap_usd": "0.08",
                "health_endpoints_forbidden": True,
            },
            "rollback": {
                "restore_core_binding_and_selector_bytes": True,
                "restore_gateway_release": gateway.BASE_RELEASE_DIGEST,
                "preserve_sqlite": True,
                "retain_installed_releases": True,
            },
        }
    )


def _target_core_bytes(plan_digest: str) -> tuple[bytes, bytes]:
    candidate = SelectionCandidate(selected_release=target_release_evidence())
    intent = build_binding_intent(
        candidate,
        verifier_script_path=VERIFIER_PATH.as_posix(),
        verifier_script_sha256=VERIFIER_SHA256,
    )
    binding = render_runtime_binding(intent, approval_plan_digest=plan_digest)
    binding_bytes = canonical_json_bytes(binding.to_payload())
    selector_bytes = render_selector_dropin(candidate).encode("utf-8")
    load_runtime_binding(parse_json_document(binding_bytes))
    require(
        digest_bytes(selector_bytes) == binding.selector_dropin_sha256,
        "target selector evidence mismatch",
    )
    return binding_bytes, selector_bytes


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    os.chmod(path, 0o600)


def _extend_backup(backup: Path, gateway_digest: str) -> tuple[bytes, bytes]:
    selector_backup = backup / "core-selector"
    selector_backup.mkdir(mode=0o700)
    old_binding = CORE_BINDING.read_bytes()
    old_selector = CORE_SELECTOR.read_bytes()
    _write_private(selector_backup / "qq.binding.json", old_binding)
    _write_private(selector_backup / "10-core-release-selector-v1.conf", old_selector)
    artifact_manifest = _artifact_manifest_bytes()
    install_receipt = _installation_receipt_bytes()
    plan = _activation_plan_bytes(gateway_digest)
    plan_digest = digest_bytes(plan)
    binding, selector = _target_core_bytes(plan_digest)
    for name, payload in (
        ("CORE_ARTIFACT_MANIFEST.json", artifact_manifest),
        ("CORE_INSTALLATION_RECEIPT.json", install_receipt),
        ("LIVE_PLAN.json", plan),
        ("target.qq.binding.json", binding),
        ("target.10-core-release-selector-v1.conf", selector),
    ):
        _write_private(backup / name, payload)
    return binding, selector


def _stop_gateway_ingress() -> None:
    for spec in gateway.CHANNELS.values():
        gateway.systemctl("stop", str(spec["socket"]))
        gateway.systemctl("stop", str(spec["service"]))


def _start_gateway_sockets_only() -> None:
    for spec in gateway.CHANNELS.values():
        gateway.systemctl("start", str(spec["socket"]))
        require(gateway.is_active(str(spec["socket"])), "Gateway socket did not start")
        require(
            not gateway.is_active(str(spec["service"])),
            "Gateway service unexpectedly active",
        )


def _verify_active_core() -> None:
    require(gateway.is_active(gateway.CORE_SERVICE), "Core failed to start")
    target = (CORE_RELEASE_ROOT / CORE_CANDIDATE_DIGEST).as_posix()
    require(
        gateway.systemctl(
            "show",
            "-p",
            "WorkingDirectory",
            "--value",
            gateway.CORE_SERVICE,
            capture=True,
        )
        == target,
        "Core target release was not selected",
    )
    completed = subprocess.run(
        ["/usr/bin/python3", VERIFIER_PATH.as_posix(), "verify-active"],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        cwd=target,
        env={
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": f"{target}/src",
        },
    )
    require(completed.returncode == 0, "Core selector verifier rejected activation")
    actual_attempts = gateway._running_environment(gateway.CORE_SERVICE).get(
        "MYUNA_DEEPSEEK_MAX_ATTEMPTS", gateway.CORE_BASE_MAX_ATTEMPTS
    )
    completed = subprocess.run(
        [
            "/usr/bin/env",
            "PYTHONDONTWRITEBYTECODE=1",
            f"PYTHONPATH={target}/src",
            "/usr/bin/python3",
            "-c",
            (
                "import os; from myuna_core.providers.runtime import "
                "load_deepseek_runtime_settings as load; "
                "assert load({'MYUNA_DEEPSEEK_MAX_ATTEMPTS':os.environ['CHECK']})"
                ".max_attempts == 1"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env={"CHECK": actual_attempts},
    )
    require(completed.returncode == 0, "Core effective attempt invariant failed")


def _verify_gateway_target(gateway_digest: str) -> None:
    for channel, spec in gateway.CHANNELS.items():
        exec_start = gateway.systemctl(
            "show",
            "-p",
            "ExecStart",
            "--value",
            str(spec["service"]),
            capture=True,
        )
        require(gateway_digest in exec_start, "Gateway target release mismatch")
        require(
            spec["dropin"].read_bytes() == gateway.render_dropin(channel, gateway_digest),
            "Gateway target drop-in mismatch",
        )


def _restore_core_bytes(backup: Path) -> None:
    selector_backup = backup / "core-selector"
    old_binding = (selector_backup / "qq.binding.json").read_bytes()
    old_selector = (selector_backup / "10-core-release-selector-v1.conf").read_bytes()
    gateway._atomic_write(
        CORE_BINDING,
        old_binding,
        mode=0o640,
        gid=grp.getgrnam("myuna").gr_gid,
    )
    gateway._atomic_write(CORE_SELECTOR, old_selector, mode=0o644)


def rollback(gateway_candidate: Path, backup: Path) -> None:
    gateway_digest, _ = gateway.validate_candidate(gateway_candidate)
    receipt = json.loads((backup / "RECEIPT.json").read_text(encoding="utf-8"))
    require(receipt.get("release_digest") == gateway_digest, "backup mismatch")
    _stop_gateway_ingress()
    gateway._remove_candidate_dropins(gateway_digest)
    _restore_core_bytes(backup)
    gateway.systemctl("daemon-reload")
    gateway.systemctl("restart", gateway.CORE_SERVICE)
    require(gateway.is_active(gateway.CORE_SERVICE), "Core rollback failed")
    require(
        gateway.systemctl(
            "show", "-p", "WorkingDirectory", "--value", gateway.CORE_SERVICE,
            capture=True,
        )
        == (CORE_RELEASE_ROOT / CORE_BASE_DIGEST).as_posix(),
        "Core rollback release mismatch",
    )
    _start_gateway_sockets_only()


def apply(core_candidate: Path, gateway_candidate: Path) -> tuple[str, Path]:
    require(os.geteuid() == 0, "activation requires root")
    gateway_digest = preflight(core_candidate, gateway_candidate)
    backup = gateway._backup_current_units(gateway_digest)
    mutated = False
    try:
        _install_core_candidate(core_candidate)
        for spec in gateway.CHANNELS.values():
            gateway._install_release(
                gateway_candidate,
                spec["release_root"] / gateway_digest,
                str(spec["group"]),
            )
        binding, selector = _extend_backup(backup, gateway_digest)
        _stop_gateway_ingress()
        mutated = True
        gateway._atomic_write(
            CORE_BINDING,
            binding,
            mode=0o640,
            gid=grp.getgrnam("myuna").gr_gid,
        )
        gateway._atomic_write(CORE_SELECTOR, selector, mode=0o644)
        for channel, spec in gateway.CHANNELS.items():
            gateway._atomic_write(
                spec["dropin"], gateway.render_dropin(channel, gateway_digest)
            )
        gateway.systemctl("daemon-reload")
        gateway.systemctl("restart", gateway.CORE_SERVICE)
        _verify_active_core()
        _start_gateway_sockets_only()
        _verify_gateway_target(gateway_digest)
        return gateway_digest, backup
    except Exception:
        if mutated:
            rollback(gateway_candidate, backup)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "apply", "rollback"))
    parser.add_argument("--core-candidate", required=True, type=Path)
    parser.add_argument("--gateway-candidate", required=True, type=Path)
    parser.add_argument("--backup", type=Path)
    args = parser.parse_args()
    if args.action == "preflight":
        gateway_digest = preflight(args.core_candidate, args.gateway_candidate)
        result = {
            "status": "ready",
            "gateway_release": gateway_digest,
            "core_release": CORE_CANDIDATE_DIGEST,
        }
    elif args.action == "apply":
        gateway_digest, backup = apply(args.core_candidate, args.gateway_candidate)
        result = {
            "status": "activated_socket_only",
            "gateway_release": gateway_digest,
            "core_release": CORE_CANDIDATE_DIGEST,
            "backup": str(backup),
        }
    else:
        require(args.backup is not None, "rollback requires backup")
        rollback(args.gateway_candidate, args.backup)
        result = {
            "status": "rolled_back_socket_only",
            "core_release": CORE_BASE_DIGEST,
            "gateway_release": gateway.BASE_RELEASE_DIGEST,
            "sqlite": "preserved",
        }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
