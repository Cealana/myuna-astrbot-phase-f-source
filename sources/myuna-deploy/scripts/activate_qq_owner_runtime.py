#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime
from hashlib import sha256
import hmac
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import sys
import time

try:
    from scripts.apply_owner_binding_pending import (
        _psql,
        _run,
        _sha256_file,
        _write_atomic,
        copy_backup_to_windows,
        create_verified_backup,
        ensure_channel_healthy,
    )
except ModuleNotFoundError:
    from apply_owner_binding_pending import (  # type: ignore[no-redef]
        _psql,
        _run,
        _sha256_file,
        _write_atomic,
        copy_backup_to_windows,
        create_verified_backup,
        ensure_channel_healthy,
    )


OPERATION = "qq-owner-private-runtime-activation-v1"
FINALIZATION_DIGEST = "38929e450d7cba0c083fec93b1e6c30570c672530609b1cb61c335730310f947"
EVIDENCE_SHA256 = "559be2a23b11c5c12064bda7d7bd0e2f0a02d268c91e7ffe1c12477c34657a29"
PRINCIPAL_ID = "principal-owner-cealana"
NAMESPACE_ID = "ns-owner-cealana-private"
BINDING_ID = "binding-astrbot-qq-owner-cealana"
MIGRATION_VERSION = "0005_qq_owner_runtime_resolution"

CORE_REPO = Path("/srv/myuna/repos/core")
DEPLOY_REPO = Path("/srv/myuna/repos/deploy")
MIGRATION_PATH = DEPLOY_REPO / "database/migrations/0005_qq_owner_runtime_resolution.sql"
VERIFY_SQL_PATH = DEPLOY_REPO / "database/tests/verify_qq_owner_runtime_resolution.sql"
BACKUP_ROOT = Path("/var/backups/postgresql/myuna/qq-owner-runtime-v1")
WINDOWS_BACKUP_ROOT = Path(
    "/mnt/c/Server-Critical-Backup/Myuna/Database-Logical-Latest"
)
RUNTIME_CONFIG_PATH = Path("/etc/myuna-gateway/qq-owner-runtime-v1.json")
RUNTIME_MARKER_PATH = Path("/etc/myuna-gateway/qq-owner-runtime-approved")
CORE_TOKEN_PATH = Path("/etc/myuna-gateway/secrets/qq-owner-core-token")
CORE_ENV_PATH = Path("/etc/myuna/qq.env")
CORE_MANIFEST_PATH = Path("/etc/myuna/capabilities/qq-owner-v5.json")
FINAL_RECEIPT_PATH = Path(
    "/var/lib/myuna-gateway/qq-owner-runtime-activation-v1-receipt.json"
)
INSTALLED_RUNNER_PATH = Path(
    "/usr/local/libexec/myuna-gateway/qq_owner_runtime_gateway.py"
)
CORE_DROPIN_DIR = Path("/etc/systemd/system/myuna-core@qq.service.d")
CORE_DROPIN_PATH = CORE_DROPIN_DIR / "credentials.conf"
RUNTIME_SERVICE_PATH = Path(
    "/etc/systemd/system/myuna-qq-owner-runtime-dev.service"
)
RUNTIME_SOCKET_UNIT_PATH = Path(
    "/etc/systemd/system/myuna-qq-owner-runtime-dev.socket"
)
RUNTIME_SOCKET_PATH = Path("/run/myuna-gateway/qq-owner.sock")

SOURCE_FILES = {
    "core/capabilities.py": CORE_REPO / "src/myuna_core/capabilities.py",
    "core/conversation.py": CORE_REPO / "src/myuna_core/conversation.py",
    "deploy/activation": DEPLOY_REPO / "scripts/activate_qq_owner_runtime.py",
    "deploy/compose": DEPLOY_REPO / "channels/astrbot-qq/compose.dev.yml",
    "deploy/core-dropin": DEPLOY_REPO / "systemd/myuna-core-qq-credentials.conf",
    "deploy/core-env": DEPLOY_REPO / "config/qq-owner-v5.env",
    "deploy/gateway-runner": DEPLOY_REPO / "scripts/qq_owner_runtime_gateway.py",
    "deploy/manifest": DEPLOY_REPO / "config/capabilities/dev-v5.json",
    "deploy/migration": MIGRATION_PATH,
    "deploy/plugin-main": DEPLOY_REPO
    / "channels/astrbot-qq/plugin/myuna_gateway/main.py",
    "deploy/plugin-protocol": DEPLOY_REPO
    / "channels/astrbot-qq/plugin/myuna_gateway/protocol.py",
    "deploy/runtime-service": DEPLOY_REPO
    / "systemd/myuna-qq-owner-runtime-dev.service",
    "deploy/runtime-socket": DEPLOY_REPO
    / "systemd/myuna-qq-owner-runtime-dev.socket",
}


class RuntimeActivationError(RuntimeError):
    pass


def canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _git_value(repo: Path, *args: str) -> str:
    return _run(
        [
            "/usr/sbin/runuser",
            "-u",
            "myuna",
            "--",
            "git",
            "-C",
            str(repo),
            *args,
        ]
    ).stdout.strip()


def _source_hashes() -> dict[str, str]:
    missing = [name for name, path in SOURCE_FILES.items() if not path.is_file()]
    if missing:
        raise RuntimeActivationError("QQ runtime source bundle is incomplete")
    return {name: _sha256_file(path) for name, path in sorted(SOURCE_FILES.items())}


def _bundle_sha256(hashes: dict[str, str]) -> str:
    return sha256(canonical_json(hashes)).hexdigest()


def build_activation_plan() -> dict[str, object]:
    hashes = _source_hashes()
    return {
        "backups": {
            "c_drive_verified_copy": True,
            "post_change": True,
            "pre_change": True,
        },
        "capabilities": {
            "deepseek_daily_budget_usd": "2.00",
            "group_chat": False,
            "memory_read": False,
            "memory_write": False,
            "plain_text_private_chat": True,
            "tools": False,
            "verified_owner_only": True,
            "vision": False,
        },
        "database": {
            "identity_rows_changed": False,
            "migration": MIGRATION_VERSION,
            "new_privilege": "exact verified binding lookup by HMAC fingerprint",
            "raw_account_id_stored": False,
        },
        "identity": {
            "binding_id": BINDING_ID,
            "evidence_sha256": EVIDENCE_SHA256,
            "finalization_digest": FINALIZATION_DIGEST,
            "namespace_id": NAMESPACE_ID,
            "principal_id": PRINCIPAL_ID,
        },
        "network": {
            "astrbot_webui": "127.0.0.1:6185",
            "core": "127.0.0.1:18081",
            "core_external_listener": False,
            "gateway_core_allow": "127.0.0.1/32",
            "qq_gateway": "unix:/run/myuna-gateway/qq-owner.sock",
        },
        "operation": OPERATION,
        "rate_and_context": {
            "history_characters": 12000,
            "history_messages": 12,
            "history_persistence": "process-memory-only",
            "requests_per_ten_minutes": 12,
        },
        "rollback": {
            "database_function": True,
            "runtime_files": True,
            "services": True,
        },
        "services": {
            "astrbot_llm_disabled": True,
            "auto_start": False,
            "core": "myuna-core@qq.service",
            "memory_worker": False,
            "runtime_socket": "myuna-qq-owner-runtime-dev.socket",
        },
        "source": {
            "bundle_sha256": _bundle_sha256(hashes),
            "core_commit": _git_value(CORE_REPO, "rev-parse", "HEAD"),
            "deploy_commit": _git_value(DEPLOY_REPO, "rev-parse", "HEAD"),
        },
    }


def activation_digest(plan: dict[str, object]) -> str:
    return sha256(canonical_json(plan)).hexdigest()


def _owner_state() -> str:
    return _psql(
        f"""
SELECT concat_ws('|',
    principal.principal_status,
    namespace.namespace_status,
    binding.binding_status,
    binding.verified_at IS NOT NULL,
    binding.metadata ->> 'finalization_approval_digest',
    binding.metadata ->> 'verification_evidence_sha256'
)
FROM myuna_identity.principal AS principal
JOIN memory.memory_namespace AS namespace
  ON namespace.owner_principal_id = principal.principal_id
JOIN myuna_identity.account_binding AS binding
  ON binding.principal_id = principal.principal_id
 AND binding.namespace_id = namespace.namespace_id
WHERE principal.principal_id = '{PRINCIPAL_ID}'
  AND namespace.namespace_id = '{NAMESPACE_ID}'
  AND binding.binding_id = '{BINDING_ID}';
"""
    )


def _migration_state() -> str:
    return _psql(
        f"""
SELECT concat_ws('|',
    to_regprocedure('gateway_runtime.resolve_verified_binding(text,text)') IS NOT NULL,
    (SELECT count(*) FROM myuna_admin.schema_migration
     WHERE migration_version = '{MIGRATION_VERSION}')
);
"""
    )


def _unit_active(unit: str) -> bool:
    return (
        _run(["systemctl", "is-active", "--quiet", unit], check=False).returncode
        == 0
    )


def ensure_preconditions() -> None:
    if os.geteuid() != 0:
        raise RuntimeActivationError("run as root from the local server console")
    if _git_value(CORE_REPO, "status", "--porcelain"):
        raise RuntimeActivationError("Core repository must be clean")
    if _git_value(DEPLOY_REPO, "status", "--porcelain"):
        raise RuntimeActivationError("deploy repository must be clean")
    expected_owner = (
        f"active|active|verified|t|{FINALIZATION_DIGEST}|{EVIDENCE_SHA256}"
    )
    if _owner_state() != expected_owner:
        raise RuntimeActivationError("verified owner identity precondition failed")
    if _migration_state() != "f|0":
        raise RuntimeActivationError("QQ runtime database migration already exists")
    for unit in (
        "myuna-core@dev.service",
        "myuna-retrieval-worker-dev.service",
        "myuna-channel-gateway-dev.service",
        "myuna-channel-gateway-dev.socket",
        "myuna-core@qq.service",
        "myuna-qq-owner-runtime-dev.service",
        "myuna-qq-owner-runtime-dev.socket",
    ):
        if _unit_active(unit):
            raise RuntimeActivationError(f"service must be inactive: {unit}")
    ensure_channel_healthy()
    for path in (
        RUNTIME_CONFIG_PATH,
        RUNTIME_MARKER_PATH,
        CORE_TOKEN_PATH,
        CORE_ENV_PATH,
        CORE_MANIFEST_PATH,
        FINAL_RECEIPT_PATH,
        RUNTIME_SOCKET_PATH,
    ):
        if path.exists():
            raise RuntimeActivationError("QQ owner runtime gate is not clean")
    deepseek_secret = Path("/etc/myuna/secrets/deepseek-api-key")
    if not deepseek_secret.is_file() or deepseek_secret.stat().st_mode & 0o077:
        raise RuntimeActivationError("DeepSeek credential is missing or has unsafe permissions")
    if not Path("/srv/myuna/environments/dev/definition/current").is_dir():
        raise RuntimeActivationError("approved v5 Definition pointer is missing")


def _install_file(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    _run(
        [
            "install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            f"{mode:04o}",
            str(source),
            str(destination),
        ]
    )


def _install_runtime_files(digest: str, token: str) -> None:
    gateway_gid = pwd.getpwnam("myuna-gateway").pw_gid
    myuna_gid = pwd.getpwnam("myuna").pw_gid
    Path("/var/lib/myuna/qq").mkdir(parents=True, exist_ok=True)
    Path("/var/log/myuna/qq").mkdir(parents=True, exist_ok=True)
    shutil.chown("/var/lib/myuna/qq", user="myuna", group="myuna")
    shutil.chown("/var/log/myuna/qq", user="myuna", group="myuna")

    _install_file(
        DEPLOY_REPO / "config/capabilities/dev-v5.json",
        CORE_MANIFEST_PATH,
        0o644,
    )
    _write_atomic(
        CORE_ENV_PATH,
        (DEPLOY_REPO / "config/qq-owner-v5.env").read_bytes(),
        mode=0o640,
        uid=0,
        gid=myuna_gid,
    )
    _write_atomic(
        CORE_TOKEN_PATH,
        (token + "\n").encode("ascii"),
        mode=0o600,
        uid=0,
        gid=0,
    )
    _install_file(
        DEPLOY_REPO / "scripts/qq_owner_runtime_gateway.py",
        INSTALLED_RUNNER_PATH,
        0o755,
    )
    plugin_source = DEPLOY_REPO / "channels/astrbot-qq/plugin/myuna_gateway"
    plugin_runtime = Path(
        "/srv/myuna/channel-adapters/astrbot_plugin_myuna_gateway/v1"
    )
    for name in ("main.py", "protocol.py"):
        _install_file(plugin_source / name, plugin_runtime / name, 0o644)
    _install_file(
        DEPLOY_REPO / "systemd/myuna-core-qq-credentials.conf",
        CORE_DROPIN_PATH,
        0o644,
    )
    _install_file(
        DEPLOY_REPO / "systemd/myuna-qq-owner-runtime-dev.service",
        RUNTIME_SERVICE_PATH,
        0o644,
    )
    _install_file(
        DEPLOY_REPO / "systemd/myuna-qq-owner-runtime-dev.socket",
        RUNTIME_SOCKET_UNIT_PATH,
        0o644,
    )
    runtime_config = {
        "binding_id": BINDING_ID,
        "channel_instance": "napcat-dev",
        "core_host": "127.0.0.1",
        "core_port": 18081,
        "evidence_sha256": EVIDENCE_SHA256,
        "finalization_digest": FINALIZATION_DIGEST,
        "max_history_characters": 12000,
        "max_history_messages": 12,
        "max_requests_per_ten_minutes": 12,
        "namespace_id": NAMESPACE_ID,
        "principal_id": PRINCIPAL_ID,
    }
    _write_atomic(
        RUNTIME_CONFIG_PATH,
        (json.dumps(runtime_config, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o640,
        uid=0,
        gid=gateway_gid,
    )
    _write_atomic(
        RUNTIME_MARKER_PATH,
        (digest + "\n").encode("ascii"),
        mode=0o644,
        uid=0,
        gid=0,
    )


def _apply_migration() -> None:
    _run(
        [str(DEPLOY_REPO / "database/scripts/apply_migrations.sh")],
        timeout=180,
    )
    verification = _psql(
        """
SELECT concat_ws('|',
    to_regprocedure('gateway_runtime.resolve_verified_binding(text,text)') IS NOT NULL,
    has_function_privilege(
        'myuna_gateway_app',
        'gateway_runtime.resolve_verified_binding(text,text)',
        'EXECUTE'
    ),
    NOT has_table_privilege(
        'myuna_gateway_app',
        'myuna_identity.account_binding',
        'SELECT'
    ),
    (SELECT count(*) = 1
     FROM myuna_identity.account_binding AS binding
     CROSS JOIN LATERAL gateway_runtime.resolve_verified_binding(
         binding.channel_kind,
         binding.account_fingerprint
     ) AS resolved
     WHERE binding.binding_id = 'binding-astrbot-qq-owner-cealana'
       AND resolved.binding_id = binding.binding_id
       AND resolved.principal_id = binding.principal_id
       AND resolved.namespace_id = binding.namespace_id)
);
"""
    )
    if verification != "t|t|t|t":
        raise RuntimeActivationError("QQ owner runtime migration verification failed")


def _rollback_migration(migration_sha256: str) -> None:
    _psql(
        f"""
BEGIN;
SET ROLE myuna_dev_owner;
REVOKE ALL ON FUNCTION gateway_runtime.resolve_verified_binding(text, text)
FROM myuna_gateway_app, PUBLIC;
DROP FUNCTION gateway_runtime.resolve_verified_binding(text, text);
DELETE FROM myuna_admin.schema_migration
WHERE migration_version = '{MIGRATION_VERSION}'
  AND migration_sha256 = :'migration_sha256';
RESET ROLE;
COMMIT;
""",
        {"migration_sha256": migration_sha256},
    )


def _wait_core_ready(timeout_seconds: int = 45) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        connection = HTTPConnection("127.0.0.1", 18081, timeout=3)
        try:
            connection.request("GET", "/readyz")
            response = connection.getresponse()
            raw = response.read(8192)
            if response.status == 200:
                payload = json.loads(raw.decode("utf-8"))
                if isinstance(payload, dict) and payload.get("status") == "ready":
                    return
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass
        finally:
            connection.close()
        time.sleep(1)
    raise RuntimeActivationError("myuna-core@qq did not become ready")


def _wait_container_healthy(name: str, timeout_seconds: int = 90) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = _run(
            [
                "docker",
                "inspect",
                "--format={{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
                name,
            ],
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip() == "running|healthy":
            return
        time.sleep(2)
    raise RuntimeActivationError("AstrBot container did not become healthy")


def _start_runtime() -> None:
    _run(["systemctl", "daemon-reload"])
    for unit in (
        "myuna-core@qq.service",
        "myuna-qq-owner-runtime-dev.socket",
        "myuna-qq-owner-runtime-dev.service",
    ):
        _run(["systemctl", "disable", unit], check=False)
    _run(["systemctl", "start", "myuna-core@qq.service"])
    _wait_core_ready()
    _run(["systemctl", "start", "myuna-qq-owner-runtime-dev.socket"])
    compose = DEPLOY_REPO / "channels/astrbot-qq/compose.dev.yml"
    _run(
        [
            "docker",
            "compose",
            "--env-file",
            "/etc/myuna-gateway/astrbot-napcat-dev.env",
            "-f",
            str(compose),
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            "astrbot",
        ],
        timeout=180,
    )
    _wait_container_healthy("myuna-astrbot-dev")
    if not RUNTIME_SOCKET_PATH.is_socket():
        raise RuntimeActivationError("QQ runtime socket is missing")


def _remove_runtime_files() -> None:
    _run(
        [
            "systemctl",
            "stop",
            "myuna-qq-owner-runtime-dev.socket",
            "myuna-qq-owner-runtime-dev.service",
            "myuna-core@qq.service",
        ],
        check=False,
    )
    for path in (
        RUNTIME_MARKER_PATH,
        RUNTIME_CONFIG_PATH,
        CORE_TOKEN_PATH,
        CORE_ENV_PATH,
        CORE_MANIFEST_PATH,
        FINAL_RECEIPT_PATH,
        INSTALLED_RUNNER_PATH,
        CORE_DROPIN_PATH,
        RUNTIME_SERVICE_PATH,
        RUNTIME_SOCKET_UNIT_PATH,
    ):
        path.unlink(missing_ok=True)
    try:
        CORE_DROPIN_DIR.rmdir()
    except OSError:
        pass
    _run(["systemctl", "daemon-reload"], check=False)


def _postconditions() -> None:
    if _owner_state() != (
        f"active|active|verified|t|{FINALIZATION_DIGEST}|{EVIDENCE_SHA256}"
    ):
        raise RuntimeActivationError("owner identity changed unexpectedly")
    if _migration_state() != "t|1":
        raise RuntimeActivationError("QQ runtime migration postcondition failed")
    if not _unit_active("myuna-core@qq.service"):
        raise RuntimeActivationError("myuna-core@qq is not active")
    if not _unit_active("myuna-qq-owner-runtime-dev.socket"):
        raise RuntimeActivationError("QQ runtime socket is not active")
    for unit in (
        "myuna-core@dev.service",
        "myuna-retrieval-worker-dev.service",
        "myuna-channel-gateway-dev.service",
        "myuna-channel-gateway-dev.socket",
    ):
        if _unit_active(unit):
            raise RuntimeActivationError("an excluded dev service became active")
    _wait_core_ready(timeout_seconds=5)
    ensure_channel_healthy()
    if _run(
        ["systemctl", "is-enabled", "--quiet", "myuna-core@qq.service"],
        check=False,
    ).returncode == 0:
        raise RuntimeActivationError("myuna-core@qq must remain disabled at boot")
    if _run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            "myuna-qq-owner-runtime-dev.socket",
        ],
        check=False,
    ).returncode == 0:
        raise RuntimeActivationError("QQ runtime socket must remain disabled at boot")


def public_receipt(
    *,
    digest: str,
    plan: dict[str, object],
    backups: list[dict[str, str]],
) -> dict[str, object]:
    return {
        "auto_start_enabled": False,
        "binding_id": BINDING_ID,
        "core_service": "active",
        "finalization_digest": FINALIZATION_DIGEST,
        "group_chat": False,
        "memory_read": False,
        "memory_write": False,
        "model_provider": "deepseek",
        "namespace_id": NAMESPACE_ID,
        "operation": OPERATION,
        "plan_digest": digest,
        "principal_id": PRINCIPAL_ID,
        "result": "qq-owner-private-runtime-ready-for-first-live-test",
        "runtime_socket": "active",
        "source_bundle_sha256": plan["source"]["bundle_sha256"],  # type: ignore[index]
        "tools": False,
        "verified_backups": [
            {
                "filename": record["filename"],
                "label": record["label"],
                "sha256": record["sha256"],
            }
            for record in backups
        ],
    }


def preview_payload(plan: dict[str, object], *, checked: bool) -> dict[str, object]:
    return {
        "apply_requested": False,
        "plan": plan,
        "plan_digest": activation_digest(plan),
        "preconditions_checked": checked,
        "preconditions_passed": checked,
        "result": "preview-only-no-writes",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approved-plan-digest")
    parser.add_argument("--check-preconditions", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise RuntimeActivationError("run as root from the local server console")
    plan = build_activation_plan()
    digest = activation_digest(plan)
    if not args.apply:
        if args.check_preconditions:
            ensure_preconditions()
        print(
            json.dumps(
                preview_payload(plan, checked=args.check_preconditions),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if not args.approved_plan_digest or not hmac.compare_digest(
        args.approved_plan_digest,
        digest,
    ):
        raise RuntimeActivationError("QQ runtime plan digest does not match user approval")

    ensure_preconditions()
    run_stamp = datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    run_root = BACKUP_ROOT / run_stamp
    windows_root = WINDOWS_BACKUP_ROOT / f"Owner-QQ-Runtime-v1-{run_stamp}"
    migration_sha256 = _sha256_file(MIGRATION_PATH)
    migration_applied = False
    succeeded = False
    token = secrets.token_urlsafe(48)
    try:
        pre_backup = create_verified_backup("pre", run_root)
        _apply_migration()
        migration_applied = True
        _install_runtime_files(digest, token)
        _start_runtime()
        _postconditions()
        post_backup = create_verified_backup("post", run_root)
        copied_pre = copy_backup_to_windows(pre_backup, windows_root)
        copied_post = copy_backup_to_windows(post_backup, windows_root)
        receipt = public_receipt(
            digest=digest,
            plan=plan,
            backups=[copied_pre, copied_post],
        )
        _write_atomic(
            FINAL_RECEIPT_PATH,
            (json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
            mode=0o600,
            uid=0,
            gid=0,
        )
        print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
        succeeded = True
    finally:
        token = ""
        if not succeeded:
            _remove_runtime_files()
            if migration_applied or _migration_state() == "t|1":
                _rollback_migration(migration_sha256)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeActivationError, subprocess.SubprocessError) as exc:
        print(f"QQ owner runtime activation rejected: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
