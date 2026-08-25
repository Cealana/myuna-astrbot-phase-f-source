#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import getpass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

try:
    from scripts.preview_owner_binding import (
        BINDING_ID,
        CHANNEL_KIND,
        IDENTITY_PEPPER_PATH,
        NAMESPACE_ID,
        PRINCIPAL_ID,
        account_fingerprint,
        public_plan_summary,
        read_root_secret,
    )
except ModuleNotFoundError:
    from preview_owner_binding import (  # type: ignore[no-redef]
        BINDING_ID,
        CHANNEL_KIND,
        IDENTITY_PEPPER_PATH,
        NAMESPACE_ID,
        PRINCIPAL_ID,
        account_fingerprint,
        public_plan_summary,
        read_root_secret,
    )


APPROVED_PLAN_DIGEST = "e2658ee4e54a665b55007820d8c733cf3720fde60a3c24a1c12c8a4df6fe1dee"
BACKUP_SCRIPT = Path("/srv/myuna/repos/deploy/database/scripts/backup_dev.sh")
LINUX_BACKUP_ROOT = Path("/var/backups/postgresql/myuna/owner-binding-v1")
WINDOWS_BACKUP_ROOT = Path(
    "/mnt/c/Server-Critical-Backup/Myuna/Database-Logical-Latest"
)
CONFIG_PATH = Path("/etc/myuna-gateway/owner-challenge-v1.json")
ACTIVATION_PATH = Path("/etc/myuna-gateway/activation-approved")
CHALLENGE_CODE_PATH = Path(
    "/etc/myuna-gateway/secrets/owner-challenge-code-v1"
)
EVIDENCE_PATH = Path("/var/lib/myuna-gateway/owner-challenge-v1-evidence.json")
RECEIPT_PATH = Path("/var/lib/myuna-gateway/owner-binding-pending-v1-receipt.json")
SOCKET_PATH = Path("/run/myuna-gateway/challenge.sock")


class PendingApplyError(RuntimeError):
    pass


def _run(
    command: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise PendingApplyError("approved pending owner operation failed closed")
    return result


def build_commit_sql() -> str:
    return f"""\
\\set ON_ERROR_STOP on
BEGIN;
SET ROLE myuna_dev_owner;

INSERT INTO myuna_identity.principal (
    principal_id, principal_kind, authority_level, display_name,
    principal_status, metadata
)
VALUES (
    '{PRINCIPAL_ID}', 'owner', 'owner', 'Cealana', 'pending',
    jsonb_build_object(
        'source', 'owner-binding-approved',
        'real', true,
        'approval_digest', :'plan_digest'
    )
);

INSERT INTO memory.memory_namespace (
    namespace_id, owner_principal_id, namespace_kind, namespace_status,
    policy_version, metadata
)
VALUES (
    '{NAMESPACE_ID}', '{PRINCIPAL_ID}', 'personal', 'pending',
    'memory-policy-v1.0',
    jsonb_build_object(
        'source', 'owner-binding-approved',
        'real', true,
        'approval_digest', :'plan_digest'
    )
);

INSERT INTO myuna_identity.account_binding (
    binding_id, principal_id, channel_kind, account_fingerprint,
    binding_status, namespace_id, metadata
)
VALUES (
    '{BINDING_ID}', '{PRINCIPAL_ID}', '{CHANNEL_KIND}', :'fingerprint',
    'pending', '{NAMESPACE_ID}',
    jsonb_build_object(
        'source', 'owner-binding-approved',
        'activation', 'qq-private-challenge',
        'approval_digest', :'plan_digest'
    )
);

RESET ROLE;
COMMIT;
"""


def build_rollback_sql() -> str:
    return f"""\
\\set ON_ERROR_STOP on
BEGIN;
SET ROLE myuna_dev_owner;

DELETE FROM myuna_identity.account_binding
WHERE binding_id = '{BINDING_ID}'
  AND binding_status = 'pending'
  AND metadata ->> 'approval_digest' = :'plan_digest';

DELETE FROM memory.memory_namespace
WHERE namespace_id = '{NAMESPACE_ID}'
  AND namespace_status = 'pending'
  AND metadata ->> 'approval_digest' = :'plan_digest';

DELETE FROM myuna_identity.principal
WHERE principal_id = '{PRINCIPAL_ID}'
  AND principal_status = 'pending'
  AND metadata ->> 'approval_digest' = :'plan_digest';

RESET ROLE;
COMMIT;
"""


def _psql(sql: str, variables: dict[str, str] | None = None) -> str:
    command = [
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "--dbname=myuna_dev",
        "--no-psqlrc",
        "--no-align",
        "--tuples-only",
        "--set=ON_ERROR_STOP=1",
    ]
    for key, value in (variables or {}).items():
        command.append(f"--set={key}={value}")
    try:
        return _run(command, input_text=sql + "\n").stdout.strip()
    except PendingApplyError:
        raise PendingApplyError("database transaction failed closed") from None


def _identity_counts() -> str:
    return _psql(
        "SELECT count(*) - 1, "
        "(SELECT count(*) - 1 FROM memory.memory_namespace), "
        "(SELECT count(*) FROM myuna_identity.account_binding) "
        "FROM myuna_identity.principal;"
    )


def _pending_state() -> str:
    return _psql(
        f"""
SELECT concat_ws('|',
    principal.principal_status,
    namespace.namespace_status,
    binding.binding_status,
    binding.channel_kind,
    binding.namespace_id
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


def ensure_runtime_gate_clean() -> None:
    for unit in (
        "myuna-core@dev.service",
        "myuna-retrieval-worker-dev.service",
        "myuna-channel-gateway-dev.service",
        "myuna-channel-gateway-dev.socket",
    ):
        result = _run(["systemctl", "is-active", "--quiet", unit], check=False)
        if result.returncode == 0:
            raise PendingApplyError(f"service must be inactive before pending apply: {unit}")

    for path in (
        CONFIG_PATH,
        ACTIVATION_PATH,
        CHALLENGE_CODE_PATH,
        EVIDENCE_PATH,
        RECEIPT_PATH,
        SOCKET_PATH,
    ):
        if path.exists():
            raise PendingApplyError("owner challenge gate is not clean")

    if _identity_counts() != "0|0|0":
        raise PendingApplyError("real identity rows already exist")


def ensure_channel_healthy() -> None:
    if _run(
        ["systemctl", "is-active", "--quiet", "myuna-astrbot-qq-dev.service"],
        check=False,
    ).returncode != 0:
        raise PendingApplyError("AstrBot/NapCat channel stack is not active")
    for container in ("myuna-astrbot-dev", "myuna-napcat-dev"):
        result = _run(
            [
                "docker",
                "inspect",
                "--format={{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
                container,
            ]
        ).stdout.strip()
        if result != "running|healthy":
            raise PendingApplyError("AstrBot/NapCat channel container is not healthy")


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_verified_backup(label: str, run_root: Path) -> dict[str, str]:
    destination = run_root / label
    try:
        result = _run([str(BACKUP_SCRIPT), str(destination)], timeout=300)
    except PendingApplyError:
        raise PendingApplyError(f"{label} database backup creation failed") from None
    dump_path = Path(result.stdout.strip())
    if not dump_path.is_file() or dump_path.parent != destination:
        raise PendingApplyError("database backup path validation failed")
    sidecar = Path(str(dump_path) + ".sha256")
    if not sidecar.is_file():
        raise PendingApplyError("database backup checksum is missing")
    try:
        _run(["sha256sum", "--check", str(sidecar)], timeout=120)
        _run(
            ["runuser", "-u", "postgres", "--", "pg_restore", "--list", str(dump_path)]
        )
    except PendingApplyError:
        raise PendingApplyError(f"{label} database backup verification failed") from None
    return {
        "label": label,
        "linux_path": str(dump_path),
        "filename": dump_path.name,
        "sha256": _sha256_file(dump_path),
    }


def copy_backup_to_windows(record: dict[str, str], windows_root: Path) -> dict[str, str]:
    source = Path(record["linux_path"])
    windows_root.mkdir(parents=True, exist_ok=True)
    destination = windows_root / f"{record['label']}-{source.name}"
    shutil.copy2(source, destination)
    copied_hash = _sha256_file(destination)
    if not hmac.compare_digest(copied_hash, record["sha256"]):
        raise PendingApplyError("C drive backup verification failed")
    checksum_path = Path(str(destination) + ".sha256")
    checksum_path.write_text(
        f"{copied_hash}  {destination.name}\n",
        encoding="ascii",
    )
    return {**record, "windows_path": str(destination)}


def _write_atomic(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _gateway_gid() -> int:
    return int(_run(["id", "-g", "myuna-gateway"]).stdout.strip())


def provision_challenge(
    *,
    fingerprint: str,
    plan_digest: str,
) -> tuple[str, datetime]:
    challenge_code = "MYUNA-OWNER-" + secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    config = {
        "account_fingerprint": fingerprint,
        "binding_id": BINDING_ID,
        "challenge_sha256": sha256(challenge_code.encode("utf-8")).hexdigest(),
        "expires_at": expires_at.isoformat(timespec="seconds"),
        "namespace_id": NAMESPACE_ID,
        "plan_digest": plan_digest,
        "principal_id": PRINCIPAL_ID,
    }
    _write_atomic(
        CHALLENGE_CODE_PATH,
        (challenge_code + "\n").encode("utf-8"),
        mode=0o600,
        uid=0,
        gid=0,
    )
    _write_atomic(
        CONFIG_PATH,
        (json.dumps(config, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        mode=0o640,
        uid=0,
        gid=_gateway_gid(),
    )
    _write_atomic(
        ACTIVATION_PATH,
        (plan_digest + "\n").encode("ascii"),
        mode=0o644,
        uid=0,
        gid=0,
    )
    return challenge_code, expires_at


def cleanup_challenge_gate() -> None:
    _run(
        [
            "systemctl",
            "stop",
            "myuna-channel-gateway-dev.socket",
            "myuna-channel-gateway-dev.service",
        ],
        check=False,
    )
    for path in (
        SOCKET_PATH,
        EVIDENCE_PATH,
        ACTIVATION_PATH,
        CONFIG_PATH,
        CHALLENGE_CODE_PATH,
        RECEIPT_PATH,
    ):
        path.unlink(missing_ok=True)


def rollback_pending_rows(plan_digest: str) -> None:
    _psql(build_rollback_sql(), {"plan_digest": plan_digest})
    if _identity_counts() != "0|0|0":
        raise PendingApplyError("automatic pending rollback did not restore the zero-row gate")


def public_receipt(
    *,
    fingerprint: str,
    expires_at: datetime,
    backups: list[dict[str, str]],
) -> dict[str, object]:
    return {
        "binding_id": BINDING_ID,
        "binding_status": "pending",
        "challenge_expires_at": expires_at.isoformat(timespec="seconds"),
        "challenge_socket": "active",
        "core_activated": False,
        "fingerprint_preview": f"{fingerprint[:8]}...{fingerprint[-8:]}",
        "memory_activated": False,
        "model_activated": False,
        "namespace_id": NAMESPACE_ID,
        "namespace_status": "pending",
        "plan_digest": APPROVED_PLAN_DIGEST,
        "principal_id": PRINCIPAL_ID,
        "principal_status": "pending",
        "result": "pending-owner-committed-challenge-ready",
        "tools_activated": False,
        "verified_backups": [
            {
                "filename": record["filename"],
                "label": record["label"],
                "sha256": record["sha256"],
            }
            for record in backups
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved-plan-digest", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise PendingApplyError("run as root from the local server console")
    if not sys.stdin.isatty():
        raise PendingApplyError("refusing non-interactive owner account input")
    if not hmac.compare_digest(args.approved_plan_digest, APPROVED_PLAN_DIGEST):
        raise PendingApplyError("approval digest does not match the recorded user approval")

    ensure_runtime_gate_clean()
    ensure_channel_healthy()
    pepper = read_root_secret(IDENTITY_PEPPER_PATH)
    first = getpass.getpass("Owner QQ stable account ID (hidden): ")
    second = getpass.getpass("Repeat owner QQ stable account ID (hidden): ")
    if not hmac.compare_digest(first, second):
        raise PendingApplyError("the two account ID entries do not match")
    fingerprint = account_fingerprint(first, pepper)
    first = ""
    second = ""
    summary = public_plan_summary(fingerprint)
    if not hmac.compare_digest(str(summary["plan_digest"]), APPROVED_PLAN_DIGEST):
        raise PendingApplyError("entered account does not match the approved plan digest")

    run_stamp = datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    run_root = LINUX_BACKUP_ROOT / run_stamp
    windows_root = WINDOWS_BACKUP_ROOT / f"Owner-Binding-v1-{run_stamp}"
    committed = False
    succeeded = False
    challenge_code = ""
    try:
        pre_backup = create_verified_backup("pre", run_root)
        _psql(
            build_commit_sql(),
            {"fingerprint": fingerprint, "plan_digest": APPROVED_PLAN_DIGEST},
        )
        committed = True
        if _pending_state() != f"pending|pending|pending|{CHANNEL_KIND}|{NAMESPACE_ID}":
            raise PendingApplyError("pending identity postcondition failed")

        challenge_code, expires_at = provision_challenge(
            fingerprint=fingerprint,
            plan_digest=APPROVED_PLAN_DIGEST,
        )
        _run(["systemctl", "start", "myuna-channel-gateway-dev.socket"])
        if _run(
            ["systemctl", "is-active", "--quiet", "myuna-channel-gateway-dev.socket"],
            check=False,
        ).returncode != 0 or not SOCKET_PATH.is_socket():
            raise PendingApplyError("owner challenge socket did not become active")

        post_backup = create_verified_backup("post", run_root)
        copied_pre = copy_backup_to_windows(pre_backup, windows_root)
        copied_post = copy_backup_to_windows(post_backup, windows_root)
        receipt = public_receipt(
            fingerprint=fingerprint,
            expires_at=expires_at,
            backups=[copied_pre, copied_post],
        )
        _write_atomic(
            RECEIPT_PATH,
            (json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
            mode=0o600,
            uid=0,
            gid=0,
        )
        print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
        print("Challenge code was generated but not printed. Use the clipboard helper next.")
        succeeded = True
    finally:
        challenge_code = ""
        if not succeeded:
            cleanup_challenge_gate()
            if committed:
                rollback_pending_rows(APPROVED_PLAN_DIGEST)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PendingApplyError, subprocess.SubprocessError) as exc:
        print(f"pending owner apply rejected: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
