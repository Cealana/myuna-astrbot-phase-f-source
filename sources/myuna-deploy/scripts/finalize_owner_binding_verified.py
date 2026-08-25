#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

try:
    from scripts.apply_owner_binding_pending import (
        ACTIVATION_PATH,
        APPROVED_PLAN_DIGEST as PENDING_APPROVAL_DIGEST,
        BINDING_ID,
        CHALLENGE_CODE_PATH,
        CONFIG_PATH,
        EVIDENCE_PATH,
        NAMESPACE_ID,
        PRINCIPAL_ID,
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
        ACTIVATION_PATH,
        APPROVED_PLAN_DIGEST as PENDING_APPROVAL_DIGEST,
        BINDING_ID,
        CHALLENGE_CODE_PATH,
        CONFIG_PATH,
        EVIDENCE_PATH,
        NAMESPACE_ID,
        PRINCIPAL_ID,
        _psql,
        _run,
        _sha256_file,
        _write_atomic,
        copy_backup_to_windows,
        create_verified_backup,
        ensure_channel_healthy,
    )


FINALIZER_VERSION = "owner-binding-finalizer-v1"
LINUX_BACKUP_ROOT = Path("/var/backups/postgresql/myuna/owner-binding-final-v1")
WINDOWS_BACKUP_ROOT = Path(
    "/mnt/c/Server-Critical-Backup/Myuna/Database-Logical-Latest"
)
FINAL_RECEIPT_PATH = Path(
    "/var/lib/myuna-gateway/owner-binding-final-v1-receipt.json"
)
CHALLENGE_UNITS = (
    "myuna-channel-gateway-dev.socket",
    "myuna-channel-gateway-dev.service",
)
RUNTIME_UNITS_THAT_MUST_BE_INACTIVE = (
    "myuna-core@dev.service",
    "myuna-retrieval-worker-dev.service",
    *CHALLENGE_UNITS,
)


class OwnerFinalizationError(RuntimeError):
    pass


def canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def load_verified_evidence() -> tuple[dict[str, str], str]:
    if not EVIDENCE_PATH.is_file():
        raise OwnerFinalizationError("verified owner challenge evidence is missing")
    stat = EVIDENCE_PATH.stat()
    gateway_uid = pwd.getpwnam("myuna-gateway").pw_uid
    if stat.st_uid not in (0, gateway_uid) or stat.st_mode & 0o077:
        raise OwnerFinalizationError("owner challenge evidence permissions are unsafe")
    try:
        payload = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise OwnerFinalizationError("owner challenge evidence is unreadable") from None
    expected = {
        "binding_id": BINDING_ID,
        "namespace_id": NAMESPACE_ID,
        "plan_digest": PENDING_APPROVAL_DIGEST,
        "principal_id": PRINCIPAL_ID,
        "result": "qq-private-challenge-matched",
    }
    if not isinstance(payload, dict) or any(payload.get(k) != v for k, v in expected.items()):
        raise OwnerFinalizationError("owner challenge evidence does not match the pending plan")
    for key in ("event_id", "trace_id", "verified_at"):
        if not isinstance(payload.get(key), str) or not payload[key]:
            raise OwnerFinalizationError("owner challenge evidence is incomplete")
    try:
        verified_at = datetime.fromisoformat(payload["verified_at"])
    except ValueError:
        raise OwnerFinalizationError("owner challenge evidence timestamp is invalid") from None
    if verified_at.tzinfo is None or verified_at > datetime.now(timezone.utc):
        raise OwnerFinalizationError("owner challenge evidence timestamp is unsafe")
    return {str(k): str(v) for k, v in payload.items()}, _sha256_file(EVIDENCE_PATH)


def build_finalization_plan(evidence_sha256: str) -> dict[str, object]:
    return {
        "backup_policy": {
            "c_drive_verified_copy": True,
            "post_commit": True,
            "pre_commit": True,
        },
        "challenge_cleanup": [
            "stop_challenge_socket_and_service",
            "remove_one_time_challenge_code",
            "remove_challenge_config",
            "remove_activation_marker",
        ],
        "changes": [
            {
                "from": "pending",
                "id": PRINCIPAL_ID,
                "record": "principal",
                "to": "active",
            },
            {
                "from": "pending",
                "id": NAMESPACE_ID,
                "record": "namespace",
                "to": "active",
            },
            {
                "from": "pending",
                "id": BINDING_ID,
                "record": "binding",
                "to": "verified",
            },
        ],
        "evidence_sha256": evidence_sha256,
        "finalizer_version": FINALIZER_VERSION,
        "no_activation": {
            "core": True,
            "memory_worker": True,
            "model": True,
            "tools": True,
        },
        "operation": "finalize-owner-qq-private-binding",
        "pending_approval_digest": PENDING_APPROVAL_DIGEST,
    }


def finalization_digest(plan: dict[str, object]) -> str:
    return sha256(canonical_json(plan)).hexdigest()


def _pending_state() -> str:
    return _psql(
        f"""
SELECT concat_ws('|',
    principal.principal_status,
    namespace.namespace_status,
    binding.binding_status,
    coalesce(binding.verified_at::text, 'NULL'),
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


def _accepted_evidence_state(event_id: str) -> str:
    return _psql(
        """
SELECT concat_ws('|', count(*),
    count(*) FILTER (
        WHERE processing_state = 'accepted'
          AND outcome_code = 'owner_challenge_matched'
    )
)
FROM gateway_runtime.inbound_event
WHERE channel_kind = 'astrbot_qq'
  AND event_id = :'event_id';
""",
        {"event_id": event_id},
    )


def ensure_runtime_inactive() -> None:
    for unit in RUNTIME_UNITS_THAT_MUST_BE_INACTIVE:
        result = _run(["systemctl", "is-active", "--quiet", unit], check=False)
        if result.returncode == 0:
            raise OwnerFinalizationError(f"service must be inactive before finalization: {unit}")


def ensure_finalization_preconditions(evidence: dict[str, str]) -> None:
    ensure_runtime_inactive()
    ensure_channel_healthy()
    expected = f"pending|pending|pending|NULL|astrbot_qq|{NAMESPACE_ID}"
    if _pending_state() != expected:
        raise OwnerFinalizationError("pending owner identity precondition failed")
    if _accepted_evidence_state(evidence["event_id"]) != "1|1":
        raise OwnerFinalizationError("durable accepted challenge evidence is missing")
    for path in (CHALLENGE_CODE_PATH, CONFIG_PATH, ACTIVATION_PATH):
        if not path.is_file():
            raise OwnerFinalizationError("one-time challenge gate is incomplete")
    if FINAL_RECEIPT_PATH.exists():
        raise OwnerFinalizationError("owner binding was already finalized")


def build_commit_sql() -> str:
    return f"""\
\\set ON_ERROR_STOP on
BEGIN;
SET ROLE myuna_dev_owner;

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM myuna_identity.principal
WHERE principal_id = '{PRINCIPAL_ID}'
  AND principal_status = 'pending'
  AND metadata ->> 'approval_digest' = :'pending_plan_digest';

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM memory.memory_namespace
WHERE namespace_id = '{NAMESPACE_ID}'
  AND owner_principal_id = '{PRINCIPAL_ID}'
  AND namespace_status = 'pending'
  AND metadata ->> 'approval_digest' = :'pending_plan_digest';

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM myuna_identity.account_binding
WHERE binding_id = '{BINDING_ID}'
  AND principal_id = '{PRINCIPAL_ID}'
  AND namespace_id = '{NAMESPACE_ID}'
  AND binding_status = 'pending'
  AND verified_at IS NULL
  AND metadata ->> 'approval_digest' = :'pending_plan_digest';

UPDATE myuna_identity.principal
SET principal_status = 'active',
    metadata = metadata || jsonb_build_object(
        'finalization_approval_digest', :'finalization_digest',
        'verification_evidence_sha256', :'evidence_sha256'
    )
WHERE principal_id = '{PRINCIPAL_ID}'
  AND principal_status = 'pending';

UPDATE memory.memory_namespace
SET namespace_status = 'active',
    metadata = metadata || jsonb_build_object(
        'finalization_approval_digest', :'finalization_digest',
        'verification_evidence_sha256', :'evidence_sha256'
    )
WHERE namespace_id = '{NAMESPACE_ID}'
  AND owner_principal_id = '{PRINCIPAL_ID}'
  AND namespace_status = 'pending';

UPDATE myuna_identity.account_binding
SET binding_status = 'verified',
    verified_at = :'verified_at'::timestamptz,
    metadata = metadata || jsonb_build_object(
        'finalization_approval_digest', :'finalization_digest',
        'verification', 'qq-private-challenge',
        'verification_evidence_sha256', :'evidence_sha256'
    )
WHERE binding_id = '{BINDING_ID}'
  AND principal_id = '{PRINCIPAL_ID}'
  AND namespace_id = '{NAMESPACE_ID}'
  AND binding_status = 'pending'
  AND verified_at IS NULL;

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM myuna_identity.principal AS principal
JOIN memory.memory_namespace AS namespace
  ON namespace.owner_principal_id = principal.principal_id
JOIN myuna_identity.account_binding AS binding
  ON binding.principal_id = principal.principal_id
 AND binding.namespace_id = namespace.namespace_id
WHERE principal.principal_id = '{PRINCIPAL_ID}'
  AND principal.principal_status = 'active'
  AND namespace.namespace_id = '{NAMESPACE_ID}'
  AND namespace.namespace_status = 'active'
  AND binding.binding_id = '{BINDING_ID}'
  AND binding.binding_status = 'verified'
  AND binding.verified_at = :'verified_at'::timestamptz
  AND principal.metadata ->> 'finalization_approval_digest' = :'finalization_digest'
  AND namespace.metadata ->> 'finalization_approval_digest' = :'finalization_digest'
  AND binding.metadata ->> 'finalization_approval_digest' = :'finalization_digest';

RESET ROLE;
COMMIT;
"""


def build_compensating_rollback_sql() -> str:
    return f"""\
\\set ON_ERROR_STOP on
BEGIN;
SET ROLE myuna_dev_owner;

UPDATE myuna_identity.account_binding
SET binding_status = 'pending',
    verified_at = NULL,
    metadata = metadata
        - 'finalization_approval_digest'
        - 'verification'
        - 'verification_evidence_sha256'
WHERE binding_id = '{BINDING_ID}'
  AND binding_status = 'verified'
  AND metadata ->> 'finalization_approval_digest' = :'finalization_digest';

UPDATE memory.memory_namespace
SET namespace_status = 'pending',
    metadata = metadata
        - 'finalization_approval_digest'
        - 'verification_evidence_sha256'
WHERE namespace_id = '{NAMESPACE_ID}'
  AND namespace_status = 'active'
  AND metadata ->> 'finalization_approval_digest' = :'finalization_digest';

UPDATE myuna_identity.principal
SET principal_status = 'pending',
    metadata = metadata
        - 'finalization_approval_digest'
        - 'verification_evidence_sha256'
WHERE principal_id = '{PRINCIPAL_ID}'
  AND principal_status = 'active'
  AND metadata ->> 'finalization_approval_digest' = :'finalization_digest';

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM myuna_identity.principal AS principal
JOIN memory.memory_namespace AS namespace
  ON namespace.owner_principal_id = principal.principal_id
JOIN myuna_identity.account_binding AS binding
  ON binding.principal_id = principal.principal_id
 AND binding.namespace_id = namespace.namespace_id
WHERE principal.principal_id = '{PRINCIPAL_ID}'
  AND principal.principal_status = 'pending'
  AND namespace.namespace_id = '{NAMESPACE_ID}'
  AND namespace.namespace_status = 'pending'
  AND binding.binding_id = '{BINDING_ID}'
  AND binding.binding_status = 'pending'
  AND binding.verified_at IS NULL;

RESET ROLE;
COMMIT;
"""


def _active_state() -> str:
    return _psql(
        f"""
SELECT concat_ws('|',
    principal.principal_status,
    namespace.namespace_status,
    binding.binding_status,
    CASE WHEN binding.verified_at IS NULL THEN 'NULL' ELSE 'SET' END
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


def cleanup_one_time_challenge_gate() -> None:
    _run(["systemctl", "stop", *CHALLENGE_UNITS], check=False)
    for path in (CHALLENGE_CODE_PATH, CONFIG_PATH, ACTIVATION_PATH):
        path.unlink(missing_ok=True)


def public_receipt(
    *,
    evidence_sha256: str,
    digest: str,
    verified_at: str,
    backups: list[dict[str, str]],
) -> dict[str, object]:
    return {
        "binding_id": BINDING_ID,
        "binding_status": "verified",
        "challenge_evidence_retained": True,
        "challenge_gate_cleaned": True,
        "core_activated": False,
        "evidence_sha256": evidence_sha256,
        "finalization_digest": digest,
        "finalizer_version": FINALIZER_VERSION,
        "memory_activated": False,
        "model_activated": False,
        "namespace_id": NAMESPACE_ID,
        "namespace_status": "active",
        "principal_id": PRINCIPAL_ID,
        "principal_status": "active",
        "result": "owner-binding-finalized-no-runtime-activation",
        "tools_activated": False,
        "verified_at": verified_at,
        "verified_backups": [
            {
                "filename": record["filename"],
                "label": record["label"],
                "sha256": record["sha256"],
            }
            for record in backups
        ],
    }


def preview_payload(
    plan: dict[str, object], *, preconditions_checked: bool
) -> dict[str, object]:
    return {
        "apply_requested": False,
        "finalization_digest": finalization_digest(plan),
        "plan": plan,
        "preconditions_checked": preconditions_checked,
        "preconditions_passed": preconditions_checked,
        "result": "preview-only-no-writes",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approved-finalization-digest")
    parser.add_argument("--check-preconditions", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise OwnerFinalizationError("run as root from the local server console")
    evidence, evidence_sha256 = load_verified_evidence()
    plan = build_finalization_plan(evidence_sha256)
    digest = finalization_digest(plan)
    if not args.apply:
        if args.check_preconditions:
            ensure_finalization_preconditions(evidence)
        print(
            json.dumps(
                preview_payload(
                    plan,
                    preconditions_checked=args.check_preconditions,
                ),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if not args.approved_finalization_digest or not hmac.compare_digest(
        args.approved_finalization_digest, digest
    ):
        raise OwnerFinalizationError("finalization digest does not match user approval")

    ensure_finalization_preconditions(evidence)
    run_stamp = datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    run_root = LINUX_BACKUP_ROOT / run_stamp
    windows_root = WINDOWS_BACKUP_ROOT / f"Owner-Binding-Final-v1-{run_stamp}"
    committed = False
    succeeded = False
    try:
        pre_backup = create_verified_backup("pre", run_root)
        _psql(
            build_commit_sql(),
            {
                "evidence_sha256": evidence_sha256,
                "finalization_digest": digest,
                "pending_plan_digest": PENDING_APPROVAL_DIGEST,
                "verified_at": evidence["verified_at"],
            },
        )
        committed = True
        if _active_state() != "active|active|verified|SET":
            raise OwnerFinalizationError("owner identity finalization postcondition failed")
        post_backup = create_verified_backup("post", run_root)
        copied_pre = copy_backup_to_windows(pre_backup, windows_root)
        copied_post = copy_backup_to_windows(post_backup, windows_root)
        cleanup_one_time_challenge_gate()
        receipt = public_receipt(
            evidence_sha256=evidence_sha256,
            digest=digest,
            verified_at=evidence["verified_at"],
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
        if committed and not succeeded:
            _psql(
                build_compensating_rollback_sql(),
                {"finalization_digest": digest},
            )
            if _pending_state() != f"pending|pending|pending|NULL|astrbot_qq|{NAMESPACE_ID}":
                raise OwnerFinalizationError("compensating rollback postcondition failed")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, OwnerFinalizationError, subprocess.SubprocessError) as exc:
        print(f"owner binding finalization rejected: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
