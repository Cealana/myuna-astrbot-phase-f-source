#!/usr/bin/env python3
from __future__ import annotations

import getpass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


CHANNEL_KIND = "astrbot_qq"
IDENTITY_PEPPER_PATH = Path("/etc/myuna-gateway/secrets/identity-pepper-v1")
PRINCIPAL_ID = "principal-owner-cealana"
NAMESPACE_ID = "ns-owner-cealana-private"
BINDING_ID = "binding-astrbot-qq-owner-cealana"
_QQ_ACCOUNT = re.compile(r"^[1-9][0-9]{4,19}$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


class PreviewError(RuntimeError):
    pass


def account_fingerprint(stable_account_id: str, pepper: bytes) -> str:
    if _QQ_ACCOUNT.fullmatch(stable_account_id) is None:
        raise PreviewError("QQ stable account ID must contain 5-20 digits and not start with zero")
    if len(pepper) < 32:
        raise PreviewError("identity pepper must contain at least 32 bytes")
    message = f"myuna-account-v1\0{CHANNEL_KIND}\0{stable_account_id}".encode("utf-8")
    return hmac.new(pepper, message, sha256).hexdigest()


def read_root_secret(path: Path = IDENTITY_PEPPER_PATH) -> bytes:
    try:
        metadata = path.stat()
    except FileNotFoundError as exc:
        raise PreviewError(f"identity pepper is missing: {path}") from exc
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PreviewError("identity pepper must be root-owned with mode 0600")
    secret = path.read_bytes().strip()
    if len(secret) < 32:
        raise PreviewError("identity pepper must contain at least 32 bytes")
    return secret


def build_preview_sql(fingerprint: str) -> str:
    if _FINGERPRINT.fullmatch(fingerprint) is None:
        raise PreviewError("account fingerprint must be lowercase SHA-256 hex")
    return f"""\
\\set ON_ERROR_STOP on
BEGIN;
SET ROLE myuna_dev_owner;

INSERT INTO myuna_identity.principal (
    principal_id,
    principal_kind,
    authority_level,
    display_name,
    principal_status,
    metadata
)
VALUES (
    '{PRINCIPAL_ID}',
    'owner',
    'owner',
    'Cealana',
    'pending',
    '{{"source": "owner-binding-preview", "real": true}}'::jsonb
);

INSERT INTO memory.memory_namespace (
    namespace_id,
    owner_principal_id,
    namespace_kind,
    namespace_status,
    policy_version,
    metadata
)
VALUES (
    '{NAMESPACE_ID}',
    '{PRINCIPAL_ID}',
    'personal',
    'pending',
    'memory-policy-v1.0',
    '{{"source": "owner-binding-preview", "real": true}}'::jsonb
);

INSERT INTO myuna_identity.account_binding (
    binding_id,
    principal_id,
    channel_kind,
    account_fingerprint,
    binding_status,
    namespace_id,
    metadata
)
VALUES (
    '{BINDING_ID}',
    '{PRINCIPAL_ID}',
    '{CHANNEL_KIND}',
    '{fingerprint}',
    'pending',
    '{NAMESPACE_ID}',
    '{{"source": "owner-binding-preview", "activation": "qq-private-challenge"}}'::jsonb
);

SELECT
    principal.principal_id,
    principal.principal_status,
    namespace.namespace_id,
    namespace.namespace_status,
    binding.binding_id,
    binding.channel_kind,
    binding.binding_status,
    left(binding.account_fingerprint, 8) || '...' || right(binding.account_fingerprint, 8)
        AS account_fingerprint_preview
FROM myuna_identity.principal AS principal
JOIN memory.memory_namespace AS namespace
  ON namespace.owner_principal_id = principal.principal_id
JOIN myuna_identity.account_binding AS binding
  ON binding.principal_id = principal.principal_id
 AND binding.namespace_id = namespace.namespace_id
WHERE principal.principal_id = '{PRINCIPAL_ID}';

RESET ROLE;
ROLLBACK;

SELECT
    (SELECT count(*) FROM myuna_identity.principal
     WHERE principal_id = '{PRINCIPAL_ID}') AS principal_rows_after_rollback,
    (SELECT count(*) FROM memory.memory_namespace
     WHERE namespace_id = '{NAMESPACE_ID}') AS namespace_rows_after_rollback,
    (SELECT count(*) FROM myuna_identity.account_binding
     WHERE binding_id = '{BINDING_ID}') AS binding_rows_after_rollback;
"""


def public_plan_summary(fingerprint: str) -> dict[str, object]:
    if _FINGERPRINT.fullmatch(fingerprint) is None:
        raise PreviewError("account fingerprint must be lowercase SHA-256 hex")
    private_plan = {
        "binding_id": BINDING_ID,
        "channel_kind": CHANNEL_KIND,
        "fingerprint": fingerprint,
        "namespace_id": NAMESPACE_ID,
        "principal_id": PRINCIPAL_ID,
    }
    plan_digest = sha256(
        json.dumps(private_plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "binding_id": BINDING_ID,
        "channel_kind": CHANNEL_KIND,
        "fingerprint_preview": f"{fingerprint[:8]}...{fingerprint[-8:]}",
        "namespace_id": NAMESPACE_ID,
        "plan_digest": plan_digest,
        "principal_id": PRINCIPAL_ID,
        "result": "transaction-preview-rolled-back",
        "writes_committed": False,
    }


def ensure_services_stopped() -> None:
    for unit in (
        "myuna-core@dev.service",
        "myuna-retrieval-worker-dev.service",
        "myuna-channel-gateway-dev.service",
    ):
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", unit],
            check=False,
        )
        if result.returncode == 0:
            raise PreviewError(f"service must be stopped before owner preview: {unit}")


def run_preview(sql: str, fingerprint: str) -> str:
    result = subprocess.run(
        [
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "--dbname",
            "myuna_dev",
            "--no-psqlrc",
            "--set",
            "ON_ERROR_STOP=1",
        ],
        input=sql,
        text=True,
        capture_output=True,
        check=False,
    )
    combined = result.stdout + result.stderr
    if fingerprint in combined:
        raise PreviewError("refusing output because it contains a full account fingerprint")
    if result.returncode != 0:
        raise PreviewError("owner binding transaction preview failed")
    return result.stdout


def main() -> int:
    if os.geteuid() != 0:
        raise PreviewError("run as root from a local interactive terminal")
    if not sys.stdin.isatty():
        raise PreviewError("refusing non-interactive owner account input")

    ensure_services_stopped()
    pepper = read_root_secret()
    first = getpass.getpass("Owner QQ stable account ID (hidden): ")
    second = getpass.getpass("Repeat owner QQ stable account ID (hidden): ")
    if not hmac.compare_digest(first, second):
        raise PreviewError("the two account ID entries do not match")

    fingerprint = account_fingerprint(first, pepper)
    first = ""
    second = ""
    sql = build_preview_sql(fingerprint)
    output = run_preview(sql, fingerprint)
    print(output.rstrip())
    print(json.dumps(public_plan_summary(fingerprint), ensure_ascii=False, indent=2))
    print("Preview only: all identity rows were rolled back; no real binding was committed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PreviewError as exc:
        print(f"owner binding preview rejected: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
