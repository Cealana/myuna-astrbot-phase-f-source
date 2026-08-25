#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json
import re
import secrets
from typing import Mapping


SCHEMA = "myuna.telegram-owner-discovery.v2"
CHANNEL_KIND = "astrbot_telegram"
BINDING_ID = "binding-astrbot-telegram-owner-cealana"
PRINCIPAL_ID = "principal-owner-cealana"
NAMESPACE_ID = "ns-owner-cealana-private"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TelegramBindingRejected(RuntimeError):
    """Content-free rejection for a fail-closed Owner binding ceremony."""


def canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class DiscoveryEvidence:
    account_fingerprint: str
    discovered_at: datetime
    expires_at: datetime
    evidence_sha256: str

    @classmethod
    def from_payload(
        cls,
        payload: object,
        *,
        evidence_sha256: str,
        now: datetime,
    ) -> "DiscoveryEvidence":
        required = {
            "account_fingerprint",
            "channel_kind",
            "discovery_command_challenge_stored",
            "discovery_command_was_scoped",
            "discovered_at",
            "expires_at",
            "raw_account_id_stored",
            "result",
            "schema",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise TelegramBindingRejected("Telegram binding evidence rejected")
        if (
            payload["schema"] != SCHEMA
            or payload["channel_kind"] != CHANNEL_KIND
            or payload["result"] != "telegram-private-start-discovered"
            or payload["raw_account_id_stored"] is not False
            or payload["discovery_command_challenge_stored"] is not False
            or payload["discovery_command_was_scoped"] is not True
        ):
            raise TelegramBindingRejected("Telegram binding evidence rejected")
        fingerprint = payload["account_fingerprint"]
        if not isinstance(fingerprint, str) or _SHA256.fullmatch(fingerprint) is None:
            raise TelegramBindingRejected("Telegram binding evidence rejected")
        if _SHA256.fullmatch(evidence_sha256) is None:
            raise TelegramBindingRejected("Telegram binding evidence rejected")
        try:
            discovered_at = datetime.fromisoformat(str(payload["discovered_at"]))
            expires_at = datetime.fromisoformat(str(payload["expires_at"]))
        except ValueError:
            raise TelegramBindingRejected("Telegram binding evidence rejected") from None
        if (
            discovered_at.tzinfo is None
            or expires_at.tzinfo is None
            or now.tzinfo is None
            or discovered_at > now
            or expires_at <= now
            or expires_at <= discovered_at
        ):
            raise TelegramBindingRejected("Telegram binding evidence rejected")
        return cls(
            account_fingerprint=fingerprint,
            discovered_at=discovered_at.astimezone(timezone.utc),
            expires_at=expires_at.astimezone(timezone.utc),
            evidence_sha256=evidence_sha256,
        )

    @property
    def fingerprint_preview(self) -> str:
        return (
            f"{self.account_fingerprint[:8]}"
            f"...{self.account_fingerprint[-8:]}"
        )


def build_pending_plan(evidence: DiscoveryEvidence) -> dict[str, object]:
    return {
        "binding": {
            "account_fingerprint": evidence.account_fingerprint,
            "binding_id": BINDING_ID,
            "channel_kind": CHANNEL_KIND,
            "initial_status": "pending",
            "namespace_id": NAMESPACE_ID,
            "principal_id": PRINCIPAL_ID,
        },
        "capabilities": {
            "group_chat": False,
            "memory_read": False,
            "memory_write": False,
            "model": False,
            "plain_text_private_only": True,
            "tools": False,
            "vision": False,
        },
        "discovery_evidence_sha256": evidence.evidence_sha256,
        "operation": "telegram-owner-binding-pending-v1",
        "raw_account_id_stored": False,
    }


def plan_digest(plan: Mapping[str, object]) -> str:
    return sha256(canonical_json(dict(plan))).hexdigest()


def public_pending_preview(evidence: DiscoveryEvidence) -> dict[str, object]:
    private_plan = build_pending_plan(evidence)
    return {
        "binding_id": BINDING_ID,
        "channel_kind": CHANNEL_KIND,
        "discovery_evidence_sha256": evidence.evidence_sha256,
        "fingerprint_preview": evidence.fingerprint_preview,
        "namespace_id": NAMESPACE_ID,
        "operation": private_plan["operation"],
        "plan_digest": plan_digest(private_plan),
        "principal_id": PRINCIPAL_ID,
        "raw_account_id_stored": False,
        "result": "preview-only-no-writes",
    }


def build_pending_insert_sql() -> str:
    return f"""\
\\set ON_ERROR_STOP on
BEGIN;
SET ROLE myuna_dev_owner;

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM myuna_identity.principal
WHERE principal_id = '{PRINCIPAL_ID}'
  AND principal_kind = 'owner'
  AND authority_level = 'owner'
  AND principal_status = 'active';

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM memory.memory_namespace
WHERE namespace_id = '{NAMESPACE_ID}'
  AND owner_principal_id = '{PRINCIPAL_ID}'
  AND namespace_status = 'active';

SELECT 1 / CASE WHEN count(*) = 0 THEN 1 ELSE 0 END
FROM myuna_identity.account_binding
WHERE binding_id = '{BINDING_ID}'
   OR channel_kind = '{CHANNEL_KIND}';

INSERT INTO myuna_identity.account_binding (
    binding_id,
    principal_id,
    namespace_id,
    channel_kind,
    account_fingerprint,
    binding_status,
    metadata
)
VALUES (
    '{BINDING_ID}',
    '{PRINCIPAL_ID}',
    '{NAMESPACE_ID}',
    '{CHANNEL_KIND}',
    :'account_fingerprint',
    'pending',
    jsonb_build_object(
        'approval_digest', :'approved_plan_digest',
        'discovery_evidence_sha256', :'discovery_evidence_sha256',
        'raw_account_id_stored', false,
        'verification', 'telegram-private-challenge-pending'
    )
);

RESET ROLE;
COMMIT;
"""


def build_one_time_challenge(
    evidence: DiscoveryEvidence,
    *,
    approved_plan_digest: str,
    now: datetime,
) -> tuple[dict[str, object], str]:
    expected = plan_digest(build_pending_plan(evidence))
    if not compare_approval(approved_plan_digest, expected):
        raise TelegramBindingRejected("Telegram challenge plan rejected")
    if now.tzinfo is None:
        raise TelegramBindingRejected("Telegram challenge plan rejected")
    challenge_code = f"MYUNA-TG-{secrets.token_urlsafe(24)}"
    expires_at = min(
        evidence.expires_at,
        now.astimezone(timezone.utc).replace(microsecond=0)
        + (evidence.expires_at - evidence.discovered_at) / 2,
    )
    if expires_at <= now.astimezone(timezone.utc):
        raise TelegramBindingRejected("Telegram challenge plan rejected")
    config = {
        "account_fingerprint": evidence.account_fingerprint,
        "binding_id": BINDING_ID,
        "challenge_sha256": sha256(challenge_code.encode("utf-8")).hexdigest(),
        "channel_instance": "telegram-owner-dev",
        "expires_at": expires_at.isoformat(timespec="seconds"),
        "namespace_id": NAMESPACE_ID,
        "plan_digest": approved_plan_digest,
        "principal_id": PRINCIPAL_ID,
    }
    return config, challenge_code


def build_finalization_plan(
    *,
    pending_plan_digest: str,
    challenge_evidence_sha256: str,
) -> dict[str, object]:
    for value in (pending_plan_digest, challenge_evidence_sha256):
        if _SHA256.fullmatch(value) is None:
            raise TelegramBindingRejected("Telegram finalization plan rejected")
    return {
        "binding_id": BINDING_ID,
        "challenge_evidence_sha256": challenge_evidence_sha256,
        "changes": [
            {
                "from": "pending",
                "record": "account_binding",
                "to": "verified",
            }
        ],
        "existing_namespace_unchanged": True,
        "existing_principal_unchanged": True,
        "operation": "telegram-owner-binding-finalization-v1",
        "pending_plan_digest": pending_plan_digest,
        "runtime_activation": False,
    }


def build_finalization_sql() -> str:
    return f"""\
\\set ON_ERROR_STOP on
BEGIN;
SET ROLE myuna_dev_owner;

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM myuna_identity.account_binding
WHERE binding_id = '{BINDING_ID}'
  AND principal_id = '{PRINCIPAL_ID}'
  AND namespace_id = '{NAMESPACE_ID}'
  AND channel_kind = '{CHANNEL_KIND}'
  AND binding_status = 'pending'
  AND verified_at IS NULL
  AND metadata ->> 'approval_digest' = :'pending_plan_digest'
  AND metadata ->> 'discovery_evidence_sha256' = :'discovery_evidence_sha256';

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM gateway_runtime.inbound_event
WHERE channel_kind = '{CHANNEL_KIND}'
  AND event_id = :'challenge_event_id'
  AND processing_state = 'accepted'
  AND outcome_code = 'owner_challenge_matched';

UPDATE myuna_identity.account_binding
SET binding_status = 'verified',
    verified_at = :'verified_at'::timestamptz,
    metadata = metadata || jsonb_build_object(
        'finalization_approval_digest', :'finalization_digest',
        'verification', 'telegram-private-challenge',
        'verification_evidence_sha256', :'challenge_evidence_sha256'
    )
WHERE binding_id = '{BINDING_ID}'
  AND binding_status = 'pending';

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM myuna_identity.account_binding
WHERE binding_id = '{BINDING_ID}'
  AND principal_id = '{PRINCIPAL_ID}'
  AND namespace_id = '{NAMESPACE_ID}'
  AND channel_kind = '{CHANNEL_KIND}'
  AND binding_status = 'verified'
  AND verified_at = :'verified_at'::timestamptz
  AND metadata ->> 'finalization_approval_digest' = :'finalization_digest';

RESET ROLE;
COMMIT;
"""


def compare_approval(supplied: str, expected: str) -> bool:
    return (
        _SHA256.fullmatch(supplied) is not None
        and _SHA256.fullmatch(expected) is not None
        and hmac.compare_digest(supplied, expected)
    )
