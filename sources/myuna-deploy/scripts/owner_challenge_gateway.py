#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile

from myuna_core.channel_gateway import GatewayEnvelopeError, SignedChannelEnvelope, sign_channel_event
from myuna_core.identity import account_fingerprint


CONFIG_PATH = Path("/etc/myuna-gateway/owner-challenge-v1.json")
EVIDENCE_PATH = Path("/var/lib/myuna-gateway/owner-challenge-v1-evidence.json")
_SAFE_ID = re.compile(r"^[a-z][a-z0-9._-]{2,127}$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_MAX_REQUEST_BYTES = 32768


class ChallengeRejected(PermissionError):
    """Fail-closed challenge rejection without identity or content detail."""


def _audit_stage(code: str) -> None:
    """Emit only a fixed operational stage code; never include event values."""

    print(f"owner challenge gateway stage={code}", flush=True)


@dataclass(frozen=True, slots=True)
class ChallengeConfig:
    binding_id: str
    principal_id: str
    namespace_id: str
    account_fingerprint: str
    plan_digest: str
    challenge_sha256: str
    expires_at: datetime

    @classmethod
    def from_payload(cls, payload: object) -> "ChallengeConfig":
        required = {
            "account_fingerprint",
            "binding_id",
            "challenge_sha256",
            "expires_at",
            "namespace_id",
            "plan_digest",
            "principal_id",
        }
        if not isinstance(payload, dict) or set(payload) != required:
            raise ChallengeRejected("challenge rejected")
        for key in ("binding_id", "namespace_id", "principal_id"):
            if not isinstance(payload[key], str) or _SAFE_ID.fullmatch(payload[key]) is None:
                raise ChallengeRejected("challenge rejected")
        for key in ("account_fingerprint", "challenge_sha256", "plan_digest"):
            if not isinstance(payload[key], str) or _FINGERPRINT.fullmatch(payload[key]) is None:
                raise ChallengeRejected("challenge rejected")
        raw_expiry = payload["expires_at"]
        if not isinstance(raw_expiry, str):
            raise ChallengeRejected("challenge rejected")
        try:
            expiry = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
        except ValueError:
            raise ChallengeRejected("challenge rejected") from None
        if expiry.tzinfo is None or expiry.utcoffset() is None:
            raise ChallengeRejected("challenge rejected")
        return cls(
            binding_id=payload["binding_id"],
            principal_id=payload["principal_id"],
            namespace_id=payload["namespace_id"],
            account_fingerprint=payload["account_fingerprint"],
            plan_digest=payload["plan_digest"],
            challenge_sha256=payload["challenge_sha256"],
            expires_at=expiry.astimezone(timezone.utc),
        )


@dataclass(frozen=True, slots=True)
class ChallengeDecision:
    matched: bool
    event_id: str
    channel_kind: str
    channel_instance: str
    occurred_at: datetime
    nonce_fingerprint: str
    payload_sha256: str
    trace_id: str


def _load_protected_json(path: Path) -> object:
    try:
        metadata = path.stat()
        mode = stat.S_IMODE(metadata.st_mode)
        if metadata.st_uid != 0 or mode & 0o027:
            raise ChallengeRejected("challenge rejected")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ChallengeRejected("challenge rejected") from None


def _read_credential(name: str) -> bytes:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        raise ChallengeRejected("challenge rejected")
    try:
        secret = (Path(directory) / name).read_bytes().strip()
    except OSError:
        raise ChallengeRejected("challenge rejected") from None
    if len(secret) < 32:
        raise ChallengeRejected("challenge rejected")
    return secret


def evaluate_challenge(
    payload: object,
    *,
    config: ChallengeConfig,
    signing_secret: bytes,
    identity_pepper: bytes,
    now: datetime,
) -> ChallengeDecision:
    try:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock is not timezone-aware")
        current = now.astimezone(timezone.utc)
        if current >= config.expires_at:
            raise ChallengeRejected("challenge rejected")

        envelope = SignedChannelEnvelope.from_payload(payload)
        expected_signature = sign_channel_event(envelope.event, signing_secret)
        if not hmac.compare_digest(envelope.signature, expected_signature):
            raise ChallengeRejected("challenge rejected")
        event = envelope.event
        if event.occurred_at < current - timedelta(minutes=5):
            raise ChallengeRejected("challenge rejected")
        if event.occurred_at > current + timedelta(seconds=30):
            raise ChallengeRejected("challenge rejected")
        if event.conversation_kind != "private":
            raise ChallengeRejected("challenge rejected")
        if event.delivery_capabilities != ("text",):
            raise ChallengeRejected("challenge rejected")
        consent = event.consent_context
        if consent.memory_candidate or consent.tools or consent.media_processing:
            raise ChallengeRejected("challenge rejected")

        fingerprint = account_fingerprint(event.channel, event.actor_account_id, identity_pepper)
        challenge_hash = sha256(event.message_text.strip().encode("utf-8")).hexdigest()
        matched = hmac.compare_digest(fingerprint, config.account_fingerprint) and hmac.compare_digest(
            challenge_hash,
            config.challenge_sha256,
        )
        canonical_envelope = json.dumps(
            envelope.as_payload(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        nonce_fingerprint = sha256(
            b"myuna-channel-nonce-v1\0" + event.nonce.encode("ascii")
        ).hexdigest()
        return ChallengeDecision(
            matched=matched,
            event_id=event.event_id,
            channel_kind=event.channel,
            channel_instance=event.channel_instance,
            occurred_at=event.occurred_at,
            nonce_fingerprint=nonce_fingerprint,
            payload_sha256=sha256(canonical_envelope).hexdigest(),
            trace_id=event.trace_id,
        )
    except (GatewayEnvelopeError, ChallengeRejected, TypeError, ValueError):
        raise ChallengeRejected("challenge rejected") from None


def _psql_scalar(sql: str, variables: dict[str, str]) -> str:
    command = [
        "/usr/bin/psql",
        "--dbname=myuna_dev",
        "--username=myuna_gateway_app",
        "--host=/var/run/postgresql",
        "--no-psqlrc",
        "--no-align",
        "--tuples-only",
        "--set=ON_ERROR_STOP=1",
    ]
    for key, value in variables.items():
        command.append(f"--set={key}={value}")
    result = subprocess.run(
        command,
        input=sql + "\n",
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        if "No such file or directory" in result.stderr:
            _audit_stage("psql_socket_missing")
        elif "Permission denied" in result.stderr:
            _audit_stage("psql_permission_denied")
        elif "Peer authentication failed" in result.stderr:
            _audit_stage("psql_peer_rejected")
        else:
            _audit_stage("psql_backend_rejected")
        raise ChallengeRejected("challenge rejected")
    return result.stdout.strip()


def claim_inbound(decision: ChallengeDecision, now: datetime) -> bool:
    expires_at = now.astimezone(timezone.utc) + timedelta(minutes=9)
    result = _psql_scalar(
        "SELECT gateway_runtime.claim_inbound_event("
        ":'channel_kind', :'channel_instance', :'event_id', :'nonce_fingerprint', "
        ":'payload_sha256', :'occurred_at'::timestamptz, :'expires_at'::timestamptz);",
        {
            "channel_kind": decision.channel_kind,
            "channel_instance": decision.channel_instance,
            "event_id": decision.event_id,
            "nonce_fingerprint": decision.nonce_fingerprint,
            "payload_sha256": decision.payload_sha256,
            "occurred_at": decision.occurred_at.isoformat(timespec="microseconds"),
            "expires_at": expires_at.isoformat(timespec="microseconds"),
        },
    )
    return result == "t"


def record_outcome(decision: ChallengeDecision, outcome: str, code: str) -> bool:
    result = _psql_scalar(
        "SELECT gateway_runtime.record_inbound_outcome("
        ":'channel_kind', :'channel_instance', :'event_id', :'outcome', :'code');",
        {
            "channel_kind": decision.channel_kind,
            "channel_instance": decision.channel_instance,
            "event_id": decision.event_id,
            "outcome": outcome,
            "code": code,
        },
    )
    return result == "t"


def write_evidence(config: ChallengeConfig, decision: ChallengeDecision, now: datetime) -> None:
    EVIDENCE_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    evidence = {
        "binding_id": config.binding_id,
        "event_id": decision.event_id,
        "namespace_id": config.namespace_id,
        "plan_digest": config.plan_digest,
        "principal_id": config.principal_id,
        "result": "qq-private-challenge-matched",
        "trace_id": decision.trace_id,
        "verified_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
    }
    descriptor: int | None = None
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".owner-challenge-",
            dir=EVIDENCE_PATH.parent,
            text=True,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = None
            json.dump(evidence, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, EVIDENCE_PATH)
        temporary_name = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _read_request(connection: socket.socket) -> object:
    connection.settimeout(5)
    request = bytearray()
    while len(request) <= _MAX_REQUEST_BYTES:
        chunk = connection.recv(4096)
        if not chunk:
            break
        request.extend(chunk)
        if b"\n" in chunk:
            break
    if len(request) > _MAX_REQUEST_BYTES or b"\n" not in request:
        raise ChallengeRejected("challenge rejected")
    try:
        return json.loads(bytes(request).split(b"\n", 1)[0])
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ChallengeRejected("challenge rejected") from None


def _respond(connection: socket.socket, status: str) -> None:
    payload = {
        "code": "owner-challenge-accepted" if status == "accepted" else "owner-challenge-rejected",
        "status": status,
    }
    try:
        connection.sendall(json.dumps(payload, separators=(",", ":")).encode("ascii") + b"\n")
    except OSError:
        pass


def process_connection(
    connection: socket.socket,
    *,
    config: ChallengeConfig,
    signing_secret: bytes,
    identity_pepper: bytes,
) -> None:
    try:
        if EVIDENCE_PATH.exists():
            raise ChallengeRejected("challenge rejected")
        payload = _read_request(connection)
        now = datetime.now(timezone.utc)
        decision = evaluate_challenge(
            payload,
            config=config,
            signing_secret=signing_secret,
            identity_pepper=identity_pepper,
            now=now,
        )
        _audit_stage("envelope_verified")
        if not claim_inbound(decision, now):
            _audit_stage("durable_replay_rejected")
            raise ChallengeRejected("challenge rejected")
        _audit_stage("durable_claimed")
        if not decision.matched:
            record_outcome(decision, "rejected", "owner_challenge_mismatch")
            _audit_stage("challenge_mismatch")
            _respond(connection, "rejected")
            return
        if not record_outcome(decision, "accepted", "owner_challenge_matched"):
            raise ChallengeRejected("challenge rejected")
        write_evidence(config, decision, now)
        _audit_stage("challenge_accepted")
        _respond(connection, "accepted")
    except (ChallengeRejected, OSError, subprocess.SubprocessError):
        _audit_stage("generic_rejection")
        _respond(connection, "rejected")


def main() -> int:
    if os.geteuid() == 0:
        raise SystemExit("refusing to run owner challenge gateway as root")
    if int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise SystemExit("owner challenge gateway requires one systemd socket")
    config = ChallengeConfig.from_payload(_load_protected_json(CONFIG_PATH))
    signing_secret = _read_credential("channel-signing")
    identity_pepper = _read_credential("identity-pepper")
    _audit_stage("ready")
    with socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM) as server:
        while True:
            connection, _ = server.accept()
            with connection:
                process_connection(
                    connection,
                    config=config,
                    signing_secret=signing_secret,
                    identity_pepper=identity_pepper,
                )


if __name__ == "__main__":
    raise SystemExit(main())
