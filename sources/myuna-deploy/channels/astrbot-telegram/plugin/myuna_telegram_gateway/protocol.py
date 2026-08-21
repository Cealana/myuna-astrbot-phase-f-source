from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json
from pathlib import Path
import re
import secrets
import socket
from typing import Callable


SCHEMA_VERSION = "myuna.channel.v1"
CHANNEL_KIND = "astrbot_telegram"
GATEWAY_RESPONSE_SCHEMA = "myuna.gateway-response.v3"
LEGACY_GATEWAY_RESPONSE_SCHEMA = "myuna.gateway-response.v2"
DELIVERY_OUTCOME_SCHEMA = "myuna.telegram-delivery-outcome.v2"
VISUAL_EVENT_SCHEMA = "myuna.telegram-visual-evidence.v1"
VISUAL_EVENT_SOURCE = "gemini_visual_extraction"
VISUAL_PREFLIGHT_ROUTING = {
    "hybrid_external_generation": True,
    "visual_preflight": True,
}
CONTEXT_PROJECTION_UNAVAILABLE_CODES = {
    "external_summary_required",
    "external_turn_already_pending",
    "external_context_unavailable",
}
MAX_VISUAL_OBSERVATION_CHARACTERS = 240
SAFE_DEGRADATION_SCHEMA = "myuna.safe-degradation.v1"
RECOVERY_NOTICE_TEXT = (
    "\u521a\u624d\u7684\u670d\u52a1\u5f02\u5e38\u5df2\u7ecf\u6062\u590d\uff0c\u53ef\u4ee5\u7ee7\u7eed\u4f7f\u7528\u4e86\u3002"
)

_TELEGRAM_ACCOUNT = re.compile(r"^[1-9][0-9]{0,19}$")
_DIARY = re.compile(r"^/diary(?:[ \t]+([^\r\n]+))?$", re.IGNORECASE)
_BENCHMARK = re.compile(r"^/benchmark(?:[ \t]+([^\r\n]+))?$", re.IGNORECASE)
_BENCHMARK_CONFIRM = re.compile(r"^confirm[ \t]+([0-9a-f]{12})$", re.IGNORECASE)
_BENCHMARK_CANCEL = re.compile(r"^cancel[ \t]+([0-9a-f]{12})$", re.IGNORECASE)
_CHECK = re.compile(r"^/check(?:[ \t]+[^\r\n]+)?$", re.IGNORECASE)
_TEMPORAL = re.compile(r"^/temporal(?:[ \t]+[^\r\n]+)?$", re.IGNORECASE)
_MAX_DIARY_SOURCE_CHARACTERS = 3_500
_SAFE_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_DETAIL = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_SAFE_FINGERPRINT = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,383}$")
_RECOVERY_STATES = frozenset({"active", "recovering", "recovered"})
_DEGRADATION_CATEGORIES = frozenset(
    {
        "core_or_gateway_failure",
        "external_action_unavailable",
        "external_data_unavailable",
        "host_or_network_unreachable",
        "memory_no_evidence",
        "memory_service_failure",
        "memory_write_unavailable",
        "onebot_or_napcat_offline",
        "provider_budget_or_auth_failure",
        "provider_transient_failure",
        "reply_contract_rejected",
        "scheduled_notification_unavailable",
        "vision_unavailable",
    }
)
_MAX_RESPONSE_BYTES = 4096
_DELIVERY_TOKEN = re.compile(r"^[0-9a-f]{64}$")
_TRACE_ID = re.compile(r"^trace-[0-9a-f]{32}$")


class GatewayTransportError(RuntimeError):
    """Transport failure with no sender or message detail."""


def diary_command_is_explicit(message_text: object) -> bool:
    if not isinstance(message_text, str):
        return False
    candidate = message_text.strip()
    match = _DIARY.fullmatch(candidate)
    if match is None:
        return False
    parameter = match.group(1)
    return parameter is None or (
        bool(parameter.strip())
        and len(parameter.strip()) <= _MAX_DIARY_SOURCE_CHARACTERS
        and "\x00" not in parameter
    )


def benchmark_intent_grants_profile_consent(message_text: object) -> bool:
    """Mirror Core's exact Benchmark-only Profile mutation grammar."""

    if not isinstance(message_text, str):
        return False
    candidate = message_text.strip()
    match = _BENCHMARK.fullmatch(candidate)
    if match is None or match.group(1) is None:
        return False
    parameter = match.group(1).strip()
    if _BENCHMARK_CONFIRM.fullmatch(parameter) or _BENCHMARK_CANCEL.fullmatch(parameter):
        return True
    return bool(
        parameter
        and not parameter.casefold().startswith(("confirm", "cancel"))
        and len(parameter) <= _MAX_DIARY_SOURCE_CHARACTERS
        and "\x00" not in parameter
    )


def temporal_command_is_explicit(message_text: object) -> bool:
    return (
        isinstance(message_text, str)
        and _TEMPORAL.fullmatch(message_text.strip()) is not None
    )


def check_command_is_explicit(message_text: object) -> bool:
    """Mirror Core's exact, whole-message /Check command grammar."""

    return (
        isinstance(message_text, str)
        and _CHECK.fullmatch(message_text.strip()) is not None
    )


def should_forward_private_plain_text(
    *,
    sender_id: str,
    is_private_chat: bool,
    has_plain_text_only: bool,
    sender_is_bot: bool | None,
    message_text: str,
) -> bool:
    """Admit only non-bot private plain text from a valid Telegram account."""

    if not is_private_chat or not has_plain_text_only:
        return False
    if sender_is_bot is not False:
        return False
    if _TELEGRAM_ACCOUNT.fullmatch(sender_id) is None:
        return False
    if not message_text.strip() or len(message_text) > 4000:
        return False
    if not message_text.lstrip().startswith("/"):
        return True
    return (
        diary_command_is_explicit(message_text)
        or benchmark_intent_grants_profile_consent(message_text)
        or temporal_command_is_explicit(message_text)
        or check_command_is_explicit(message_text)
    )


def read_signing_secret(path: str | Path) -> bytes:
    try:
        secret = Path(path).read_bytes().strip()
    except OSError as exc:
        raise GatewayTransportError("gateway transport unavailable") from exc
    if len(secret) < 32:
        raise GatewayTransportError("gateway transport unavailable")
    return secret


def _opaque_id(secret: bytes, domain: bytes, value: str, prefix: str) -> str:
    digest = hmac.new(secret, domain + b"\0" + value.encode("utf-8"), sha256).hexdigest()
    return f"{prefix}-{digest[:40]}"


def _event_time(raw_timestamp: object, now: datetime) -> datetime:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("gateway clock must be timezone-aware")
    if isinstance(raw_timestamp, (int, float)) and not isinstance(raw_timestamp, bool):
        try:
            parsed = datetime.fromtimestamp(float(raw_timestamp), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            parsed = now
    else:
        parsed = now
    return parsed.astimezone(timezone.utc)


def build_signed_envelope(
    *,
    sender_id: str,
    message_text: str,
    message_id: object,
    raw_timestamp: object,
    signing_secret: bytes,
    channel_instance: str,
    now: datetime | None = None,
    nonce_factory: Callable[[], str] | None = None,
) -> dict[str, object]:
    if _TELEGRAM_ACCOUNT.fullmatch(sender_id) is None:
        raise ValueError("unsupported channel account")
    if not message_text.strip() or len(message_text) > 4000:
        raise ValueError("unsupported message")
    if len(signing_secret) < 32:
        raise ValueError("signing secret is invalid")
    if _SAFE_INSTANCE.fullmatch(channel_instance) is None:
        raise ValueError("channel instance is invalid")

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    occurred_at = _event_time(raw_timestamp, current)
    source_message_id = str(message_id) if message_id is not None else secrets.token_hex(24)
    nonce = (nonce_factory or (lambda: secrets.token_urlsafe(32)))()
    if re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce) is None:
        raise ValueError("nonce is invalid")

    event = {
        "actor_account_id": sender_id,
        "channel": CHANNEL_KIND,
        "channel_instance": channel_instance,
        "consent_context": {
            "media_processing": False,
            "memory_candidate": False,
            "tools": False,
        },
        "conversation_id": _opaque_id(
            signing_secret,
            b"myuna-telegram-private-conversation-v1",
            sender_id,
            "conv",
        ),
        "conversation_kind": "private",
        "delivery_capabilities": ["text"],
        "event_id": _opaque_id(
            signing_secret,
            b"myuna-telegram-event-v1",
            f"{sender_id}\0{source_message_id}",
            "evt",
        ),
        "message_parts": [{"text": message_text, "type": "text"}],
        "nonce": nonce,
        "reply_to": None,
        "schema_version": SCHEMA_VERSION,
        "timestamp": occurred_at.isoformat(timespec="microseconds"),
        "trace_id": f"trace-{secrets.token_hex(16)}",
    }
    canonical = json.dumps(
        event,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = hmac.new(
        signing_secret,
        b"myuna-channel-envelope-v1\0" + canonical,
        sha256,
    ).hexdigest()
    return {"event": event, "signature": signature}


def attach_signed_visual_event(
    envelope: dict[str, object],
    *,
    observation: str,
    caption_present: bool,
    signing_secret: bytes,
) -> dict[str, object]:
    if set(envelope) != {"event", "signature"}:
        raise ValueError("channel envelope is invalid")
    event_signature = envelope["signature"]
    if (
        not isinstance(event_signature, str)
        or re.fullmatch(r"[0-9a-f]{64}", event_signature) is None
    ):
        raise ValueError("channel envelope signature is invalid")
    if (
        not isinstance(observation, str)
        or not observation.strip()
        or "\x00" in observation
        or len(observation) > MAX_VISUAL_OBSERVATION_CHARACTERS
    ):
        raise ValueError("visual observation is invalid")
    if not isinstance(caption_present, bool):
        raise ValueError("caption presence is invalid")
    if len(signing_secret) < 32:
        raise ValueError("signing secret is invalid")
    visual_event: dict[str, object] = {
        "caption_present": caption_present,
        "observation": observation.strip(),
        "schema": VISUAL_EVENT_SCHEMA,
        "source": VISUAL_EVENT_SOURCE,
    }
    canonical = json.dumps(
        visual_event,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    visual_signature = hmac.new(
        signing_secret,
        b"myuna-telegram-visual-event-v1\0"
        + event_signature.encode("ascii")
        + b"\0"
        + canonical,
        sha256,
    ).hexdigest()
    return {
        "event": envelope["event"],
        "routing": {
            "hybrid_external_generation": True,
            "visual_event": visual_event,
            "visual_event_signature": visual_signature,
        },
        "signature": event_signature,
    }


def attach_visual_preflight(envelope: dict[str, object]) -> dict[str, object]:
    """Request a signed local readiness check before visual-provider egress."""

    if set(envelope) != {"event", "signature"}:
        raise ValueError("channel envelope is invalid")
    event_signature = envelope["signature"]
    if (
        not isinstance(event_signature, str)
        or re.fullmatch(r"[0-9a-f]{64}", event_signature) is None
    ):
        raise ValueError("channel envelope signature is invalid")
    return {
        "event": envelope["event"],
        "routing": dict(VISUAL_PREFLIGHT_ROUTING),
        "signature": event_signature,
    }


def _validate_degradation(payload: object) -> dict[str, object]:
    required = {
        "category",
        "fingerprint",
        "owner_action_required",
        "recovery_state",
        "reply",
        "retryable",
        "safe_detail_code",
        "schema",
        "status",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise GatewayTransportError("gateway transport unavailable")
    if payload.get("schema") != SAFE_DEGRADATION_SCHEMA:
        raise GatewayTransportError("gateway transport unavailable")
    if payload.get("status") != "degraded":
        raise GatewayTransportError("gateway transport unavailable")
    if payload.get("category") not in _DEGRADATION_CATEGORIES:
        raise GatewayTransportError("gateway transport unavailable")
    if payload.get("recovery_state") not in _RECOVERY_STATES:
        raise GatewayTransportError("gateway transport unavailable")
    if type(payload.get("retryable")) is not bool:
        raise GatewayTransportError("gateway transport unavailable")
    if type(payload.get("owner_action_required")) is not bool:
        raise GatewayTransportError("gateway transport unavailable")
    detail = payload.get("safe_detail_code")
    fingerprint = payload.get("fingerprint")
    reply = payload.get("reply")
    if not isinstance(detail, str) or _SAFE_DETAIL.fullmatch(detail) is None:
        raise GatewayTransportError("gateway transport unavailable")
    if not isinstance(fingerprint, str) or _SAFE_FINGERPRINT.fullmatch(fingerprint) is None:
        raise GatewayTransportError("gateway transport unavailable")
    if not isinstance(reply, str) or not reply.strip() or len(reply) > 512:
        raise GatewayTransportError("gateway transport unavailable")
    return dict(payload)


def decode_gateway_response(raw: bytes) -> dict[str, object]:
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayTransportError("gateway transport unavailable") from exc
    if not isinstance(decoded, dict):
        raise GatewayTransportError("gateway transport unavailable")

    keys = set(decoded)
    response_schema = decoded.get("schema")
    if response_schema in {GATEWAY_RESPONSE_SCHEMA, LEGACY_GATEWAY_RESPONSE_SCHEMA}:
        kind = decoded.get("kind")
        if (
            kind == "visual_preflight_ready"
            and response_schema == GATEWAY_RESPONSE_SCHEMA
            and keys == {"kind", "schema"}
        ):
            return {"kind": kind, "schema": response_schema}
        if (
            kind in {
                "visual_preflight_unavailable",
                "context_projection_unavailable",
            }
            and response_schema == GATEWAY_RESPONSE_SCHEMA
            and keys == {"kind", "safe_detail_code", "schema"}
            and decoded.get("safe_detail_code")
            in CONTEXT_PROJECTION_UNAVAILABLE_CODES
        ):
            return {
                "kind": kind,
                "safe_detail_code": decoded["safe_detail_code"],
                "schema": response_schema,
            }
        if kind == "accepted_reply":
            reply = decoded.get("reply")
            expected_keys = {"kind", "reply", "schema"}
            if "recovery_notice" in decoded:
                expected_keys.add("recovery_notice")
            if "delivery_token" in decoded or "pacing_seconds" in decoded:
                if response_schema != GATEWAY_RESPONSE_SCHEMA:
                    raise GatewayTransportError("gateway transport unavailable")
                expected_keys.update({"delivery_token", "pacing_seconds"})
                token = decoded.get("delivery_token")
                pacing = decoded.get("pacing_seconds")
                if (
                    not isinstance(token, str)
                    or _DELIVERY_TOKEN.fullmatch(token) is None
                    or not isinstance(pacing, (int, float))
                    or isinstance(pacing, bool)
                    or not 0 <= float(pacing) <= 15
                ):
                    raise GatewayTransportError("gateway transport unavailable")
            if (
                keys != expected_keys
                or not isinstance(reply, str)
                or not reply.strip()
                or len(reply) > 4000
            ):
                raise GatewayTransportError("gateway transport unavailable")
            result: dict[str, object] = {
                "kind": "accepted_reply",
                "reply": reply.strip(),
                "schema": response_schema,
            }
            if "recovery_notice" in decoded:
                notice = decoded["recovery_notice"]
                if notice != RECOVERY_NOTICE_TEXT:
                    raise GatewayTransportError("gateway transport unavailable")
                result["recovery_notice"] = RECOVERY_NOTICE_TEXT
            if "delivery_token" in decoded:
                result["delivery_token"] = decoded["delivery_token"]
                result["pacing_seconds"] = float(decoded["pacing_seconds"])
            return result
        if kind == "duplicate_suppressed" and keys == {"kind", "schema"}:
            return {
                "kind": "duplicate_suppressed",
                "schema": response_schema,
            }
        if kind == "safe_degraded_reply" and keys == {
            "degradation",
            "kind",
            "schema",
        }:
            return {
                "degradation": _validate_degradation(decoded["degradation"]),
                "kind": "safe_degraded_reply",
                "schema": response_schema,
            }
        raise GatewayTransportError("gateway transport unavailable")

    status = decoded.get("status")
    code = decoded.get("code")
    if status not in {"accepted", "rejected"} or not isinstance(code, str):
        raise GatewayTransportError("gateway transport unavailable")
    if keys == {"code", "status"}:
        return {"status": status, "code": code}
    reply = decoded.get("reply")
    if (
        keys != {"code", "reply", "status"}
        or status != "accepted"
        or code != "owner-runtime-reply"
        or not isinstance(reply, str)
        or not reply.strip()
        or len(reply) > 4000
    ):
        raise GatewayTransportError("gateway transport unavailable")
    return {"status": status, "code": code, "reply": reply.strip()}


def send_envelope(
    socket_path: str | Path,
    payload: dict[str, object],
    *,
    timeout: float = 175.0,
) -> dict[str, object]:
    request = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(request) > 32768:
        raise GatewayTransportError("gateway transport unavailable")

    response = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(socket_path))
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            while len(response) <= _MAX_RESPONSE_BYTES:
                chunk = client.recv(1024)
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break
    except OSError as exc:
        raise GatewayTransportError("gateway transport unavailable") from exc

    if len(response) > _MAX_RESPONSE_BYTES or b"\n" not in response:
        raise GatewayTransportError("gateway transport unavailable")
    return decode_gateway_response(bytes(response).split(b"\n", 1)[0])


def send_delivery_outcome(
    socket_path: str | Path,
    delivery_token: str,
    trace_id: str,
    *,
    outcome: str,
    timeout: float = 5.0,
) -> None:
    if not isinstance(delivery_token, str) or _DELIVERY_TOKEN.fullmatch(delivery_token) is None:
        raise GatewayTransportError("gateway transport unavailable")
    if not isinstance(trace_id, str) or _TRACE_ID.fullmatch(trace_id) is None:
        raise GatewayTransportError("gateway transport unavailable")
    if not isinstance(outcome, str) or outcome not in {"delivered", "cancelled"}:
        raise GatewayTransportError("gateway transport unavailable")
    payload = {
        "delivery_token": delivery_token,
        "outcome": outcome,
        "schema": DELIVERY_OUTCOME_SCHEMA,
        "trace_id": trace_id,
    }
    request = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    response = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(socket_path))
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            while len(response) <= 512:
                chunk = client.recv(512)
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break
    except OSError as exc:
        raise GatewayTransportError("gateway transport unavailable") from exc
    try:
        decoded = json.loads(bytes(response).split(b"\n", 1)[0])
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GatewayTransportError("gateway transport unavailable") from None
    if decoded != {
        "schema": DELIVERY_OUTCOME_SCHEMA,
        "status": "accepted",
    }:
        raise GatewayTransportError("gateway transport unavailable")
