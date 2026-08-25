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
CHANNEL_KIND = "astrbot_qq"
_QQ_ACCOUNT = re.compile(r"^[1-9][0-9]{4,19}$")
_SAFE_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_RESPONSE_BYTES = 4096
GATEWAY_RESPONSE_SCHEMA = "myuna.gateway-response.v2"
SAFE_DEGRADATION_SCHEMA = "myuna.safe-degradation.v1"
_SAFE_DETAIL = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_SAFE_FINGERPRINT = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,383}$")
_RECOVERY_STATES = frozenset({"active", "recovering", "recovered"})
_SAFE_DEGRADATION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "category",
        "retryable",
        "owner_action_required",
        "safe_detail_code",
        "recovery_state",
        "fingerprint",
        "reply",
    }
)
_CANONICAL_DEGRADATION_REPLIES = {
    "memory_no_evidence": "我现在没有找到能确认这件事的记录，所以不能装作记得",
    "reply_contract_rejected": (
        "刚才那句话没有通过回复检查，我没有把不可靠的内容继续发出来。"
        "你可以换个说法再问我一次"
    ),
    "provider_transient_failure": "我刚才没能正常完成这次回复。稍后再试一次就好",
    "provider_budget_or_auth_failure": (
        "我现在没能使用对话模型，这不是你说错了什么，需要先检查服务额度或配置"
    ),
    "core_or_gateway_failure": (
        "我这边的对话服务现在不太正常，这次没能继续处理，需要先恢复服务"
    ),
    "memory_service_failure": (
        "我刚才没能读取记忆服务，所以不能把这次情况说成‘没有相关记忆’。"
        "我只能先根据眼前的对话回答"
    ),
    "onebot_or_napcat_offline": (
        "QQ 连接现在不在线，没法从同一个 QQ 会话继续发送，需要先恢复登录"
    ),
    "host_or_network_unreachable": (
        "服务器或网络现在不可达，同一台机器里的服务没法自行恢复通信"
    ),
    "scheduled_notification_unavailable": (
        "我现在还不能设置定时任务，也不能在你不发消息时主动从 QQ 提醒你。"
        "你可以先设一个手机闹钟，到时再来找我就好"
    ),
    "memory_write_unavailable": (
        "我现在只能读取已经接入的记忆，还不能把新内容写进去。"
        "你可以先记在备忘录里，下次把记录发给我，我可以帮你整理"
    ),
    "external_data_unavailable": "我现在不能查询实时外部数据，所以不能替你确认最新结果",
    "vision_unavailable": "我现在还不能读取图片里的内容",
    "external_action_unavailable": (
        "我现在没有外部操作权限，不能直接替你执行这件事。你完成后再告诉我就好"
    ),
}


class GatewayTransportError(RuntimeError):
    """Transport failure with no sender or message detail."""


def should_forward_private_plain_text(
    *,
    sender_id: str,
    self_id: str,
    is_private_chat: bool,
    has_plain_text_only: bool,
) -> bool:
    """Admit only real private text from another valid QQ account.

    Rejected events must be dropped silently by the adapter.  In particular,
    replying to an outbound echo or a non-message OneBot event can create a
    local feedback loop before identity resolution is even attempted.
    """

    if not is_private_chat or not has_plain_text_only:
        return False
    if _QQ_ACCOUNT.fullmatch(sender_id) is None:
        return False
    if _QQ_ACCOUNT.fullmatch(self_id) is None:
        return False
    return not hmac.compare_digest(sender_id, self_id)


def _validate_safe_degradation(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != _SAFE_DEGRADATION_FIELDS:
        raise GatewayTransportError("gateway transport unavailable")
    string_fields = (
        "schema",
        "status",
        "category",
        "safe_detail_code",
        "recovery_state",
        "fingerprint",
        "reply",
    )
    if any(not isinstance(payload[field], str) for field in string_fields):
        raise GatewayTransportError("gateway transport unavailable")
    if payload["schema"] != SAFE_DEGRADATION_SCHEMA or payload["status"] != "degraded":
        raise GatewayTransportError("gateway transport unavailable")
    category = payload["category"]
    if category not in _CANONICAL_DEGRADATION_REPLIES:
        raise GatewayTransportError("gateway transport unavailable")
    if payload["recovery_state"] not in _RECOVERY_STATES:
        raise GatewayTransportError("gateway transport unavailable")
    if type(payload["retryable"]) is not bool:
        raise GatewayTransportError("gateway transport unavailable")
    if type(payload["owner_action_required"]) is not bool:
        raise GatewayTransportError("gateway transport unavailable")
    if _SAFE_DETAIL.fullmatch(payload["safe_detail_code"]) is None:
        raise GatewayTransportError("gateway transport unavailable")
    if _SAFE_FINGERPRINT.fullmatch(payload["fingerprint"]) is None:
        raise GatewayTransportError("gateway transport unavailable")
    reply = payload["reply"]
    if reply != _CANONICAL_DEGRADATION_REPLIES[category] or not 1 <= len(reply) <= 512:
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
    if decoded.get("schema") == GATEWAY_RESPONSE_SCHEMA:
        kind = decoded.get("kind")
        if kind == "accepted_reply":
            reply = decoded.get("reply")
            if (
                keys != {"kind", "reply", "schema"}
                or not isinstance(reply, str)
                or not reply.strip()
                or len(reply) > 4000
            ):
                raise GatewayTransportError("gateway transport unavailable")
            return {
                "kind": kind,
                "reply": reply.strip(),
                "schema": GATEWAY_RESPONSE_SCHEMA,
            }
        if kind == "safe_degraded_reply" and keys == {
            "degradation",
            "kind",
            "schema",
        }:
            return {
                "degradation": _validate_safe_degradation(decoded["degradation"]),
                "kind": kind,
                "schema": GATEWAY_RESPONSE_SCHEMA,
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
    if _QQ_ACCOUNT.fullmatch(sender_id) is None:
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
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce):
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
            b"myuna-qq-private-conversation-v1",
            sender_id,
            "conv",
        ),
        "conversation_kind": "private",
        "delivery_capabilities": ["text"],
        "event_id": _opaque_id(
            signing_secret,
            b"myuna-qq-event-v1",
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


def send_envelope(
    socket_path: str | Path,
    payload: dict[str, object],
    *,
    timeout: float = 75.0,
) -> dict[str, str]:
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
