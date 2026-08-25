"""Strict Telegram Owner-private client for the P08 temporal service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
import shlex
import socket
from typing import Mapping


SCHEMA = "myuna.active-temporal-context-protocol.v1"
BOUNDARY = "authenticated_telegram_owner_private_temporal_context"
SOCKET_PATH = "/run/myuna-active-temporal-context-v1/temporal.sock"
MAX_WIRE_BYTES = 16_384
MAX_REPLY_CHARACTERS = 4_000

_COMMAND = re.compile(r"^/temporal(?:[ \t]+(.*))?$", re.IGNORECASE)
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CATEGORIES = frozenset(
    {
        "current_task",
        "short_term_status",
        "temporary_plan",
        "next_action",
        "deadline",
        "waiting_item",
        "temporary_constraint",
        "temporary_availability",
        "short_lived_preference",
    }
)
_DRAFT_ACTIONS = frozenset({"add", "supersede", "refresh", "restore"})
_WRITE_ACTIONS = _DRAFT_ACTIONS | {"revoke", "confirm"}
_USAGE = (
    "用法：/temporal get <查询>；/temporal add <类别> <槽位> <1-30天> <内容>；"
    "/temporal supersede|refresh|restore <fact_id> <类别> <槽位> <1-30天> <内容>；"
    "/temporal revoke <fact_id>；/temporal confirm <proposal_id> <确认码>"
)
_UNAVAILABLE = "临时信息服务现在不可用；这次没有读取或写入临时信息，请稍后再试"


class TemporalGatewayRejected(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class TemporalCommand:
    action: str
    arguments: tuple[str, ...]

    @property
    def writes(self) -> bool:
        return self.action in _WRITE_ACTIONS


def is_temporal_command(value: object) -> bool:
    return isinstance(value, str) and _COMMAND.fullmatch(value.strip()) is not None


def parse_temporal_command(value: object) -> TemporalCommand | None:
    if not isinstance(value, str):
        return None
    match = _COMMAND.fullmatch(value.strip())
    if match is None:
        return None
    parameter = match.group(1)
    if parameter is None:
        return TemporalCommand("help", ())
    try:
        parts = shlex.split(parameter, posix=True)
    except ValueError:
        return TemporalCommand("help", ())
    if not parts:
        return TemporalCommand("help", ())
    action = parts[0].casefold()
    arguments = tuple(parts[1:])
    if action == "get" and len(arguments) >= 1:
        return TemporalCommand(action, (" ".join(arguments),))
    if action == "add" and len(arguments) >= 4:
        return TemporalCommand(action, (*arguments[:3], " ".join(arguments[3:])))
    if action in {"supersede", "refresh", "restore"} and len(arguments) >= 5:
        return TemporalCommand(action, (*arguments[:4], " ".join(arguments[4:])))
    if action == "revoke" and len(arguments) == 1:
        return TemporalCommand(action, arguments)
    if action == "confirm" and len(arguments) == 2:
        return TemporalCommand(action, arguments)
    return TemporalCommand("help", ())


def temporal_intent_grants_candidate_consent(value: object) -> bool:
    command = parse_temporal_command(value)
    return command is not None and command.writes


def _safe(value: str) -> str:
    if _SAFE.fullmatch(value) is None:
        raise TemporalGatewayRejected("invalid_request")
    return value


def _days(value: str) -> int:
    try:
        days = int(value)
    except ValueError:
        raise TemporalGatewayRejected("invalid_request") from None
    if not 1 <= days <= 30:
        raise TemporalGatewayRejected("invalid_request")
    return days


def _draft(
    *,
    category: str,
    slot_key: str,
    days: str,
    summary: str,
    source_kind: str,
    source_ref: str,
    occurred_at: datetime,
) -> dict[str, object]:
    if category not in _CATEGORIES:
        raise TemporalGatewayRejected("invalid_request")
    _safe(slot_key)
    _safe(source_ref)
    if (
        not summary
        or summary != summary.strip()
        or "\x00" in summary
        or len(summary) > 500
    ):
        raise TemporalGatewayRejected("invalid_request")
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise TemporalGatewayRejected("invalid_request")
    valid_from = occurred_at.astimezone(timezone.utc)
    expires_at = valid_from + timedelta(days=_days(days))
    return {
        "category": category,
        "expires_at": expires_at.isoformat(timespec="microseconds"),
        "slot_key": slot_key,
        "source_channel": "telegram",
        "source_kind": source_kind,
        "source_ref": source_ref,
        "summary": summary,
        "valid_from": valid_from.isoformat(timespec="microseconds"),
        "valid_to": None,
    }


def build_request(
    command: TemporalCommand,
    *,
    authenticated_context: Mapping[str, object],
    request_id: str,
    event_id: str,
    occurred_at: datetime,
) -> dict[str, object]:
    if command.action == "help":
        raise TemporalGatewayRejected("usage_requested")
    _safe(request_id)
    _safe(event_id)
    if command.action == "get":
        operation = "retrieve"
        payload: dict[str, object] = {
            "query": command.arguments[0],
            "categories": [],
            "slot_keys": [],
        }
    elif command.action == "confirm":
        operation = "confirm"
        payload = {
            "explicit_intent": True,
            "proposal_id": _safe(command.arguments[0]),
            "confirmation_code": _safe(command.arguments[1]),
        }
    else:
        operation = "propose"
        target: str | None = None
        draft: dict[str, object] | None = None
        if command.action == "revoke":
            target = _safe(command.arguments[0])
            action = "revoke"
        else:
            action = "create" if command.action == "add" else command.action
            offset = 0 if command.action == "add" else 1
            if offset:
                target = _safe(command.arguments[0])
            category, slot_key, days, summary = command.arguments[offset : offset + 4]
            source_kind = {
                "add": "owner_statement",
                "supersede": "owner_statement",
                "refresh": "owner_refresh",
                "restore": "owner_restore",
            }[command.action]
            draft = _draft(
                category=category,
                slot_key=slot_key,
                days=days,
                summary=summary,
                source_kind=source_kind,
                source_ref=event_id,
                occurred_at=occurred_at,
            )
        payload = {
            "explicit_intent": True,
            "action": action,
            "draft": draft,
            "target_fact_id": target,
            "ttl_seconds": 600,
        }
    return {
        "schema": SCHEMA,
        "boundary": BOUNDARY,
        "operation": operation,
        "request_id": request_id,
        "authenticated_context": dict(authenticated_context),
        "input": payload,
    }


def _read_response(raw: bytes, *, request_id: str) -> dict[str, object]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True) from None
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    if payload.get("request_id") not in {None, request_id}:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    if payload.get("ok") is False:
        error = payload.get("error")
        if (
            not isinstance(error, dict)
            or set(error) != {"code", "retryable"}
            or not isinstance(error.get("code"), str)
            or type(error.get("retryable")) is not bool
        ):
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
        raise TemporalGatewayRejected(error["code"], retryable=error["retryable"])
    if payload.get("ok") is not True or payload.get("request_id") != request_id:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    if not isinstance(payload.get("operation"), str) or not isinstance(
        payload.get("output"), dict
    ):
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    for field in (
        "model_called",
        "profile_written",
        "session_written",
        "legacy_namespace_written",
    ):
        if payload.get(field) is not False:
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    return payload


def send_temporal_request(
    payload: Mapping[str, object],
    *,
    socket_path: str = SOCKET_PATH,
    timeout: float = 5.0,
) -> dict[str, object]:
    raw = json.dumps(
        dict(payload), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8") + b"\n"
    if len(raw) > MAX_WIRE_BYTES:
        raise TemporalGatewayRejected("invalid_request")
    response = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(socket_path)
            client.sendall(raw)
            client.shutdown(socket.SHUT_WR)
            while len(response) <= MAX_WIRE_BYTES:
                chunk = client.recv(1024)
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break
    except OSError:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True) from None
    if len(response) > MAX_WIRE_BYTES:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    first = bytes(response).split(b"\n", 1)[0]
    return _read_response(first, request_id=str(payload["request_id"]))


def render_temporal_reply(command: TemporalCommand, response: Mapping[str, object]) -> str:
    output = response.get("output")
    if not isinstance(output, Mapping):
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    if command.action == "get":
        if output.get("state") == "empty" and output.get("fact_count") == 0:
            reply = "目前没有找到相关的临时信息。"
        elif (
            output.get("state") == "selected"
            and isinstance(output.get("fact_count"), int)
            and isinstance(output.get("context"), str)
        ):
            lines = output["context"].splitlines()[1:]
            if not lines:
                raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
            reply = "当前临时信息：\n" + "\n".join(lines)
        else:
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    elif command.action == "confirm":
        outcome = output.get("outcome")
        fact_id = output.get("fact_id")
        if not isinstance(outcome, str) or (fact_id is not None and not isinstance(fact_id, str)):
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
        suffix = "" if fact_id is None else f"（fact_id={fact_id}）"
        reply = f"临时信息变更已确认：{outcome}{suffix}"
    else:
        proposal_id = output.get("proposal_id")
        confirmation_code = output.get("confirmation_code")
        if not isinstance(proposal_id, str) or not isinstance(confirmation_code, str):
            raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
        reply = (
            "已准备临时信息变更；请在10分钟内发送：\n"
            f"/temporal confirm {proposal_id} {confirmation_code}"
        )
    if not reply or len(reply) > MAX_REPLY_CHARACTERS:
        raise TemporalGatewayRejected("temporal_unavailable", retryable=True)
    return reply


def usage_reply() -> str:
    return _USAGE


def unavailable_reply() -> str:
    return _UNAVAILABLE
