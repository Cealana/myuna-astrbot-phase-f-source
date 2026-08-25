from __future__ import annotations

import asyncio
import os
from sys import maxsize

from astrbot.api import star
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.message_components import Plain
from astrbot.core import logger

from .protocol import (
    GatewayTransportError,
    build_signed_envelope,
    read_signing_secret,
    send_envelope,
    should_forward_private_plain_text,
)


_PRIORITY = maxsize + 100
_SOCKET_PATH = os.environ.get(
    "MYUNA_GATEWAY_SOCKET",
    "/run/myuna-gateway/qq-owner.sock",
)
_SIGNING_SECRET_PATH = os.environ.get(
    "MYUNA_GATEWAY_SIGNING_SECRET",
    "/run/secrets/myuna-channel-signing-v1",
)
_CHANNEL_INSTANCE = os.environ.get(
    "MYUNA_GATEWAY_CHANNEL_INSTANCE",
    "napcat-dev",
)


class Main(star.Star):
    """Intercept every OneBot event before AstrBot can invoke an LLM."""

    def __init__(self, context: star.Context) -> None:
        super().__init__(context)
        logger.info("Myuna QQ fail-closed boundary initialized")

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP, priority=_PRIORITY)
    @filter.event_message_type(filter.EventMessageType.ALL, priority=_PRIORITY)
    async def intercept_onebot(self, event: AstrMessageEvent):
        event.should_call_llm(False)
        event.stop_event()

        try:
            sender_id = str(event.get_sender_id())
            self_id = str(event.get_self_id())
        except (AttributeError, TypeError, ValueError):
            return

        message_obj = getattr(event, "message_obj", None)
        parts = getattr(message_obj, "message", None)
        has_plain_text_only = (
            isinstance(parts, (list, tuple))
            and bool(parts)
            and all(isinstance(part, Plain) for part in parts)
        )
        if not should_forward_private_plain_text(
            sender_id=sender_id,
            self_id=self_id,
            is_private_chat=event.is_private_chat(),
            has_plain_text_only=has_plain_text_only,
        ):
            return

        message_text = "".join(part.text for part in parts)
        try:
            secret = read_signing_secret(_SIGNING_SECRET_PATH)
            envelope = build_signed_envelope(
                sender_id=sender_id,
                message_text=message_text,
                message_id=getattr(message_obj, "message_id", None),
                raw_timestamp=getattr(message_obj, "timestamp", None),
                signing_secret=secret,
                channel_instance=_CHANNEL_INSTANCE,
            )
            result = await asyncio.to_thread(send_envelope, _SOCKET_PATH, envelope)
        except (GatewayTransportError, TypeError, ValueError):
            logger.warning("Myuna QQ boundary rejected an event without recording event content")
            yield event.plain_result("QQ 安全入口已连接，但身份验证尚未开放；未调用模型、记忆或工具。")
            return

        if result.get("kind") == "accepted_reply":
            yield event.plain_result(result["reply"])
        elif result.get("kind") == "safe_degraded_reply":
            yield event.plain_result(result["degradation"]["reply"])
        elif result["status"] == "accepted" and result["code"] == "owner-runtime-reply":
            yield event.plain_result(result["reply"])
        elif result["status"] == "accepted":
            yield event.plain_result("身份验证消息已安全接收；本阶段未调用模型、记忆或工具。")
        elif result["code"] == "owner-runtime-unavailable":
            yield event.plain_result("Myuna 当前暂时无法回应，请稍后再试；未调用记忆或工具。")
        else:
            yield event.plain_result("当前消息未通过安全入口验证；未调用模型、记忆或工具。")

    async def terminate(self) -> None:
        logger.info("Myuna QQ fail-closed boundary stopped")
