from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from myuna_core.authenticated_conversation import AuthenticatedConversationContext
from myuna_core.channel_gateway import ASTRBOT_QQ_CHANNEL, ASTRBOT_TELEGRAM_CHANNEL

from .contracts import TemporalContextError


@dataclass(frozen=True, slots=True)
class AuthorizedTemporalScope:
    channel_kind: str
    scope_sha256: str

    def __post_init__(self) -> None:
        if self.channel_kind not in {"telegram", "qq"}:
            raise TemporalContextError("scope_channel_invalid")
        if len(self.scope_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.scope_sha256
        ):
            raise TemporalContextError("scope_sha256_invalid")


class TemporalAccessPolicy:
    def __init__(
        self,
        *,
        reader_channels: tuple[str, ...] = (ASTRBOT_TELEGRAM_CHANNEL,),
        writer_channels: tuple[str, ...] = (ASTRBOT_TELEGRAM_CHANNEL,),
    ) -> None:
        recognized = {ASTRBOT_TELEGRAM_CHANNEL, ASTRBOT_QQ_CHANNEL}
        if not reader_channels or not writer_channels:
            raise ValueError("temporal access channels cannot be empty")
        if set(reader_channels) - recognized or set(writer_channels) - recognized:
            raise ValueError("temporal access channel is unknown")
        if set(writer_channels) - set(reader_channels):
            raise ValueError("writer channels must also have read scope")
        self.reader_channels = frozenset(reader_channels)
        self.writer_channels = frozenset(writer_channels)

    @staticmethod
    def _scope(context: AuthenticatedConversationContext) -> AuthorizedTemporalScope:
        payload = "\0".join(
            (
                context.binding_id,
                context.principal_id,
                context.namespace_id,
                context.channel_kind,
                context.channel_instance,
                context.conversation_id,
            )
        ).encode("utf-8")
        normalized_channel = {
            ASTRBOT_TELEGRAM_CHANNEL: "telegram",
            ASTRBOT_QQ_CHANNEL: "qq",
        }[context.channel_kind]
        return AuthorizedTemporalScope(
            channel_kind=normalized_channel,
            scope_sha256=sha256(b"myuna-active-temporal-scope-v1\0" + payload).hexdigest(),
        )

    def authorize_read(
        self, context: AuthenticatedConversationContext
    ) -> AuthorizedTemporalScope:
        if (
            context.authority_level != "owner"
            or context.conversation_kind != "private"
            or context.channel_kind not in self.reader_channels
        ):
            raise TemporalContextError("read_scope_rejected")
        return self._scope(context)

    def authorize_write(
        self,
        context: AuthenticatedConversationContext,
        *,
        explicit_intent: bool,
    ) -> AuthorizedTemporalScope:
        if (
            not explicit_intent
            or not context.consent_memory_candidate
            or context.authority_level != "owner"
            or context.conversation_kind != "private"
            or context.channel_kind not in self.writer_channels
        ):
            raise TemporalContextError("write_scope_rejected")
        return self._scope(context)
