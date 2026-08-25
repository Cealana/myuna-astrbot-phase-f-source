"""Fail-closed V7.1 Telegram adapter policy with no polling or duplicate write."""

from __future__ import annotations

from dataclasses import dataclass

from myuna_core.interaction_contract_v7_1 import (
    OwnerInputKind,
    classify_owner_input,
)


ADAPTER_SCHEMA = "myuna.v7.1-telegram-adapter.v1"


@dataclass(frozen=True, slots=True)
class AdapterPolicy:
    schema: str
    route: str
    legacy_history_read: bool
    legacy_history_write: bool
    external_context_read: bool
    external_epoch_write: bool
    provider_call_allowed: bool
    channel_send_count: int
    background_polling: bool

    def __post_init__(self) -> None:
        if self.schema != ADAPTER_SCHEMA or self.channel_send_count != 1:
            raise ValueError("v7_1_adapter_policy_rejected")
        if self.background_polling:
            raise ValueError("v7_1_background_polling_rejected")
        if self.legacy_history_write and self.external_epoch_write:
            raise ValueError("v7_1_duplicate_history_write_rejected")


def adapter_policy_for(text: str, *, hybrid_external_generation: bool) -> AdapterPolicy:
    contract = classify_owner_input(text)
    if contract.kind is OwnerInputKind.OBSERVER_INQUIRY:
        return AdapterPolicy(
            schema=ADAPTER_SCHEMA,
            route="observer_inquiry",
            legacy_history_read=False,
            legacy_history_write=False,
            external_context_read=False,
            external_epoch_write=False,
            provider_call_allowed=True,
            channel_send_count=1,
            background_polling=False,
        )
    if contract.kind is OwnerInputKind.COMMAND:
        return AdapterPolicy(
            schema=ADAPTER_SCHEMA,
            route="command_isolated",
            legacy_history_read=False,
            legacy_history_write=False,
            external_context_read=False,
            external_epoch_write=False,
            provider_call_allowed=False,
            channel_send_count=1,
            background_polling=False,
        )
    return AdapterPolicy(
        schema=ADAPTER_SCHEMA,
        route="ordinary_v7_1",
        legacy_history_read=not hybrid_external_generation,
        legacy_history_write=not hybrid_external_generation,
        external_context_read=hybrid_external_generation,
        external_epoch_write=hybrid_external_generation,
        provider_call_allowed=True,
        channel_send_count=1,
        background_polling=False,
    )


def preserve_rendered_reply(reply: str) -> str:
    if (
        not isinstance(reply, str)
        or not reply
        or reply != reply.strip()
        or "\x00" in reply
        or "\r" in reply
        or len(reply) > 4000
    ):
        raise ValueError("v7_1_rendered_reply_rejected")
    return reply
