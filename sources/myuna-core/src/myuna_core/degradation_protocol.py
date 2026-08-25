from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping

from .natural_degradation import (
    DegradationCategory,
    FailureEnvelope,
    RecoveryState,
    natural_degradation_text,
)


SAFE_DEGRADATION_SCHEMA = "myuna.safe-degradation.v1"
_STATUS = "degraded"
_MAX_REPLY_CHARACTERS = 512
_SAFE_DETAIL = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_SAFE_FINGERPRINT = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,383}$")
_PAYLOAD_FIELDS = frozenset(
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


@dataclass(frozen=True, slots=True)
class SafeDegradationProjection:
    """A bounded, content-free degradation result safe for a channel gateway."""

    schema: str
    status: str
    category: DegradationCategory
    retryable: bool
    owner_action_required: bool
    safe_detail_code: str
    recovery_state: RecoveryState
    fingerprint: str
    reply: str

    def __post_init__(self) -> None:
        if self.schema != SAFE_DEGRADATION_SCHEMA:
            raise ValueError("unsupported safe degradation schema")
        if self.status != _STATUS:
            raise ValueError("safe degradation status must be degraded")
        if not isinstance(self.category, DegradationCategory):
            raise TypeError("category must be a DegradationCategory")
        if type(self.retryable) is not bool:
            raise TypeError("retryable must be boolean")
        if type(self.owner_action_required) is not bool:
            raise TypeError("owner_action_required must be boolean")
        if _SAFE_DETAIL.fullmatch(self.safe_detail_code) is None:
            raise ValueError("safe_detail_code must be a safe identifier")
        if not isinstance(self.recovery_state, RecoveryState):
            raise TypeError("recovery_state must be a RecoveryState")
        if _SAFE_FINGERPRINT.fullmatch(self.fingerprint) is None:
            raise ValueError("fingerprint must be a safe bounded identifier")
        expected_reply = natural_degradation_text(self.category)
        if self.reply != expected_reply:
            raise ValueError("reply must equal the canonical category text")
        if not 1 <= len(self.reply) <= _MAX_REPLY_CHARACTERS:
            raise ValueError("reply is outside the safe channel limit")

    @classmethod
    def from_envelope(cls, envelope: FailureEnvelope) -> "SafeDegradationProjection":
        return cls(
            schema=SAFE_DEGRADATION_SCHEMA,
            status=_STATUS,
            category=envelope.category,
            retryable=envelope.retryable,
            owner_action_required=envelope.owner_action_required,
            safe_detail_code=envelope.safe_detail_code,
            recovery_state=envelope.recovery_state,
            fingerprint=envelope.fingerprint,
            reply=natural_degradation_text(envelope.category),
        )

    @classmethod
    def from_payload(cls, payload: object) -> "SafeDegradationProjection":
        if not isinstance(payload, Mapping) or set(payload) != _PAYLOAD_FIELDS:
            raise ValueError("safe degradation payload fields do not match the schema")
        category = payload["category"]
        recovery_state = payload["recovery_state"]
        if not isinstance(category, str) or not isinstance(recovery_state, str):
            raise TypeError("safe degradation enums must be strings")
        try:
            parsed_category = DegradationCategory(category)
            parsed_recovery_state = RecoveryState(recovery_state)
        except ValueError:
            raise ValueError("safe degradation payload contains an unknown enum") from None
        values = {
            "schema": payload["schema"],
            "status": payload["status"],
            "retryable": payload["retryable"],
            "owner_action_required": payload["owner_action_required"],
            "safe_detail_code": payload["safe_detail_code"],
            "fingerprint": payload["fingerprint"],
            "reply": payload["reply"],
        }
        for key in ("schema", "status", "safe_detail_code", "fingerprint", "reply"):
            if not isinstance(values[key], str):
                raise TypeError(f"{key} must be a string")
        return cls(
            schema=values["schema"],
            status=values["status"],
            category=parsed_category,
            retryable=values["retryable"],
            owner_action_required=values["owner_action_required"],
            safe_detail_code=values["safe_detail_code"],
            recovery_state=parsed_recovery_state,
            fingerprint=values["fingerprint"],
            reply=values["reply"],
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "status": self.status,
            "category": self.category.value,
            "retryable": self.retryable,
            "owner_action_required": self.owner_action_required,
            "safe_detail_code": self.safe_detail_code,
            "recovery_state": self.recovery_state.value,
            "fingerprint": self.fingerprint,
            "reply": self.reply,
        }
