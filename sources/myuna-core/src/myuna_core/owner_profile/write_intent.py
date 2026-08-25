from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import re
from typing import Mapping

from .contracts import (
    PROFILE_STATE_MAXIMUM,
    PROFILE_STATE_MINIMUM,
    PROFILE_STATE_SCALE,
    OwnerProfileError,
)


MAX_SOURCE_CHARACTERS = 3_500


class OwnerProfileCandidateError(OwnerProfileError):
    pass


_BENCHMARK = re.compile(r"^/benchmark(?:[ \t]+([^\r\n]+))?$", re.IGNORECASE)
_CONFIRM = re.compile(r"^confirm[ \t]+([0-9a-f]{12})$", re.IGNORECASE)
_CANCEL = re.compile(r"^cancel[ \t]+([0-9a-f]{12})$", re.IGNORECASE)
_PROFILE_VALUE = re.compile(
    r"^(?:请)?(?:把|将)?亲密度(?:设为|设置为)[ \t]*(-?\d+(?:\.\d{1,4})?)$"
)
_PROFILE_CORRECT = re.compile(
    r"^(?:请)?(?:把|将)?亲密度修正为[ \t]*(-?\d+(?:\.\d{1,4})?)$"
)
_PROFILE_ROLLBACK = re.compile(r"^(?:请)?(?:把|将)?亲密度回滚到[ \t]*(-?\d+(?:\.\d{1,4})?)$")
_PROFILE_CONFIRM = re.compile(
    r"^确认亲密度提案[ \t]+([a-z0-9][a-z0-9_.:-]{0,127})[ \t]+v([1-9]\d*)$",
    re.IGNORECASE,
)
_PROFILE_CANCEL = re.compile(
    r"^取消亲密度提案[ \t]+([a-z0-9][a-z0-9_.:-]{0,127})[ \t]+v([1-9]\d*)$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class BenchmarkWriteIntent:
    action: str
    source_text: str | None = None
    confirmation_code: str | None = None


def parse_benchmark_write_intent(text: object) -> BenchmarkWriteIntent | None:
    if not isinstance(text, str):
        raise OwnerProfileCandidateError("candidate_intent_rejected")
    candidate = text.strip()
    if not candidate.casefold().startswith("/benchmark"):
        return None
    match = _BENCHMARK.fullmatch(candidate)
    if match is None or match.group(1) is None:
        raise OwnerProfileCandidateError("candidate_intent_rejected")
    parameter = match.group(1).strip()
    confirmation = _CONFIRM.fullmatch(parameter)
    if confirmation is not None:
        return BenchmarkWriteIntent(
            action="confirm",
            confirmation_code=confirmation.group(1).upper(),
        )
    cancellation = _CANCEL.fullmatch(parameter)
    if cancellation is not None:
        return BenchmarkWriteIntent(
            action="cancel",
            confirmation_code=cancellation.group(1).upper(),
        )
    if (
        parameter.casefold().startswith(("confirm", "cancel"))
        or not parameter
        or len(parameter) > MAX_SOURCE_CHARACTERS
        or "\x00" in parameter
    ):
        raise OwnerProfileCandidateError("candidate_intent_rejected")
    return BenchmarkWriteIntent(action="propose", source_text=parameter)


def benchmark_intent_grants_profile_consent(text: object) -> bool:
    try:
        return parse_benchmark_write_intent(text) is not None
    except OwnerProfileCandidateError:
        return False


def _scaled_profile_value(text: str) -> int:
    try:
        decimal = Decimal(text)
        scaled = decimal * PROFILE_STATE_SCALE
    except InvalidOperation:
        raise OwnerProfileError("profile_state_intent_rejected") from None
    if scaled != scaled.to_integral_value():
        raise OwnerProfileError("profile_state_intent_rejected")
    value = int(scaled)
    if value < PROFILE_STATE_MINIMUM or value > PROFILE_STATE_MAXIMUM:
        raise OwnerProfileError("profile_state_intent_rejected")
    return value


def parse_profile_v2_structural_request(
    text: object,
) -> Mapping[str, object] | None:
    """Parse the one finite Owner-facing Profile-v2 structural grammar."""
    if type(text) is not str:
        raise OwnerProfileError("profile_state_intent_rejected")
    candidate = " ".join(text.strip().split())
    if not candidate or len(candidate) > 256 or "\x00" in candidate:
        return None
    if candidate == "冻结亲密度":
        return {"action": "freeze"}
    if candidate == "解冻亲密度":
        return {"action": "unfreeze"}
    match = _PROFILE_CORRECT.fullmatch(candidate)
    if match is not None:
        return {
            "action": "correct",
            "requested_value": _scaled_profile_value(match.group(1)),
        }
    match = _PROFILE_ROLLBACK.fullmatch(candidate)
    if match is not None:
        return {"action": "rollback", "requested_value": _scaled_profile_value(match.group(1))}
    match = _PROFILE_CONFIRM.fullmatch(candidate)
    if match is not None:
        return {
            "action": "confirm_manifest",
            "proposal_id": match.group(1),
            "proposal_version": int(match.group(2)),
        }
    match = _PROFILE_CANCEL.fullmatch(candidate)
    if match is not None:
        return {
            "action": "cancel_manifest",
            "proposal_id": match.group(1),
            "proposal_version": int(match.group(2)),
        }
    match = _PROFILE_VALUE.fullmatch(candidate)
    if match is not None:
        return {
            "action": "propose_manifest",
            "requested_value": _scaled_profile_value(match.group(1)),
        }
    if candidate.startswith(
        (
            "确认亲密度提案",
            "取消亲密度提案",
            "冻结亲密度",
            "解冻亲密度",
            "把亲密度",
            "将亲密度",
            "亲密度设为",
            "亲密度设置为",
            "亲密度修正为",
        )
    ):
        raise OwnerProfileError("profile_state_intent_rejected")
    return None
