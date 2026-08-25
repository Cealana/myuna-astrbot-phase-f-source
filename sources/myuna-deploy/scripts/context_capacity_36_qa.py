from __future__ import annotations

import json
from time import perf_counter

from context_window_policy import ConversationHistory


PROFILE_MAX_MESSAGES = 36
PROFILE_MAX_CHARACTERS = 48_000
PROFILE_MIN_HTTP_BODY_BYTES = 327_680
CORE_MESSAGE_MAX_CHARACTERS = 4_000
SATURATED_REQUEST_MESSAGES = PROFILE_MAX_MESSAGES - 1
OFFLINE_ITERATIONS = 100
OFFLINE_SECONDS_LIMIT = 2.0


def _user_text(turn: int) -> str:
    markers = {
        1: "EVICTED=旧银钥匙",
        2: "FIRST=雾蓝纸鹤",
        10: "MIDDLE=珊瑚时钟",
    }
    marker = markers.get(turn, f"USER-{turn:02d}")
    return f"synthetic turn {turn:02d} user | {marker} | 中文🙂"


def _assistant_text(turn: int) -> str:
    marker = "TAIL=月桂玻璃" if turn == 18 else f"ASSISTANT-{turn:02d}"
    return f"synthetic turn {turn:02d} assistant | {marker} | 已确认"


def build_saturated_request(
    *,
    conversation_id: str = "synthetic-session-a",
) -> tuple[ConversationHistory, list[dict[str, str]], list[dict[str, str]]]:
    history = ConversationHistory(
        PROFILE_MAX_MESSAGES,
        PROFILE_MAX_CHARACTERS,
    )
    for turn in range(1, 19):
        request = history.request_messages(conversation_id, _user_text(turn))
        history.commit_reply(conversation_id, request, _assistant_text(turn))
    stored = history.store.load(conversation_id)
    request = history.request_messages(
        conversation_id,
        "Return FIRST, MIDDLE, and TAIL in order; never return EVICTED.",
    )
    return history, stored, request


def core_payload_bytes(messages: list[dict[str, str]]) -> bytes:
    return json.dumps(
        {
            "high_quality": False,
            "messages": messages,
            "mode": "myuna",
            "risk_level": "low",
            "synthetic_memory": False,
            "task_class": "ordinary_chat",
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def maximal_valid_messages(fill: str) -> list[dict[str, str]]:
    if len(fill) != 1:
        raise ValueError("fill must be exactly one Unicode character")
    remaining = PROFILE_MAX_CHARACTERS
    messages: list[dict[str, str]] = []
    for index in range(SATURATED_REQUEST_MESSAGES):
        remaining_slots = SATURATED_REQUEST_MESSAGES - index - 1
        take = min(CORE_MESSAGE_MAX_CHARACTERS, remaining - remaining_slots)
        if take < 1:
            raise AssertionError("profile cannot allocate non-empty messages")
        messages.append(
            {
                "role": "user" if index % 2 == 0 else "assistant",
                "content": fill * take,
            }
        )
        remaining -= take
    if remaining != 0:
        raise AssertionError("profile allocation did not consume the character budget")
    return messages


def run_offline_gate() -> dict[str, object]:
    started = perf_counter()
    for _ in range(OFFLINE_ITERATIONS):
        _, stored, request = build_saturated_request()
    elapsed = perf_counter() - started

    contents = [item["content"] for item in request]
    roles = [item["role"] for item in request]
    cjk_body_bytes = len(core_payload_bytes(maximal_valid_messages("你")))
    escaped_body_bytes = len(core_payload_bytes(maximal_valid_messages("\x00")))
    checks = {
        "stored_exactly_36": len(stored) == PROFILE_MAX_MESSAGES,
        "request_exactly_35": len(request) == SATURATED_REQUEST_MESSAGES,
        "roles_alternate_and_end_user": roles
        == ["user" if index % 2 == 0 else "assistant" for index in range(35)],
        "evicted_boundary_absent": not any("EVICTED=" in item for item in contents),
        "first_retained_present": any("FIRST=雾蓝纸鹤" in item for item in contents),
        "middle_present": any("MIDDLE=珊瑚时钟" in item for item in contents),
        "tail_present": any("TAIL=月桂玻璃" in item for item in contents),
        "no_duplicate_messages": len(contents) == len(set(contents)),
        "cjk_body_fits_candidate_limit": cjk_body_bytes <= PROFILE_MIN_HTTP_BODY_BYTES,
        "escaped_body_fits_candidate_limit": (
            escaped_body_bytes <= PROFILE_MIN_HTTP_BODY_BYTES
        ),
        "offline_latency_within_limit": elapsed <= OFFLINE_SECONDS_LIMIT,
    }
    return {
        "schema": "myuna.context-capacity-36.offline-gate.v1",
        "profile": {
            "max_history_messages": PROFILE_MAX_MESSAGES,
            "max_history_characters": PROFILE_MAX_CHARACTERS,
            "minimum_http_body_bytes": PROFILE_MIN_HTTP_BODY_BYTES,
            "saturated_core_request_messages": SATURATED_REQUEST_MESSAGES,
            "provider_messages_with_one_system": SATURATED_REQUEST_MESSAGES + 1,
        },
        "measurements": {
            "cjk_body_bytes": cjk_body_bytes,
            "escaped_body_bytes": escaped_body_bytes,
            "offline_iterations": OFFLINE_ITERATIONS,
            "offline_seconds": round(elapsed, 6),
        },
        "checks": checks,
        "result": "passed" if all(checks.values()) else "failed",
    }


if __name__ == "__main__":
    report = run_offline_gate()
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    raise SystemExit(0 if report["result"] == "passed" else 1)
