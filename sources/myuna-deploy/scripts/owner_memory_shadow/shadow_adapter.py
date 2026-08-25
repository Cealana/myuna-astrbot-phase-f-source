#!/usr/bin/env python3
"""Local-only owner-memory Shadow worker with metadata-only observability."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import time
import unicodedata
from typing import Any, Iterable
from uuid import UUID

from preview_bridge import load_preview_bridge


POLICY_ID = "owner-qq-shadow-deterministic-zh-v1"
SERVICE_VERSION = "owner-memory-shadow-adapter-v1"
MAX_DATAGRAM_BYTES = 4096
MAX_QUERY_CHARACTERS = 256
ALLOWED_EVENT_KEYS = {
    "schema_version", "boundary", "request_uuid", "query", "enqueue_monotonic_ns"
}
DEEP_TERMS = (
    "记得", "回忆", "以前", "第一回", "第一次", "首次", "原话", "逐字",
    "当时为什么", "什么时候", "哪一天", "几点", "经过", "详细说说",
)
TRACE_FIELDS = {
    "request_uuid", "query_sha256", "query_character_count", "policy_version",
    "retrieval_mode", "candidate_memory_ids", "scores", "ranks",
    "filter_reason_codes", "latency", "safe_error_class", "candidate_counts",
    "service_version", "monotonic_event_timestamp",
}


def _normalized(text: str) -> str:
    value = unicodedata.normalize("NFKC", text).casefold()
    return "".join(character for character in value if character.isalnum())


def _ngrams(text: str, size: int = 3) -> set[str]:
    normalized = _normalized(text)
    if not normalized:
        return set()
    if len(normalized) <= size:
        return {normalized}
    return {normalized[index:index + size] for index in range(len(normalized) - size + 1)}


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def classify_mode(query: str) -> str:
    normalized = unicodedata.normalize("NFKC", query).casefold()
    return "deep" if any(term in normalized for term in DEEP_TERMS) else "recent"


def _raw_lexical(result: dict[str, Any]) -> float:
    components = {"primary_lexical": 0.0, "tag_alias_lexical": 0.0, "support_lexical": 0.0}
    for reason in result.get("score_reasons") or []:
        match = re.fullmatch(r"(primary_lexical|tag_alias_lexical|support_lexical)=([0-9.]+)", str(reason))
        if match:
            components[match.group(1)] = float(match.group(2))
    return round(
        (0.62 * components["primary_lexical"])
        + (0.25 * components["tag_alias_lexical"])
        + (0.13 * components["support_lexical"]),
        6,
    )


def _relation_ids(result: dict[str, Any]) -> set[str]:
    identifiers: set[str] = set()
    for relation in result.get("relations") or []:
        for key in ("source_candidate_id", "target_candidate_id", "related_candidate_id"):
            if relation.get(key):
                identifiers.add(str(relation[key]))
    return identifiers


def _is_near_duplicate(candidate: dict[str, Any], selected: dict[str, Any]) -> bool:
    candidate_id = str(candidate.get("candidate_id") or "")
    selected_id = str(selected.get("candidate_id") or "")
    if candidate_id in _relation_ids(selected) or selected_id in _relation_ids(candidate):
        return True
    candidate_text = " ".join(
        [str(candidate.get("assertion_text") or ""), str(candidate.get("exact_quote") or "")]
    )
    selected_text = " ".join(
        [str(selected.get("assertion_text") or ""), str(selected.get("exact_quote") or "")]
    )
    text_overlap = _jaccard(_ngrams(candidate_text), _ngrams(selected_text))
    candidate_tags = set(map(str, candidate.get("tags") or []))
    selected_tags = set(map(str, selected.get("tags") or []))
    tag_overlap = _jaccard(candidate_tags, selected_tags)
    candidate_scope = set(map(str, candidate.get("scope") or []))
    selected_scope = set(map(str, selected.get("scope") or []))
    scope_overlap = _jaccard(candidate_scope, selected_scope)
    return text_overlap >= 0.72 or (text_overlap >= 0.48 and tag_overlap >= 0.67 and scope_overlap >= 0.67)


def _distinct_facet(candidate: dict[str, Any], top: dict[str, Any]) -> bool:
    candidate_tags = set(map(str, candidate.get("tags") or []))
    top_tags = set(map(str, top.get("tags") or []))
    has_new_tag = bool(candidate_tags - top_tags)
    candidate_text = str(candidate.get("assertion_text") or "")
    top_text = str(top.get("assertion_text") or "")
    return has_new_tag and _jaccard(_ngrams(candidate_text), _ngrams(top_text)) < 0.48


def apply_policy(results: Iterable[dict[str, Any]], mode: str) -> tuple[list[dict[str, Any]], Counter[str]]:
    filtered: Counter[str] = Counter()
    eligible: list[dict[str, Any]] = []
    for result in results:
        if result.get("sensitivity") == "restricted":
            filtered["restricted"] += 1
            continue
        raw = _raw_lexical(result)
        if raw < 0.12:
            filtered["below_floor"] += 1
            continue
        copy = dict(result)
        copy["raw_lexical_score"] = raw
        eligible.append(copy)
    if not eligible or float(eligible[0].get("score") or 0.0) < 0.28:
        if eligible:
            filtered["below_floor"] += len(eligible)
        return [], filtered

    top_score = float(eligible[0]["score"])
    selected: list[dict[str, Any]] = []
    maximum = 3 if mode == "deep" else 2
    for candidate in eligible:
        score = float(candidate.get("score") or 0.0)
        if selected and (score < 0.24 or score < 0.65 * top_score):
            filtered["relative_gap"] += 1
            continue
        if any(_is_near_duplicate(candidate, prior) for prior in selected):
            filtered["near_duplicate"] += 1
            continue
        if mode == "recent" and selected and not _distinct_facet(candidate, selected[0]):
            filtered["low_novelty"] += 1
            continue
        selected.append(candidate)
        if len(selected) >= maximum:
            break
    return selected, filtered


def parse_event(datagram: bytes) -> dict[str, Any]:
    if not datagram or len(datagram) > MAX_DATAGRAM_BYTES:
        raise ValueError("event_size")
    event = json.loads(datagram.decode("utf-8"))
    if not isinstance(event, dict) or set(event) != ALLOWED_EVENT_KEYS:
        raise ValueError("event_schema")
    if event.get("schema_version") != 1 or event.get("boundary") != "verified_owner_private_text":
        raise ValueError("event_boundary")
    UUID(str(event.get("request_uuid") or ""))
    query = event.get("query")
    if not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY_CHARACTERS:
        raise ValueError("event_query")
    enqueue_ns = event.get("enqueue_monotonic_ns")
    if not isinstance(enqueue_ns, int) or enqueue_ns <= 0:
        raise ValueError("event_monotonic")
    return {
        "request_uuid": str(event["request_uuid"]),
        "query": query,
        "enqueue_monotonic_ns": enqueue_ns,
    }


def _safe_error(error: BaseException) -> str:
    if isinstance(error, (ValueError, UnicodeError, json.JSONDecodeError)):
        return "invalid_event"
    if isinstance(error, TimeoutError):
        return "retrieval_timeout"
    return "retrieval_unavailable"


def make_trace(event: dict[str, Any], preview: Any, *, at: datetime | None = None) -> dict[str, Any]:
    started = time.monotonic_ns()
    query = event["query"]
    mode = classify_mode(query)
    payload = preview.retrieve_safe(
        preview.load_safe_records(), query=query, mode=mode, days=3, limit=10,
        at=at or datetime.now(timezone.utc),
    )
    selected, policy_filtered = apply_policy(payload.get("results") or [], mode)
    latency_ms = (time.monotonic_ns() - started) / 1_000_000
    trace = {
        "request_uuid": event["request_uuid"],
        "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "query_character_count": len(query),
        "policy_version": POLICY_ID,
        "retrieval_mode": mode,
        "candidate_memory_ids": [str(item["candidate_id"]) for item in selected],
        "scores": [
            {"raw": item["raw_lexical_score"], "final": float(item["score"])}
            for item in selected
        ],
        "ranks": list(range(1, len(selected) + 1)),
        "filter_reason_codes": dict(sorted(policy_filtered.items())),
        "latency": {
            "enqueue_to_worker_ms": round(
                max(0, started - int(event["enqueue_monotonic_ns"])) / 1_000_000, 3
            ),
            "retrieval_ms": round(latency_ms, 3),
        },
        "safe_error_class": None,
        "candidate_counts": {
            "preview": len(payload.get("results") or []), "would_inject": len(selected)
        },
        "service_version": SERVICE_VERSION,
        "monotonic_event_timestamp": time.monotonic_ns(),
    }
    if set(trace) != TRACE_FIELDS:
        raise RuntimeError("trace_contract")
    return trace


def make_error_trace(request_uuid: str | None, query: str | None, error: BaseException) -> dict[str, Any]:
    safe_uuid = request_uuid if request_uuid else "00000000-0000-0000-0000-000000000000"
    safe_query = query if isinstance(query, str) else ""
    return {
        "request_uuid": safe_uuid,
        "query_sha256": hashlib.sha256(safe_query.encode("utf-8")).hexdigest(),
        "query_character_count": len(safe_query),
        "policy_version": POLICY_ID,
        "retrieval_mode": classify_mode(safe_query),
        "candidate_memory_ids": [], "scores": [], "ranks": [],
        "filter_reason_codes": {}, "latency": {},
        "safe_error_class": _safe_error(error),
        "candidate_counts": {"preview": 0, "would_inject": 0},
        "service_version": SERVICE_VERSION,
        "monotonic_event_timestamp": time.monotonic_ns(),
    }


def append_trace(path: Path, trace: dict[str, Any]) -> None:
    if set(trace) != TRACE_FIELDS:
        raise RuntimeError("trace_contract")
    encoded = json.dumps(trace, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    with path.open("a", encoding="ascii", newline="\n") as handle:
        handle.write(encoded + "\n")


def handle_datagram(datagram: bytes, preview: Any) -> dict[str, Any]:
    event: dict[str, Any] | None = None
    try:
        event = parse_event(datagram)
        return make_trace(event, preview)
    except Exception as error:
        return make_error_trace(
            event.get("request_uuid") if event else None,
            event.get("query") if event else None,
            error,
        )


def serve_systemd_socket(trace_path: Path) -> None:
    preview = load_preview_bridge()
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    if int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise RuntimeError("systemd_socket_required")
    listen_pid = int(os.environ.get("LISTEN_PID", "0"))
    if listen_pid not in (0, os.getpid()):
        raise RuntimeError("systemd_socket_pid_mismatch")
    with socket.fromfd(3, socket.AF_UNIX, socket.SOCK_DGRAM) as server:
        while True:
            datagram = server.recv(MAX_DATAGRAM_BYTES + 1)
            try:
                append_trace(trace_path, handle_datagram(datagram, preview))
            except OSError:
                # A trace failure must never create a response path or persist
                # plaintext in journald. Keep serving future datagrams.
                continue


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", required=True)
    args = parser.parse_args()
    serve_systemd_socket(Path(args.trace))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
