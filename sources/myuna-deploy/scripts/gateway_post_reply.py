"""Marker-gated, post-reply fanout for independent Shadow observers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from degradation_shadow_enqueue import (
    DegradationShadowJob,
    enqueue_degradation_after_response,
    write_fault_incident_receipt_after_response,
)
from gateway_enqueue import approved_marker_enabled, enqueue_after_reply
from incident_history_runtime_adapter_v1 import (
    IncidentHistoryAppendJob,
    append_incident_history_after_response,
)
from turn_route_enqueue import enqueue_turn_route_after_reply


MEMORY_SHADOW_MARKER = Path("/etc/myuna-gateway/qq-owner-memory-shadow-v1-enabled")
MEMORY_SHADOW_SOCKET = "/run/myuna-owner-memory-shadow-dev/shadow.sock"
TURN_ROUTE_SHADOW_MARKER = Path(
    "/etc/myuna-gateway/qq-owner-turn-route-shadow-v1-enabled"
)
TURN_ROUTE_SHADOW_SOCKET = "/run/myuna-turn-route-shadow-dev/shadow.sock"
DEGRADATION_SHADOW_MARKER = Path(
    "/etc/myuna-gateway/qq-owner-natural-degradation-shadow-v1-enabled"
)
DEGRADATION_SHADOW_SOCKET = "/run/myuna-natural-degradation-shadow-dev/shadow.sock"

# Compatibility names retained for the already-installed Memory Shadow seam.
SHADOW_MARKER = MEMORY_SHADOW_MARKER
SHADOW_SOCKET = MEMORY_SHADOW_SOCKET


class ConnectionContext(Protocol):
    def __enter__(self): ...
    def __exit__(self, exc_type, exc, traceback): ...


@dataclass(frozen=True, slots=True)
class PostReplyObservationJob:
    request_uuid: str
    query: str
    actual_route: str = "unknown"


# The installed gateway currently imports ShadowJob. Keeping this alias makes
# a future reviewed installation a bounded source update instead of a flag day.
ShadowJob = PostReplyObservationJob


@dataclass(frozen=True, slots=True)
class PostConnectionFanout:
    accepted: PostReplyObservationJob | None = None
    degradation: DegradationShadowJob | None = None
    incident_history: IncidentHistoryAppendJob | None = None

    def __post_init__(self) -> None:
        if (self.accepted is None) == (self.degradation is None):
            raise ValueError("exactly one post-connection observation is required")
        if self.incident_history is not None and (
            self.degradation is None
            or self.incident_history.incident_ref != self.degradation.incident_ref
        ):
            raise ValueError("incident history must bind the degradation incident_ref")


def _marker_is_enabled(
    marker: Path,
    marker_check: Callable[[str], bool],
) -> bool:
    try:
        return marker_check(str(marker))
    except Exception:
        return False


def _send_memory_shadow(
    job: PostReplyObservationJob,
    *,
    marker: Path,
    enqueue: Callable[[str, str, str], str],
    marker_check: Callable[[str], bool],
) -> None:
    if not _marker_is_enabled(marker, marker_check):
        return
    try:
        enqueue(MEMORY_SHADOW_SOCKET, job.request_uuid, job.query)
    except Exception:
        pass


def _send_turn_route_shadow(
    job: PostReplyObservationJob,
    *,
    marker: Path,
    enqueue: Callable[[str, str, str, str], str],
    marker_check: Callable[[str], bool],
) -> None:
    if not _marker_is_enabled(marker, marker_check):
        return
    try:
        enqueue(
            TURN_ROUTE_SHADOW_SOCKET,
            job.request_uuid,
            job.query,
            job.actual_route,
        )
    except Exception:
        pass


def _send_degradation_shadow(
    job: DegradationShadowJob,
    *,
    marker: Path,
    enqueue: Callable[[str, DegradationShadowJob], str],
    marker_check: Callable[[str], bool],
) -> None:
    if not _marker_is_enabled(marker, marker_check):
        return
    try:
        enqueue(DEGRADATION_SHADOW_SOCKET, job)
    except Exception:
        pass


def _write_fault_receipt(
    job: DegradationShadowJob,
    *,
    write_receipt: Callable[[DegradationShadowJob], str],
) -> None:
    try:
        write_receipt(job)
    except Exception:
        pass


def _normalize_fanout(
    result: PostReplyObservationJob | PostConnectionFanout | None,
) -> PostConnectionFanout | None:
    if result is None:
        return None
    if isinstance(result, PostConnectionFanout):
        return result
    if isinstance(result, PostReplyObservationJob):
        return PostConnectionFanout(accepted=result)
    return None


def serve_accepted_connection(
    connection: ConnectionContext,
    process_connection: Callable[
        [ConnectionContext], PostReplyObservationJob | PostConnectionFanout | None
    ],
    *,
    marker: Path = MEMORY_SHADOW_MARKER,
    enqueue: Callable[[str, str, str], str] = enqueue_after_reply,
    turn_route_marker: Path = TURN_ROUTE_SHADOW_MARKER,
    turn_route_enqueue: Callable[
        [str, str, str, str], str
    ] = enqueue_turn_route_after_reply,
    degradation_marker: Path = DEGRADATION_SHADOW_MARKER,
    degradation_enqueue: Callable[
        [str, DegradationShadowJob], str
    ] = enqueue_degradation_after_response,
    fault_receipt_write: Callable[
        [DegradationShadowJob], str
    ] = write_fault_incident_receipt_after_response,
    incident_history_append: Callable[
        [IncidentHistoryAppendJob], str
    ] = append_incident_history_after_response,
    marker_check: Callable[[str], bool] = approved_marker_enabled,
) -> None:
    """Close the reply connection before independent best-effort fanout."""

    result: PostReplyObservationJob | PostConnectionFanout | None = None
    with connection:
        result = process_connection(connection)
    fanout = _normalize_fanout(result)
    if fanout is None:
        return
    if fanout.accepted is not None:
        _send_memory_shadow(
            fanout.accepted,
            marker=marker,
            enqueue=enqueue,
            marker_check=marker_check,
        )
        _send_turn_route_shadow(
            fanout.accepted,
            marker=turn_route_marker,
            enqueue=turn_route_enqueue,
            marker_check=marker_check,
        )
    if fanout.degradation is not None:
        _write_fault_receipt(
            fanout.degradation,
            write_receipt=fault_receipt_write,
        )
        _send_degradation_shadow(
            fanout.degradation,
            marker=degradation_marker,
            enqueue=degradation_enqueue,
            marker_check=marker_check,
        )
        if fanout.incident_history is not None:
            try:
                incident_history_append(fanout.incident_history)
            except Exception:
                pass
