from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import math
from pathlib import Path
import re
import socket
import time
from typing import Any, Mapping, Protocol
from uuid import uuid4

from .models import MemoryQuery


MAX_REQUEST_BYTES = 65_536
MAX_RESPONSE_BYTES = 1_048_576
ALLOWED_MODES = frozenset({"auto", "hybrid", "lexical"})
AUDIT_LABEL = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]*$")


class AuditSink(Protocol):
    def emit(
        self,
        event: str,
        *,
        outcome: str = "ok",
        request_id: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None: ...


class RetrievalWorkerError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class WorkerRetrievalHit:
    memory_id: str
    score: float
    reasons: tuple[str, ...]
    score_components: Mapping[str, float] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class WorkerRetrievalResult:
    request_id: str
    mode_requested: str
    mode_used: str
    degraded_reason: str | None
    duration_ms: float
    hits: tuple[WorkerRetrievalHit, ...]
    trace: Mapping[str, Any]
    model: Mapping[str, Any]


class SyntheticRetrievalClient(Protocol):
    def retrieve(
        self,
        query: MemoryQuery,
        *,
        mode: str = "auto",
        timeout_seconds: float = 20.0,
        request_id: str | None = None,
    ) -> WorkerRetrievalResult: ...


def query_fingerprint(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _finite_number(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RetrievalWorkerError(
            "invalid_worker_response",
            f"{field_name} must be numeric",
            retryable=False,
        )
    result = float(value)
    if not math.isfinite(result):
        raise RetrievalWorkerError(
            "invalid_worker_response",
            f"{field_name} must be finite",
            retryable=False,
        )
    return result


class UnixSocketSyntheticRetrievalClient:
    """Strict Stage 5 client for the synthetic-only Stage 4 worker."""

    def __init__(self, socket_path: Path, *, connect_timeout: float = 5.0) -> None:
        if not socket_path.is_absolute():
            raise ValueError("retrieval worker socket path must be absolute")
        if not 0.1 <= connect_timeout <= 30.0:
            raise ValueError("connect_timeout must be between 0.1 and 30 seconds")
        self.socket_path = socket_path
        self.connect_timeout = connect_timeout

    def retrieve(
        self,
        query: MemoryQuery,
        *,
        mode: str = "auto",
        timeout_seconds: float = 20.0,
        request_id: str | None = None,
    ) -> WorkerRetrievalResult:
        if mode not in ALLOWED_MODES:
            raise ValueError("mode must be auto, hybrid, or lexical")
        if not 0.05 <= timeout_seconds <= 60.0:
            raise ValueError("timeout_seconds must be between 0.05 and 60")
        if query.include_external_records:
            raise ValueError("Stage 5 cannot retrieve external operational records")
        if query.limit > 10:
            raise ValueError("Stage 5 retrieval limit must not exceed 10")

        actual_request_id = request_id or str(uuid4())
        payload: dict[str, Any] = {
            "request_id": actual_request_id,
            "action": "retrieve",
            "synthetic": True,
            "text": query.text,
            "mode": mode,
            "timeout_seconds": timeout_seconds,
            "scope": list(query.scope),
            "kinds": [kind.value for kind in query.kinds],
            "proactive": query.proactive,
            "limit": query.limit,
        }
        for field_name in ("at", "time_start", "time_end"):
            value = getattr(query, field_name)
            if value is not None:
                payload[field_name] = value.isoformat()

        response = self._call(payload, timeout_seconds + self.connect_timeout)
        return self._parse_retrieval_response(response, actual_request_id, mode)

    def _call(self, payload: Mapping[str, Any], timeout: float) -> Mapping[str, Any]:
        encoded = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        if len(encoded) > MAX_REQUEST_BYTES:
            raise ValueError("retrieval worker request exceeds size limit")

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        try:
            client.connect(str(self.socket_path))
            client.sendall(encoded)
            received = bytearray()
            while b"\n" not in received:
                chunk = client.recv(min(65_536, MAX_RESPONSE_BYTES + 1 - len(received)))
                if not chunk:
                    break
                received.extend(chunk)
                if len(received) > MAX_RESPONSE_BYTES:
                    raise RetrievalWorkerError(
                        "worker_response_too_large",
                        "retrieval worker response exceeded the Stage 5 limit",
                        retryable=False,
                    )
        except socket.timeout as error:
            raise RetrievalWorkerError(
                "worker_timeout",
                "retrieval worker did not respond before the client deadline",
                retryable=True,
            ) from error
        except (FileNotFoundError, ConnectionRefusedError, PermissionError, OSError) as error:
            raise RetrievalWorkerError(
                "worker_unavailable",
                "retrieval worker Unix socket is unavailable",
                retryable=True,
            ) from error
        finally:
            client.close()

        if not received or b"\n" not in received:
            raise RetrievalWorkerError(
                "incomplete_worker_response",
                "retrieval worker closed without a complete response",
                retryable=True,
            )
        try:
            decoded = json.loads(bytes(received).split(b"\n", 1)[0])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RetrievalWorkerError(
                "invalid_worker_response",
                "retrieval worker returned invalid JSON",
                retryable=False,
            ) from error
        if not isinstance(decoded, dict):
            raise RetrievalWorkerError(
                "invalid_worker_response",
                "retrieval worker response must be an object",
                retryable=False,
            )
        return decoded

    @staticmethod
    def _parse_retrieval_response(
        payload: Mapping[str, Any],
        expected_request_id: str,
        expected_mode: str,
    ) -> WorkerRetrievalResult:
        if payload.get("ok") is not True:
            error = payload.get("error")
            code = error.get("code") if isinstance(error, dict) else None
            message = error.get("message") if isinstance(error, dict) else None
            safe_code = code if isinstance(code, str) and code else "worker_rejected"
            safe_message = (
                message if isinstance(message, str) and message else "worker rejected request"
            )
            raise RetrievalWorkerError(
                safe_code,
                safe_message,
                retryable=safe_code in {"model_timeout", "model_unavailable", "internal_error"},
            )
        if payload.get("request_id") != expected_request_id:
            raise RetrievalWorkerError(
                "request_id_mismatch",
                "retrieval worker response request_id did not match",
                retryable=False,
            )
        if payload.get("synthetic_only") is not True:
            raise RetrievalWorkerError(
                "synthetic_boundary_missing",
                "retrieval worker response did not assert the synthetic boundary",
                retryable=False,
            )

        mode_requested = payload.get("mode_requested")
        mode_used = payload.get("mode_used")
        if mode_requested != expected_mode or mode_used not in {"hybrid", "lexical"}:
            raise RetrievalWorkerError(
                "mode_mismatch",
                "retrieval worker returned an invalid mode transition",
                retryable=False,
            )
        if expected_mode == "lexical" and mode_used != "lexical":
            raise RetrievalWorkerError(
                "mode_mismatch",
                "lexical request unexpectedly used a model",
                retryable=False,
            )
        if expected_mode == "hybrid" and mode_used != "hybrid":
            raise RetrievalWorkerError(
                "mode_mismatch",
                "hybrid request unexpectedly degraded",
                retryable=False,
            )
        degraded_reason = payload.get("degraded_reason")
        if degraded_reason is not None and not isinstance(degraded_reason, str):
            raise RetrievalWorkerError(
                "invalid_worker_response",
                "degraded_reason must be a string or null",
                retryable=False,
            )
        if expected_mode == "auto" and mode_used == "lexical" and not degraded_reason:
            raise RetrievalWorkerError(
                "unexplained_degradation",
                "auto request degraded without a reason",
                retryable=False,
            )

        raw_hits = payload.get("hits")
        if not isinstance(raw_hits, list) or len(raw_hits) > 10:
            raise RetrievalWorkerError(
                "invalid_worker_response",
                "hits must be a list of at most 10 items",
                retryable=False,
            )
        hits: list[WorkerRetrievalHit] = []
        for raw_hit in raw_hits:
            if not isinstance(raw_hit, dict):
                raise RetrievalWorkerError(
                    "invalid_worker_response",
                    "each hit must be an object",
                    retryable=False,
                )
            memory_id = raw_hit.get("memory_id")
            reasons = raw_hit.get("reasons")
            components = raw_hit.get("score_components", {})
            if (
                not isinstance(memory_id, str)
                or not memory_id
                or len(memory_id) > 256
                or not isinstance(reasons, list)
                or any(not isinstance(reason, str) for reason in reasons)
                or not isinstance(components, dict)
            ):
                raise RetrievalWorkerError(
                    "invalid_worker_response",
                    "retrieval hit failed schema validation",
                    retryable=False,
                )
            hits.append(
                WorkerRetrievalHit(
                    memory_id=memory_id,
                    score=_finite_number(raw_hit.get("score"), "hit.score"),
                    reasons=tuple(reasons),
                    score_components={
                        str(key): _finite_number(value, f"score_components.{key}")
                        for key, value in components.items()
                    },
                )
            )

        trace = payload.get("trace")
        model = payload.get("model")
        if not isinstance(trace, dict) or not isinstance(model, dict):
            raise RetrievalWorkerError(
                "invalid_worker_response",
                "trace and model must be objects",
                retryable=False,
            )
        duration_ms = _finite_number(payload.get("duration_ms"), "duration_ms")
        if duration_ms < 0:
            raise RetrievalWorkerError(
                "invalid_worker_response",
                "duration_ms must not be negative",
                retryable=False,
            )
        return WorkerRetrievalResult(
            request_id=expected_request_id,
            mode_requested=expected_mode,
            mode_used=str(mode_used),
            degraded_reason=degraded_reason,
            duration_ms=duration_ms,
            hits=tuple(hits),
            trace=dict(trace),
            model=dict(model),
        )


class AuditedSyntheticRetrievalAdapter:
    """Core-facing Stage 5 adapter with metadata-only access auditing."""

    def __init__(
        self,
        client: SyntheticRetrievalClient,
        audit: AuditSink,
        *,
        caller: str = "myuna-core-dev",
    ) -> None:
        if not AUDIT_LABEL.fullmatch(caller) or len(caller) > 64:
            raise ValueError("caller must be a short internal audit label")
        self.client = client
        self.audit = audit
        self.caller = caller

    def retrieve(
        self,
        query: MemoryQuery,
        *,
        mode: str = "auto",
        timeout_seconds: float = 20.0,
        request_id: str | None = None,
        route_reason: str = "synthetic_stage5_validation",
    ) -> WorkerRetrievalResult:
        if not AUDIT_LABEL.fullmatch(route_reason) or len(route_reason) > 128:
            raise ValueError("route_reason must be a short internal audit label")
        actual_request_id = request_id or str(uuid4())
        tick = time.perf_counter()
        common_details: dict[str, Any] = {
            "synthetic": True,
            "caller": self.caller,
            "route_reason": route_reason,
            "query_fingerprint": query_fingerprint(query.text),
            "fingerprint_version": "sha256-v1",
            "query_characters": len(query.text),
            "scope_count": len(query.scope),
            "kinds": [kind.value for kind in query.kinds],
            "proactive": query.proactive,
            "limit": query.limit,
            "has_at": query.at is not None,
            "has_time_window": query.time_start is not None or query.time_end is not None,
            "mode_requested": mode,
        }
        try:
            result = self.client.retrieve(
                query,
                mode=mode,
                timeout_seconds=timeout_seconds,
                request_id=actual_request_id,
            )
        except RetrievalWorkerError as error:
            self.audit.emit(
                "memory_retrieval",
                outcome="error" if error.retryable else "rejected",
                request_id=actual_request_id,
                details={
                    **common_details,
                    "error_code": error.code,
                    "retryable": error.retryable,
                    "bridge_duration_ms": round((time.perf_counter() - tick) * 1000, 3),
                },
            )
            raise

        embedding_identity = result.trace.get("embedding_identity", {})
        safe_embedding_identity = (
            {
                key: embedding_identity.get(key)
                for key in ("provider_id", "model_id", "model_revision", "dimensions", "mode")
                if key in embedding_identity
            }
            if isinstance(embedding_identity, dict)
            else {}
        )
        self.audit.emit(
            "memory_retrieval",
            outcome="degraded" if result.degraded_reason else "ok",
            request_id=actual_request_id,
            details={
                **common_details,
                "mode_used": result.mode_used,
                "degraded_reason": result.degraded_reason,
                "hit_count": len(result.hits),
                "hit_ids": [hit.memory_id for hit in result.hits],
                "worker_duration_ms": result.duration_ms,
                "bridge_duration_ms": round((time.perf_counter() - tick) * 1000, 3),
                "embedding_identity": safe_embedding_identity,
            },
        )
        return result
