from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
    urlopen,
)
import json
import socket


MAX_RESPONSE_BYTES = 10 * 1024 * 1024
LOCAL_PROVIDER_PORT = 879
_SAFE_RESPONSE_HEADERS = frozenset({"retry-after", "request-id", "x-request-id"})


class TransportFailure(RuntimeError):
    """A content-free network failure safe for logs and user-facing diagnostics."""


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status_code: int
    body: bytes
    headers: Mapping[str, str]


class JsonTransport(Protocol):
    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> TransportResponse:
        ...


def _safe_headers(headers: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in headers.items():
        normalized = str(key).lower()
        if normalized in _SAFE_RESPONSE_HEADERS:
            result[normalized] = str(value)
    return result


def _read_bounded(response: Any) -> bytes:
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise TransportFailure("provider response exceeded the size limit")
    return body


class UrllibJsonTransport:
    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> TransportResponse:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request = Request(url, data=body, headers=dict(headers), method="POST")
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                return TransportResponse(
                    status_code=int(response.status),
                    body=_read_bounded(response),
                    headers=_safe_headers(response.headers),
                )
        except HTTPError as exc:
            return TransportResponse(
                status_code=int(exc.code),
                body=_read_bounded(exc),
                headers=_safe_headers(exc.headers),
            )
        except (URLError, TimeoutError, socket.timeout, OSError) as exc:
            raise TransportFailure("provider network request failed") from exc


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _validate_loopback_endpoint(url: str) -> None:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise TransportFailure("local provider endpoint failed validation") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or port != LOCAL_PROVIDER_PORT
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/v1/chat/completions"
        or parsed.query
        or parsed.fragment
    ):
        raise TransportFailure("local provider endpoint failed validation")


class LoopbackUrllibJsonTransport:
    """No-proxy, no-redirect transport for one literal loopback endpoint."""

    def __init__(self) -> None:
        self._opener = build_opener(ProxyHandler({}), _NoRedirectHandler())

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> TransportResponse:
        _validate_loopback_endpoint(url)
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request = Request(url, data=body, headers=dict(headers), method="POST")
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                return TransportResponse(
                    status_code=int(response.status),
                    body=_read_bounded(response),
                    headers=_safe_headers(response.headers),
                )
        except HTTPError as exc:
            return TransportResponse(
                status_code=int(exc.code),
                body=_read_bounded(exc),
                headers=_safe_headers(exc.headers),
            )
        except (URLError, TimeoutError, socket.timeout, OSError) as exc:
            raise TransportFailure("local provider request failed") from exc
