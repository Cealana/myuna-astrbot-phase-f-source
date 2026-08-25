"""Stable content-free correlation for P16 fault incidents."""

from __future__ import annotations

from hashlib import sha256
import re


_SAFE_INCIDENT = re.compile(r"^inc-[0-9a-f]{12}$")
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def incident_ref_for_request(request_id: str) -> str:
    if not isinstance(request_id, str) or _SAFE_REQUEST_ID.fullmatch(request_id) is None:
        raise ValueError("request id is invalid")
    digest = sha256(
        b"myuna-fault-incident-v1\0" + request_id.encode("ascii")
    ).hexdigest()
    return f"inc-{digest[:12]}"


def validate_incident_ref(value: object) -> str:
    if not isinstance(value, str) or _SAFE_INCIDENT.fullmatch(value) is None:
        raise ValueError("incident_ref is invalid")
    return value
