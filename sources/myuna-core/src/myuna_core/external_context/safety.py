from __future__ import annotations

import re

from .contracts import EgressSafetySignals, ExternalContextError


_CREDENTIAL_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)authorization\s*:\s*bearer\s+\S+"),
    re.compile(r"(?i)(?:api[_ -]?key|password|passwd|secret)\s*[:=]\s*\S+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
)
_EXPLICIT_FORWARD_PATTERNS = (
    re.compile(r"(?im)^forwarded message\s*$"),
    re.compile(r"(?im)^forwarded from\s*[:：]"),
    re.compile(r"转发的聊天记录"),
    re.compile(r"转发自\s*[:：]"),
)


def enforce_external_egress_safety(
    message: str,
    signals: EgressSafetySignals,
) -> None:
    if not signals.classifier_available:
        raise ExternalContextError("egress_safety_unavailable")
    if signals.credential_material or any(
        pattern.search(message) for pattern in _CREDENTIAL_PATTERNS
    ):
        raise ExternalContextError("credential_material_excluded")
    if signals.forwarded_private or any(
        pattern.search(message) for pattern in _EXPLICIT_FORWARD_PATTERNS
    ):
        raise ExternalContextError("forwarded_private_content_excluded")
    if signals.third_party_private:
        raise ExternalContextError("third_party_private_content_excluded")
