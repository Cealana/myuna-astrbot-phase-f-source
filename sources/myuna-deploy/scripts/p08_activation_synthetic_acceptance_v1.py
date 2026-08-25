#!/usr/bin/env python3
"""Network-free acceptance child used only by the protected engine shadow."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
import sys

import p08_activation_contract_v1 as activation_contract
import p08_temporal_gateway_v1 as gateway


def main() -> int:
    if sys.argv[1:] != ["--content-free-status"]:
        return 2
    nonce = os.environ.get("MYUNA_P08_STATUS_INVOCATION_NONCE", "")
    scope = os.environ.get("MYUNA_P08_SYNTHETIC_SCOPE_DIGEST", "")
    root = os.environ.get("MYUNA_P08_SYNTHETIC_ROOT", "")
    if re.fullmatch(r"[0-9a-f]{64}", nonce) is None or re.fullmatch(
        r"[0-9a-f]{64}", scope
    ) is None:
        return 2
    if not root.startswith("/") or root == "/":
        return 2
    control = Path(root) / "var/lib/myuna-active-temporal-context-v1/synthetic-control.json"
    try:
        value = json.loads(control.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return 2
    if (
        not isinstance(value, dict)
        or set(value) != {"acceptance", "fault_kind", "fault_role", "schema"}
        or value.get("schema") != "myuna.p08-activation-synthetic-control.v1"
        or value.get("acceptance") not in {"accept", "reject"}
        or value.get("fault_kind") not in activation_contract.SYNTHETIC_FAULT_KINDS
        or not (value.get("fault_role") is None or isinstance(value.get("fault_role"), str))
    ):
        return 2
    if value["acceptance"] == "reject":
        rejection = gateway.ContentFreeStatusRejection.from_stage(
            "transport_connect",
            invocation_nonce=nonce,
        )
        sys.stdout.write(
            json.dumps(
                rejection.projection(),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        return 1
    stable = {
        "active_fact_count": 0,
        "active_set_complete": True,
        "active_set_digest": "1" * 64,
        "lifecycle_complete": True,
        "lifecycle_digest": "2" * 64,
        "lifecycle_event_count": 0,
        "lifecycle_watermark": 0,
        "pending_proposal_count": 0,
        "scope_binding_digest": scope,
        "source_identity": gateway.CONTENT_FREE_STATUS_SOURCE_IDENTITY,
        "status_schema": gateway.CONTENT_FREE_STATUS_SCHEMA,
        "total_fact_count": 0,
        "trusted_time_binding_digest": "3" * 64,
        "trusted_time_evidence_complete": True,
    }
    status_digest = gateway._canonical_digest(
        "myuna-p08-content-free-status-v1", stable
    )
    response_digest = gateway._canonical_digest(
        "myuna-p08-content-free-status-v1",
        {
            "request_nonce": nonce,
            "source_identity": gateway.CONTENT_FREE_STATUS_SOURCE_IDENTITY,
            "status_digest": status_digest,
        },
    )
    projection = {
        **stable,
        "request_nonce": nonce,
        "response_digest": response_digest,
        "status_digest": status_digest,
    }
    sys.stdout.write(
        json.dumps(projection, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
