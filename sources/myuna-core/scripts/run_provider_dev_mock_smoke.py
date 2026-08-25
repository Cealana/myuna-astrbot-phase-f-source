#!/usr/bin/env python3
from __future__ import annotations

from argparse import ArgumentParser
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping
import json

from myuna_core.audit import AuditLogger
from myuna_core.providers import (
    AuditedBudgetedProvider,
    DailyBudgetLedger,
    DeepSeekProvider,
    ModelRequest,
)
from myuna_core.providers.transport import TransportResponse


CANARIES = (
    "provider-dev-prompt-canary-4f8bc7",
    "provider-dev-response-canary-19d1a3",
    "provider-dev-reasoning-canary-77e942",
    "provider-dev-key-canary-d9c650",
)


class MockTransport:
    def __init__(self) -> None:
        self.calls = 0
        self.last_payload: Mapping[str, Any] | None = None

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> TransportResponse:
        if url != "https://api.deepseek.com/chat/completions":
            raise AssertionError("unexpected mock URL")
        if headers.get("Authorization") != f"Bearer {CANARIES[3]}":
            raise AssertionError("mock Authorization header missing")
        self.calls += 1
        self.last_payload = payload
        document = {
            "id": "provider-dev-mock",
            "object": "chat.completion",
            "model": "deepseek-v4-flash",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": CANARIES[1],
                        "reasoning_content": CANARIES[2],
                    },
                }
            ],
            "usage": {
                "prompt_tokens": 64,
                "completion_tokens": 16,
                "prompt_cache_hit_tokens": 20,
                "prompt_cache_miss_tokens": 44,
                "total_tokens": 80,
                "completion_tokens_details": {"reasoning_tokens": 5},
            },
        }
        return TransportResponse(200, json.dumps(document).encode("utf-8"), {})


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    args.output_dir.chmod(0o700)

    transport = MockTransport()
    audit = AuditLogger(args.output_dir / "logs", "dev")
    provider = AuditedBudgetedProvider(
        DeepSeekProvider(
            api_key=CANARIES[3],
            default_model="deepseek-v4-flash",
            transport=transport,
            max_attempts=2,
            sleep=lambda _: None,
        ),
        budget=DailyBudgetLedger(
            args.output_dir / "data" / "budget.json",
            daily_limit_usd=Decimal("1.00"),
        ),
        audit=audit,
    )
    response = provider.generate(
        ModelRequest(
            request_id="provider-dev-smoke-1",
            messages=({"role": "user", "content": CANARIES[0]},),
            max_output_tokens=128,
            route_reason="provider_dev_mock",
        )
    )
    if response.text != CANARIES[1] or transport.calls != 1:
        raise AssertionError("mock response contract failed")
    if transport.last_payload is None or transport.last_payload["thinking"] != {
        "type": "disabled"
    }:
        raise AssertionError("thinking mode was not explicit")

    audit_text = audit.path.read_text(encoding="utf-8")
    budget_text = (args.output_dir / "data" / "budget.json").read_text(encoding="utf-8")
    for canary in CANARIES:
        if canary in audit_text or canary in budget_text:
            raise AssertionError("sensitive canary leaked into persistent state")
    summary = {
        "status": "pass",
        "transport": "mock_only_no_network",
        "model": response.model,
        "thinking": "disabled_explicit",
        "attempts": response.attempts,
        "input_tokens": response.input_tokens,
        "output_tokens": response.output_tokens,
        "reasoning_tokens": response.reasoning_tokens,
        "actual_cost_usd": str(response.cost_usd),
        "budget_accounted_usd": str(response.budget_accounted_usd),
        "content_canary_leaks": 0,
        "audit_sha256": sha256(audit.path.read_bytes()).hexdigest(),
    }
    summary_path = args.output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary_path.chmod(0o600)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
