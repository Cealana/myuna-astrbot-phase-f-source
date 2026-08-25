#!/usr/bin/env python3
from __future__ import annotations

from argparse import ArgumentParser
from datetime import datetime, timezone
from pathlib import Path
import json

from myuna_core.audit import AuditLogger
from myuna_core.providers import ModelRequest, build_deepseek_runtime_provider


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.output_root / timestamp
    run_dir.mkdir(parents=True, exist_ok=False)
    run_dir.chmod(0o700)
    provider = build_deepseek_runtime_provider(
        data_dir=args.data_dir,
        audit=AuditLogger(args.log_dir, "dev"),
    )
    response = provider.generate(
        ModelRequest(
            request_id=f"deepseek-live-gate-{timestamp}",
            messages=(
                {
                    "role": "system",
                    "content": "You are an API connectivity test. Return only a JSON object.",
                },
                {
                    "role": "user",
                    "content": 'Return exactly this JSON object: {"status":"ok"}',
                },
            ),
            max_output_tokens=64,
            thinking="disabled",
            response_format="json_object",
            route_reason="provider_live_gate",
            caller="provider_gate_unit",
        )
    )
    try:
        parsed = json.loads(response.text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("live gate response was not valid JSON") from exc
    if parsed != {"status": "ok"}:
        raise RuntimeError("live gate response did not match the approved synthetic result")

    summary = {
        "status": "pass",
        "provider": response.provider,
        "model": response.model,
        "thinking": "disabled_explicit",
        "finish_reason": response.finish_reason,
        "attempts": response.attempts,
        "input_tokens": response.input_tokens,
        "output_tokens": response.output_tokens,
        "reasoning_tokens": response.reasoning_tokens,
        "actual_cost_usd": str(response.cost_usd),
        "budget_accounted_usd": str(response.budget_accounted_usd),
        "response_content_persisted": False,
    }
    summary_path = run_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary_path.chmod(0o600)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
