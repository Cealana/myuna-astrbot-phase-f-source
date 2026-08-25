from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path

from myuna_core.audit import AuditLogger
from myuna_core.memory.models import MemoryQuery
from myuna_core.memory.worker_adapter import (
    AuditedSyntheticRetrievalAdapter,
    UnixSocketSyntheticRetrievalClient,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path("/run/myuna-retrieval-dev/worker.sock"),
    )
    parser.add_argument("--audit-dir", type=Path, required=True)
    args = parser.parse_args()

    client = UnixSocketSyntheticRetrievalClient(args.socket)
    audit = AuditLogger(args.audit_dir, "stage5-smoke")
    adapter = AuditedSyntheticRetrievalAdapter(client, audit, caller="stage5-smoke")
    at = datetime.fromisoformat("2042-08-01T12:00:00+08:00")
    cases = (
        ("lexical", "雾港旧书店银杏路九号", 20.0, "s2-bookshop-corrected"),
        ("hybrid", "第一次修好音乐盒", 20.0, "s2-first-music-box"),
        ("auto", "雾港旧书店银杏路九号", 0.05, "s2-bookshop-corrected"),
    )
    results: list[dict[str, object]] = []
    plaintext: list[str] = []
    for index, (mode, text, timeout, expected_top1) in enumerate(cases, start=1):
        response = adapter.retrieve(
            MemoryQuery(text, at=at, limit=3),
            mode=mode,
            timeout_seconds=timeout,
            request_id=f"stage5-smoke-{index}",
            route_reason="synthetic_stage5_integration",
        )
        top1 = response.hits[0].memory_id if response.hits else None
        if top1 != expected_top1:
            raise RuntimeError(f"unexpected top1 for {mode}: {top1}")
        if mode == "auto" and response.degraded_reason != "model_timeout":
            raise RuntimeError("auto timeout did not produce explicit lexical degradation")
        results.append(
            {
                "mode_requested": mode,
                "mode_used": response.mode_used,
                "degraded_reason": response.degraded_reason,
                "top1": top1,
                "duration_ms": response.duration_ms,
            }
        )
        plaintext.append(text)

    audit_text = audit.path.read_text(encoding="utf-8")
    if any(text in audit_text for text in plaintext):
        raise RuntimeError("audit log contains query plaintext")
    audit_records = [json.loads(line) for line in audit_text.splitlines()]
    if len(audit_records) != len(cases):
        raise RuntimeError("unexpected audit record count")
    print(
        json.dumps(
            {
                "accepted": True,
                "synthetic_only": True,
                "results": results,
                "audit_records": len(audit_records),
                "audit_plaintext_matches": 0,
                "audit_path": str(audit.path),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
