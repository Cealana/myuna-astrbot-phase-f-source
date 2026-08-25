#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import sys


REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "src"))

from owner_memory_retrieval_v2.postgres_source import load_safe_records  # noqa: E402
from owner_memory_retrieval_v2.protocol import build_response  # noqa: E402


EXPECTED_USER = "myuna_memory_runtime"


def main() -> int:
    user = pwd.getpwuid(os.geteuid()).pw_name
    if user != EXPECTED_USER:
        raise SystemExit("runtime probe must use the read-only memory identity")
    records = load_safe_records()
    response = build_response(
        {
            "request_id": "r2-direct-probe",
            "query": "我希望长期记忆怎样保留重要的事情？",
        },
        records,
        at=datetime.now(timezone.utc),
    )
    output = {
        "status": "passed" if response["hit_ids"] == ["M001"] else "failed",
        "evaluated_as": user,
        "safe_record_count": len(records),
        "hit_ids": response["hit_ids"],
        "policy_version": response["policy_version"],
        "model_called": response["model_called"],
        "memory_write_performed": response["memory_write_performed"],
        "restricted_included": response["restricted_included"],
        "query_text_printed": False,
        "memory_text_printed": False,
    }
    print(json.dumps(output, ensure_ascii=True, sort_keys=True))
    return 0 if output["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
