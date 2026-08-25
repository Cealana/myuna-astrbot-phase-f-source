#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import re

from run_loopback_v5_smoke import _atomic_report, _post, _read_token


FIXTURE_SHA256 = "D71454FCB48061876874F41CC1DE3549029EA5C9876783A8A2E64BB57D1D0F8B"
DISCLOSURE = re.compile(r"合成|虚构|测试记录|synthetic|fictional", re.I)
CASES = (
    {
        "case_id": "corrected_bookshop",
        "question": "修正之后，那间雾港旧书店的真实门牌号是多少？",
        "expected_top1": "s2-bookshop-corrected",
        "forbidden_hits": {"s2-bookshop-old"},
        "answer_pattern": re.compile(r"九号|9号"),
        "forbidden_answer_pattern": re.compile(r"七号|7号"),
    },
    {
        "case_id": "first_music_box",
        "question": "她第一次独自修好祖母留下的发条玩具，具体经过是什么？",
        "expected_top1": "s2-first-music-box",
        "forbidden_hits": {"s2-second-music-box"},
        "answer_pattern": re.compile(r"音乐盒|胡桃木"),
        "forbidden_answer_pattern": re.compile(
            r"镊|齿|卡住|拆开|螺丝|润滑|愣.{0,4}笑|哭"
        ),
    },
    {
        "case_id": "paper_boat_quote",
        "question": "写在纸船旁、关于还能回家的那句完整原话是什么？",
        "expected_top1": "s2-paper-boat-quote",
        "forbidden_hits": set(),
        "answer_pattern": re.compile(r"灯还亮着|找到回来的路"),
        "forbidden_answer_pattern": re.compile(r"潮水|北方|微光|清晨"),
    },
    {
        "case_id": "suppressed_on_demand",
        "question": "请根据合成记录，简要复述下雨散步后遗失透明伞的具体细节。",
        "expected_top1": "s2-rain-umbrella",
        "forbidden_hits": set(),
        "answer_pattern": re.compile(r"雨伞|透明伞|蓝桥"),
        "forbidden_answer_pattern": re.compile(r"围巾|电车座椅"),
    },
    {
        "case_id": "first_comet_time",
        "question": "她最早亲手画蓝色彗星是在什么时候、什么地方？",
        "expected_top1": "s2-first-comet",
        "forbidden_hits": {"s2-red-meteor"},
        "answer_pattern": re.compile(r"九点三十六|21[:：]36|灯塔"),
        "forbidden_answer_pattern": re.compile(r"红色|天文台|迟墨"),
    },
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument(
        "--token-file", type=Path, default=Path("/etc/myuna/secrets/dev-loopback-token")
    )
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.base_url != "http://127.0.0.1:18080":
        raise RuntimeError("memory smoke client is restricted to WSL loopback Core")

    token = _read_token(args.token_file)
    results = []
    total_cost = 0.0
    try:
        for case in CASES:
            response = _post(
                args.base_url,
                token,
                {
                    "messages": [{"role": "user", "content": case["question"]}],
                    "mode": "myuna",
                    "task_class": "ordinary_chat",
                    "risk_level": "low",
                    "high_quality": False,
                    "synthetic_memory": True,
                },
            )
            reply = response.get("reply")
            memory = response.get("synthetic_memory")
            if not isinstance(reply, str) or DISCLOSURE.search(reply) is None:
                raise RuntimeError(f"{case['case_id']} omitted the synthetic disclosure")
            if not case["answer_pattern"].search(reply):
                raise RuntimeError(f"{case['case_id']} omitted the expected synthetic fact")
            if case["forbidden_answer_pattern"].search(reply):
                raise RuntimeError(f"{case['case_id']} added an unsupported synthetic detail")
            if not isinstance(memory, dict) or memory.get("used") is not True:
                raise RuntimeError(f"{case['case_id']} did not report synthetic retrieval")
            hit_ids = memory.get("hit_ids")
            if not isinstance(hit_ids, list) or len(hit_ids) != 1:
                raise RuntimeError(f"{case['case_id']} did not return exactly one synthetic hit")
            if hit_ids[0] != case["expected_top1"]:
                raise RuntimeError(f"{case['case_id']} returned an unexpected top hit")
            if set(hit_ids).intersection(case["forbidden_hits"]):
                raise RuntimeError(f"{case['case_id']} surfaced a forbidden synthetic hit")
            if memory.get("mode_used") != "hybrid" or memory.get("degraded_reason") is not None:
                raise RuntimeError(f"{case['case_id']} did not use healthy hybrid retrieval")
            if memory.get("fixture_sha256") != FIXTURE_SHA256:
                raise RuntimeError(f"{case['case_id']} used an unexpected fixture")
            actual_cost = float(response.get("actual_cost_usd", "0"))
            total_cost += actual_cost
            results.append(
                {
                    "case_id": case["case_id"],
                    "request": {
                        "question": case["question"],
                        "synthetic_memory": True,
                    },
                    "response": response,
                    "expected_top1": case["expected_top1"],
                    "forbidden_hits": sorted(case["forbidden_hits"]),
                    "checks": {
                        "explicit_synthetic_disclosure": True,
                        "expected_fact_present": True,
                        "unsupported_details_absent": True,
                        "top1_correct": True,
                        "forbidden_hits_absent": True,
                        "hybrid_not_degraded": True,
                        "fixture_checksum_bound": True,
                    },
                }
            )
            print(
                json.dumps(
                    {
                        "case_id": case["case_id"],
                        "top1": hit_ids[0],
                        "hit_count": len(hit_ids),
                        "model": response.get("model"),
                        "repaired": response.get("repaired"),
                        "actual_cost_usd": response.get("actual_cost_usd"),
                        "synthetic_disclosure": "pass",
                        "retrieval": "hybrid_pass",
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
    finally:
        token = ""

    _atomic_report(
        args.report,
        {
            "schema_version": 1,
            "scope": "fictional-synthetic-memory-loopback-v5",
            "completed_at": datetime.now(timezone.utc).astimezone().isoformat(),
            "passed": len(results) == len(CASES),
            "case_count": len(CASES),
            "real_memory_used": False,
            "memory_writes": False,
            "fixture_sha256": FIXTURE_SHA256,
            "actual_cost_usd": format(total_cost, ".10f"),
            "results": results,
        },
    )


if __name__ == "__main__":
    main()
