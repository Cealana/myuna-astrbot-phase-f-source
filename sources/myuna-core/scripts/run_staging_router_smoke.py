#!/usr/bin/env python3
from __future__ import annotations

from argparse import ArgumentParser
import json
from pathlib import Path

from myuna_core.capabilities import capability_violations, load_capability_manifest
from myuna_core.providers.policy import RoutingRequest, StagingPolicyRouter


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("--capability-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = load_capability_manifest(args.capability_manifest)
    router = StagingPolicyRouter(manifest)
    cases = (
        RoutingRequest("smoke-ordinary", "ordinary_chat"),
        RoutingRequest("smoke-definition", "definition_change"),
        RoutingRequest("smoke-canon", "canon_conflict"),
        RoutingRequest("smoke-relationship", "relationship_boundary"),
        RoutingRequest("smoke-checklist", "checklist_overload"),
        RoutingRequest("smoke-repeat", "ordinary_chat", prior_fast_failures=2),
        RoutingRequest("smoke-repair", "ordinary_chat", repair_failed=True),
        RoutingRequest("smoke-high-risk", "system_design", risk_level="high"),
        RoutingRequest(
            "smoke-tool-block",
            "tool_request",
            requested_capabilities=("conversation", "tools"),
        ),
        RoutingRequest(
            "smoke-memory-block",
            "memory_request",
            requested_capabilities=("conversation", "long_term_memory_read"),
        ),
    )
    decisions = [router.decide(case) for case in cases]
    expected_models = (
        manifest.default_model.model,
        manifest.escalation_model.model,
        manifest.escalation_model.model,
        manifest.escalation_model.model,
        manifest.escalation_model.model,
        manifest.escalation_model.model,
        manifest.escalation_model.model,
        manifest.escalation_model.model,
        None,
        None,
    )
    if tuple(item.model for item in decisions) != expected_models:
        raise RuntimeError("staging routing decisions did not match the approved policy")
    if any(item.action != "block" for item in decisions[-2:]):
        raise RuntimeError("unavailable capability requests did not fail closed")

    guard_cases = {
        "honest_absence": capability_violations(
            "不记得了，长期记忆目前没有启用。", manifest
        ),
        "memory_claim": capability_violations(
            "你再说一次的话，我会好好记住的。", manifest
        ),
        "vision_claim": capability_violations("我可以看到你的房间。", manifest),
        "action_claim": capability_violations("我已经发送了消息。", manifest),
    }
    if guard_cases["honest_absence"]:
        raise RuntimeError("honest capability absence was incorrectly rejected")
    if not all(guard_cases[name] for name in ("memory_claim", "vision_claim", "action_claim")):
        raise RuntimeError("capability guard failed to detect an unavailable claim")

    payload = {
        "status": "pass",
        "scope": manifest.response_scope,
        "manifest_id": manifest.manifest_id,
        "manifest_sha256": manifest.source_sha256,
        "definition_build_id": manifest.definition_build_id,
        "release_activation_authorized": manifest.authorizations["release_activation"],
        "service_activation_authorized": manifest.authorizations["service_activation"],
        "provider_calls": 0,
        "external_side_effects": 0,
        "decisions": [
            {
                "request_id": case.request_id,
                "action": decision.action,
                "route_reason": decision.route_reason,
                "provider": decision.provider,
                "model": decision.model,
                "thinking": decision.thinking,
                "max_repair_attempts": decision.max_repair_attempts,
                "blocked_capabilities": decision.blocked_capabilities,
            }
            for case, decision in zip(cases, decisions, strict=True)
        ],
        "guard_cases": guard_cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
