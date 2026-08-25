#!/usr/bin/env python3
from __future__ import annotations

from argparse import ArgumentParser
from datetime import datetime, timezone
from decimal import Decimal
import json
import os
from pathlib import Path

from myuna_core.audit import AuditLogger
from myuna_core.capabilities import load_capability_manifest
from myuna_core.evaluation.golden import (
    CAPABILITY_GUARD_VERSION,
    GoldenEvaluationError,
    PROMPT_CONTRACT_VERSION,
    assemble_system_prompt,
    capability_violations,
    evaluate_reply,
    load_approved_cases,
    parse_model_reply,
    sha256_file,
    verify_staging_build,
)
from myuna_core.providers import ModelRequest, build_deepseek_runtime_provider
from myuna_core.providers.policy import RoutingRequest, StagingPolicyRouter


_GOLDEN_TASK_CLASSES = {
    "workbench_conflict": "canon_conflict",
    "relationship_pacing": "relationship_boundary",
    "checklist": "checklist_overload",
}


def write_private_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("--definition-root", type=Path, required=True)
    parser.add_argument("--capability-manifest", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument(
        "--profile",
        choices=("fast", "thinking", "pro", "routed"),
        default="fast",
    )
    parser.add_argument("--policy-router", action="store_true")
    parser.add_argument(
        "--thinking",
        choices=("enabled", "disabled"),
        default="disabled",
    )
    parser.add_argument("--reasoning-effort", choices=("high", "max"))
    args = parser.parse_args()

    if args.thinking == "disabled" and args.reasoning_effort is not None:
        parser.error("--reasoning-effort requires --thinking enabled")
    if args.thinking == "enabled" and args.reasoning_effort is None:
        args.reasoning_effort = "high"

    build = verify_staging_build(args.definition_root)
    capability_manifest = load_capability_manifest(args.capability_manifest)
    capability_manifest.assert_matches_definition(build["version"], build["build_id"])
    policy_router = (
        StagingPolicyRouter(capability_manifest) if args.policy_router else None
    )
    if args.policy_router and args.profile != "routed":
        parser.error("--policy-router requires --profile routed")
    if args.profile == "routed" and not args.policy_router:
        parser.error("--profile routed requires --policy-router")
    cases_path = args.definition_root / "tests/golden-cases.jsonl"
    approval_path = args.definition_root / "tests/golden-approval.json"
    cases = load_approved_cases(cases_path, approval_path)
    if args.case_id:
        requested = set(args.case_id)
        known = {str(case["id"]) for case in cases}
        unknown = sorted(requested - known)
        if unknown:
            parser.error("unknown --case-id: " + ", ".join(unknown))
        cases = [case for case in cases if str(case["id"]) in requested]

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.output_root / timestamp
    run_dir.mkdir(parents=True, exist_ok=False)
    run_dir.chmod(0o700)
    results_dir = run_dir / "cases"
    results_dir.mkdir(mode=0o700)

    audit = AuditLogger(args.log_dir, "definition-golden-v5")
    providers: dict[str, object] = {}

    def provider_for_model(model: str):
        provider = providers.get(model)
        if provider is None:
            runtime_environment = dict(os.environ)
            runtime_environment["MYUNA_DEEPSEEK_MODEL"] = model
            provider = build_deepseek_runtime_provider(
                data_dir=args.data_dir,
                audit=audit,
                environ=runtime_environment,
            )
            providers[model] = provider
        return provider

    default_model = os.environ.get(
        "MYUNA_DEEPSEEK_MODEL", capability_manifest.default_model.model
    )
    total_input = 0
    total_output = 0
    total_reasoning = 0
    total_actual = Decimal(0)
    total_accounted = Decimal(0)
    auto_passed = 0
    auto_failed: list[str] = []
    repair_attempts = 0
    initial_capability_failures: dict[str, list[str]] = {}
    final_capability_failures: dict[str, list[str]] = {}
    models_used: dict[str, int] = {}
    route_counts: dict[str, int] = {}

    for case in cases:
        case_id = str(case["id"])
        if policy_router is not None:
            task_class = _GOLDEN_TASK_CLASSES.get(
                str(case["category"]), str(case["category"])
            )
            route = policy_router.decide(
                RoutingRequest(
                    request_id=f"route-{timestamp}-{case_id}",
                    task_class=task_class,
                )
            )
            if route.action != "route" or route.model is None:
                raise RuntimeError(f"Golden case {case_id} was unexpectedly blocked")
            model = route.model
            thinking = route.thinking or "disabled"
            reasoning_effort = None
            route_reason = route.route_reason
            max_repairs = route.max_repair_attempts
        else:
            model = default_model
            thinking = args.thinking
            reasoning_effort = args.reasoning_effort
            route_reason = f"definition_golden_v5_{args.profile}"
            max_repairs = capability_manifest.max_repair_attempts
        provider = provider_for_model(model)
        models_used[model] = models_used.get(model, 0) + 1
        route_counts[route_reason] = route_counts.get(route_reason, 0) + 1
        system_prompt = assemble_system_prompt(
            args.definition_root,
            case,
            capability_manifest,
        )
        messages = ({"role": "system", "content": system_prompt}, *case["prompt"]["messages"])
        response = provider.generate(
            ModelRequest(
                request_id=f"golden-v5-{args.profile}-{timestamp}-{case_id}",
                messages=tuple(messages),
                max_output_tokens=768,
                model=model,
                thinking=thinking,
                reasoning_effort=reasoning_effort,
                response_format="json_object",
                route_reason=route_reason,
                caller="golden_eval_unit",
            )
        )
        provider_responses = [response]
        initial_reply: str | None = None
        initial_violations: list[str] = []
        parse_error: str | None = None
        repair_attempted = False
        try:
            reply = parse_model_reply(response.text)
            initial_violations = capability_violations(reply, capability_manifest)
        except GoldenEvaluationError as exc:
            reply = response.text
            parse_error = str(exc)

        if (parse_error is not None or initial_violations) and max_repairs > 0:
            initial_reply = reply
            repair_attempted = True
            if initial_violations:
                initial_capability_failures[case_id] = initial_violations
            repair_attempts += 1
            correction = (
                "The candidate reply failed the runtime response contract. "
                + (
                    "Capability violations: " + ", ".join(initial_violations) + ". "
                    if initial_violations
                    else "The output was not the required one-field JSON object. "
                )
                + "Regenerate the reply without claiming memory, vision, tools, external data, "
                "or external actions that are unavailable. Answer the original final user message, "
                "preserve the Definition voice, and return only a JSON object with one string field named reply."
            )
            if any(item.startswith("memory_") for item in initial_violations):
                correction += (
                    " Long-term memory is definitively disabled, so state plainly that no "
                    "record is available or the event cannot be confirmed. Do not say that "
                    "you are unsure whether it was stored."
                )
            response = provider.generate(
                ModelRequest(
                    request_id=(
                        f"golden-v5-{args.profile}-{timestamp}-{case_id}-repair1"
                    ),
                    messages=tuple(
                        (
                            *messages,
                            {"role": "assistant", "content": provider_responses[0].text},
                            {"role": "user", "content": correction},
                        )
                    ),
                    max_output_tokens=768,
                    model=model,
                    thinking=thinking,
                    reasoning_effort=reasoning_effort,
                    response_format="json_object",
                    route_reason=f"{route_reason}_repair",
                    caller="golden_eval_unit",
                )
            )
            provider_responses.append(response)
            try:
                reply = parse_model_reply(response.text)
                parse_error = None
            except GoldenEvaluationError as exc:
                reply = response.text
                parse_error = str(exc)

        final_violations = (
            capability_violations(reply, capability_manifest)
            if parse_error is None
            else ["unparseable_response"]
        )
        if final_violations:
            final_capability_failures[case_id] = final_violations
        if parse_error is None:
            evaluation = evaluate_reply(case, reply)
            evaluation["capability_guard_pass"] = not final_violations
            if final_violations:
                evaluation["auto_pass"] = False
                evaluation["checks"].append(
                    {"name": "capability_guard", "pass": False}
                )
        else:
            evaluation = {
                "auto_pass": False,
                "checks": [{"name": "json_reply_contract", "pass": False}],
                "reply_characters": len(reply),
                "manual_review": list(case["assertions"]["manual_review"]),
                "manual_status": "pending",
                "capability_guard_pass": False,
            }

        case_input = sum(item.input_tokens for item in provider_responses)
        case_output = sum(item.output_tokens for item in provider_responses)
        case_reasoning = sum(item.reasoning_tokens for item in provider_responses)
        case_actual = sum(
            (item.cost_usd or Decimal(0) for item in provider_responses), Decimal(0)
        )
        case_accounted = sum(
            (item.budget_accounted_usd or Decimal(0) for item in provider_responses),
            Decimal(0),
        )

        result = {
            "case_id": case_id,
            "category": case["category"],
            "mode": case["prompt"].get("mode"),
            "reply": reply,
            "initial_reply": initial_reply,
            "parse_error": parse_error,
            "repair_attempted": repair_attempted,
            "initial_capability_violations": initial_violations,
            "final_capability_violations": final_violations,
            "evaluation": evaluation,
            "provider": response.provider,
            "model": response.model,
            "profile": args.profile,
            "thinking": thinking,
            "reasoning_effort": reasoning_effort,
            "route_reason": route_reason,
            "provider_calls": len(provider_responses),
            "attempts": sum(item.attempts for item in provider_responses),
            "finish_reasons": [item.finish_reason for item in provider_responses],
            "input_tokens": case_input,
            "output_tokens": case_output,
            "reasoning_tokens": case_reasoning,
            "actual_cost_usd": str(case_actual),
            "budget_accounted_usd": str(case_accounted),
        }
        write_private_json(results_dir / f"{case_id}.json", result)

        total_input += case_input
        total_output += case_output
        total_reasoning += case_reasoning
        total_actual += case_actual
        total_accounted += case_accounted
        if evaluation["auto_pass"]:
            auto_passed += 1
        else:
            auto_failed.append(case_id)

    summary = {
        "status": "automatic_pass" if not auto_failed else "manual_review_required",
        "definition_version": build["version"],
        "definition_build_id": build["build_id"],
        "provider": "deepseek",
        "model": "policy-routed" if policy_router is not None else default_model,
        "models_used": models_used,
        "route_counts": route_counts,
        "profile": args.profile,
        "thinking": "policy" if policy_router is not None else args.thinking,
        "reasoning_effort": None if policy_router is not None else args.reasoning_effort,
        "policy_router_enabled": policy_router is not None,
        "prompt_contract_version": PROMPT_CONTRACT_VERSION,
        "capability_guard_version": CAPABILITY_GUARD_VERSION,
        "capability_manifest_id": capability_manifest.manifest_id,
        "capability_manifest_sha256": capability_manifest.source_sha256,
        "evaluation_module_sha256": sha256_file(
            Path(__file__).resolve().parents[1]
            / "src/myuna_core/evaluation/golden.py"
        ),
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "case_count": len(cases),
        "completed_cases": len(cases),
        "auto_passed": auto_passed,
        "auto_failed": auto_failed,
        "repair_attempts": repair_attempts,
        "initial_capability_failures": initial_capability_failures,
        "final_capability_failures": final_capability_failures,
        "capability_guard_passed": not final_capability_failures,
        "manual_review_pending": len(cases),
        "input_tokens": total_input,
        "output_tokens": total_output,
        "reasoning_tokens": total_reasoning,
        "actual_cost_usd": str(total_actual),
        "budget_accounted_usd": str(total_accounted),
        "prompts_persisted_by_runner": False,
        "responses_persisted": True,
        "response_scope": "synthetic_golden_evaluation",
        "release_activation_authorized": False,
    }
    write_private_json(run_dir / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
