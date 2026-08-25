from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from hashlib import sha256
import ast
import json
from pathlib import Path
import unittest

from myuna_core.memory_aware_turn_protocol import (
    MEMORY_OPERATIONS,
    STEP_RESPONSE_SCHEMA,
    FinalBranch,
    MemoryAwareTurnError,
    MemoryCatalog,
    MemoryCatalogEntry,
    MemoryRequest,
    ServerIntentProposal,
    TurnBudget,
    advance_for_repair,
    advance_with_memory,
    complete_turn,
    create_memory_outcome,
    create_turn_step,
    derive_obligations,
    final_for_turn,
    memory_request_progress_fingerprint,
    parse_provider_step,
    preflight_memory_request,
    provider_response_payload,
    request_for_turn,
    validate_memory_outcome,
)
from myuna_core.memory_aware_provider_invocation import invoke_provider_step
from myuna_core.providers.base import ModelRequest, ModelResponse, ProviderError


def _sha(character: str) -> str:
    return character * 64


def _catalog(
    *,
    overrides: dict[str, str] | None = None,
    operations: tuple[str, ...] = MEMORY_OPERATIONS,
) -> MemoryCatalog:
    availability = {} if overrides is None else overrides
    entries = [
        MemoryCatalogEntry(
            operation=operation,
            scope_id={
                "p07_search_references": "raw-search",
                "p07_fetch_sources": "raw-fetch",
                "p08_temporal_read": "temporal",
                "profile_read": "profile",
                "p10b_trusted_time_read": "trusted-time",
            }[operation],
            availability=availability.get(operation, "available"),
            snapshot_digest=_sha(chr(97 + index)),
            source_closure_digest=sha256(
                f"closure-{operation}".encode("ascii")
            ).hexdigest(),
        )
        for index, operation in enumerate(operations)
    ]
    return MemoryCatalog(tuple(sorted(entries, key=lambda item: (item.operation, item.scope_id))))


def _turn(
    message: str = "Synthetic resident question",
    *,
    catalog: MemoryCatalog | None = None,
    budget: TurnBudget | None = None,
):
    return create_turn_step(
        owner_principal_id="owner-synthetic",
        conversation_id="conversation-synthetic",
        turn_id="turn-synthetic",
        request_id="request-synthetic",
        owner_message=message,
        catalog=_catalog() if catalog is None else catalog,
        budget=TurnBudget(absolute_deadline_ns=10_000) if budget is None else budget,
    )


def _json(turn, branch) -> str:
    return json.dumps(
        provider_response_payload(turn, branch),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


class FakeProvider:
    name = "synthetic"
    default_model = "synthetic-model"
    max_attempts = 5

    def __init__(
        self,
        outputs: list[str | ProviderError],
        *,
        attempts: int = 1,
        output_tokens: int = 32,
    ) -> None:
        self.outputs = list(outputs)
        self.attempts = attempts
        self.output_tokens = output_tokens
        self.requests: list[ModelRequest] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        selected = self.outputs.pop(0)
        if isinstance(selected, ProviderError):
            raise selected
        return ModelResponse(
            provider=self.name,
            model=self.default_model,
            text=selected,
            input_tokens=10,
            output_tokens=self.output_tokens,
            cache_hit_tokens=0,
            cache_miss_tokens=10,
            reasoning_tokens=0,
            finish_reason="stop",
            attempts=self.attempts,
            cost_usd=Decimal("0"),
            budget_accounted_usd=Decimal("0"),
        )


class MemoryAwareTurnProtocolTests(unittest.TestCase):
    def test_protocol_import_surface_is_provider_independent(self) -> None:
        protocol = Path(__file__).resolve().parents[1] / "src/myuna_core/memory_aware_turn_protocol.py"
        tree = ast.parse(protocol.read_text(encoding="utf-8"), filename=str(protocol))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        self.assertFalse(any("providers" in name for name in imports))
        self.assertFalse(hasattr(__import__("myuna_core.memory_aware_turn_protocol", fromlist=["*"]), "invoke_provider_step"))

    def test_resident_only_final_is_one_step_and_zero_retrieval(self) -> None:
        turn = _turn()
        final = final_for_turn(turn, owner_message="Synthetic resident answer")
        provider = FakeProvider([_json(turn, final)])

        branch, attempts = invoke_provider_step(provider, turn)
        self.assertIsInstance(branch, FinalBranch)
        completed = complete_turn(turn, branch, provider_attempts=attempts)

        self.assertEqual(completed.owner_message, "Synthetic resident answer")
        self.assertEqual(completed.retrieval_rounds, 0)
        self.assertEqual(completed.provider_attempts_used, 1)
        self.assertEqual(provider.requests[0].response_format, "json_object")

    def test_search_then_fetch_binds_selection_and_exact_claim(self) -> None:
        turn = _turn("Do you remember our previous walk?")
        search = request_for_turn(
            turn,
            operation="p07_search_references",
            scope_id="raw-search",
            query="previous walk",
        )
        parsed_search = parse_provider_step(_json(turn, search), turn)
        self.assertEqual(parsed_search, search)
        search_result, search_receipt = create_memory_outcome(
            search,
            status="available",
            values=("reference-alpha",),
        )
        turn = advance_with_memory(
            turn,
            search,
            search_result,
            search_receipt,
            provider_attempts=1,
        )
        fetch = request_for_turn(
            turn,
            operation="p07_fetch_sources",
            scope_id="raw-fetch",
            query="exact source for the walk",
            selection_digest=search_receipt.selection_digest,
            parent_receipt_digest=search_receipt.digest,
        )
        fetch_result, fetch_receipt = create_memory_outcome(
            fetch,
            status="available",
            values=("Synthetic complete source value",),
        )
        turn = advance_with_memory(
            turn,
            fetch,
            fetch_result,
            fetch_receipt,
            provider_attempts=1,
        )
        final = final_for_turn(turn, owner_message="The precise original quote is supported.")

        completed = complete_turn(turn, final, provider_attempts=1)

        self.assertEqual(completed.retrieval_rounds, 2)
        self.assertEqual(completed.receipt_digests, (search_receipt.digest, fetch_receipt.digest))

    def test_search_receipt_cannot_satisfy_exact_claim(self) -> None:
        turn = _turn("Remember the earlier turn")
        search = request_for_turn(
            turn,
            operation="p07_search_references",
            scope_id="raw-search",
            query="earlier turn",
        )
        result, receipt = create_memory_outcome(
            search,
            status="available",
            values=("reference-only",),
        )
        turn = advance_with_memory(turn, search, result, receipt, provider_attempts=1)
        final = final_for_turn(turn, owner_message="The exact quote is supported.")

        with self.assertRaisesRegex(MemoryAwareTurnError, "final_obligation_unsatisfied"):
            complete_turn(turn, final, provider_attempts=1)

    def test_two_scope_obligations_are_deterministic(self) -> None:
        turn = _turn("Remember before our relationship changed")
        operations = [item.operation for item in turn.obligations]
        self.assertEqual(operations, ["p07_search_references", "profile_read"])
        first_digest = turn.obligation_digest
        second = _turn("Remember before our relationship changed")
        self.assertEqual(first_digest, second.obligation_digest)

    def test_all_reference_obligation_classes_are_derived(self) -> None:
        cases = {
            "Remember the previous event": "historical_reference",
            "Do that again as usual": "indirect_historical_reference",
            "Our relationship changed": "relationship_change",
            "The evidence is stale and conflicting": "stale_or_conflicting_evidence",
        }
        catalog = _catalog()
        for text, reason in cases.items():
            with self.subTest(text=text):
                obligations = derive_obligations(text, catalog, include_exact_claims=False)
                self.assertIn(reason, {item.reason for item in obligations})
        exact = derive_obligations(
            "Use the original quote with specific number 123",
            catalog,
            include_exact_claims=True,
        )
        self.assertIn("exact_source_claim", {item.reason for item in exact})

    def test_bilingual_history_and_exact_source_obligations_are_complete(self) -> None:
        catalog = _catalog()
        history_cases = {
            "What did we discuss last time?": "historical_reference",
            "Do you recall our trip?": "historical_reference",
            "我们以前聊过的那件事": "historical_reference",
            "你记得我们去年春天谈的旅行吗？": "historical_reference",
            "Continue where we left off": "indirect_historical_reference",
            "Can we resume our plan?": "indirect_historical_reference",
            "Continue from our earlier plan": "indirect_historical_reference",
            "还是照旧安排": "indirect_historical_reference",
            "接着刚才那个继续吧": "indirect_historical_reference",
            "接着我们的计划往下走": "indirect_historical_reference",
            "继续我们的计划吧": "indirect_historical_reference",
        }
        for text, reason in history_cases.items():
            with self.subTest(text=text):
                obligations = derive_obligations(
                    text,
                    catalog,
                    include_exact_claims=True,
                )
                self.assertIn(reason, {item.reason for item in obligations})

        exact_cases = (
            "Quote the exact words from May 3, 2024",
            "What number did we decide on that date?",
            "What did we decide?",
            "What decision did we make last time?",
            "Which came first in the chronology?",
            "What was the order of events?",
            "二〇二四年五月三日我们做了什么决定？",
            "请逐字给出原话和具体来源",
            "What did you promise me last time?",
            "Remember why our relationship changed before?",
            "你之前答应过我的承诺是什么？",
            "还记得我们关系为什么变了吗？",
        )
        for text in exact_cases:
            with self.subTest(text=text):
                obligations = derive_obligations(
                    text,
                    catalog,
                    include_exact_claims=True,
                )
                exact = tuple(
                    item
                    for item in obligations
                    if item.reason == "exact_source_claim"
                )
                self.assertEqual(len(exact), 1)
                self.assertEqual(exact[0].operation, "p07_fetch_sources")

    def test_latin_markers_use_boundaries_for_resident_only_words(self) -> None:
        for text in (
            "The teams played against each other",
            "Pasta is a resident-only topic",
            "This object is priceless",
            "Help me make a decision about dinner",
            "What should we decide for dinner?",
            "请帮我决定晚饭吃什么",
            "继续搅拌汤",
            "接着加热晚餐",
            "Can you promise to help tomorrow?",
            "Why should our relationship improve in the future?",
            "请答应明天提醒我",
            "我们以后为什么要改善关系？",
        ):
            with self.subTest(text=text):
                obligations = derive_obligations(
                    text,
                    _catalog(),
                    include_exact_claims=True,
                )
                self.assertEqual(obligations, ())

    def test_isolated_continuation_and_decision_recall_are_fail_closed(self) -> None:
        catalog = _catalog()
        for text in (
            "接着我们的计划往下走",
            "继续我们的计划吧",
        ):
            with self.subTest(text=text):
                turn = _turn(text, catalog=catalog)
                self.assertEqual(
                    {(item.reason, item.operation) for item in turn.obligations},
                    {("indirect_historical_reference", "p07_search_references")},
                )
                final = final_for_turn(turn, owner_message="Unsupported resident answer")
                with self.assertRaisesRegex(
                    MemoryAwareTurnError,
                    "final_obligation_unsatisfied",
                ):
                    complete_turn(turn, final, provider_attempts=1)

        for text in (
            "What did we decide?",
            "What decision did we make last time?",
            "我们之前做的决定是什么？",
        ):
            with self.subTest(text=text):
                turn = _turn(text, catalog=catalog)
                self.assertEqual(
                    {item.operation for item in turn.obligations},
                    {"p07_search_references", "p07_fetch_sources"},
                )
                search = request_for_turn(
                    turn,
                    operation="p07_search_references",
                    scope_id="raw-search",
                    query="prior decision",
                )
                result, receipt = create_memory_outcome(
                    search,
                    status="available",
                    values=("reference-only",),
                )
                turn = advance_with_memory(
                    turn,
                    search,
                    result,
                    receipt,
                    provider_attempts=1,
                )
                final = final_for_turn(
                    turn,
                    owner_message="The selected option was Alpha.",
                )
                with self.assertRaisesRegex(
                    MemoryAwareTurnError,
                    "final_obligation_unsatisfied",
                ):
                    complete_turn(turn, final, provider_attempts=1)

    def test_required_catalog_operations_cannot_disappear(self) -> None:
        missing_cases = (
            (
                "p07_search_references",
                "Do you recall our trip?",
                "historical_reference",
            ),
            (
                "p07_fetch_sources",
                "Quote the exact source",
                "exact_source_claim",
            ),
        )
        for missing_operation, message, reason in missing_cases:
            with self.subTest(missing_operation=missing_operation):
                operations = tuple(
                    operation
                    for operation in MEMORY_OPERATIONS
                    if operation != missing_operation
                )
                selected = _turn(message, catalog=_catalog(operations=operations))
                missing = tuple(
                    item
                    for item in selected.obligations
                    if item.operation == missing_operation and item.reason == reason
                )
                self.assertEqual(len(missing), 1)
                self.assertEqual(missing[0].availability, "unavailable")
                self.assertIsNone(missing[0].scope_id)

        catalog = _catalog(operations=("profile_read",))
        turn = _turn(
            "Do you recall the exact source for our prior decision?",
            catalog=catalog,
        )
        self.assertEqual(
            {(item.operation, item.availability, item.scope_id) for item in turn.obligations},
            {
                ("p07_fetch_sources", "unavailable", None),
                ("p07_search_references", "unavailable", None),
            },
        )

        unsafe = final_for_turn(turn, owner_message="Unsupported answer")
        with self.assertRaisesRegex(
            MemoryAwareTurnError,
            "uncertain_evidence_answer_rejected",
        ):
            complete_turn(turn, unsafe, provider_attempts=1)

        safe = final_for_turn(
            turn,
            owner_message="I need clarification before answering",
            resolution="clarify",
        )
        completed = complete_turn(turn, safe, provider_attempts=1)
        self.assertEqual(completed.resolution, "clarify")
        self.assertEqual(completed.retrieval_rounds, 0)
        self.assertEqual(safe.uncertainty_statuses, ("unavailable",))

    def test_search_only_cannot_satisfy_exact_claim_classes(self) -> None:
        claims = (
            'The exact quote was "synthetic".',
            "The precise number was 17.",
            "The precise date was May 3, 2024.",
            "The decision we made last time was accepted.",
            "The chronology was event A before event B.",
        )
        for owner_message in claims:
            with self.subTest(owner_message=owner_message):
                turn = _turn("Remember the earlier event")
                search = request_for_turn(
                    turn,
                    operation="p07_search_references",
                    scope_id="raw-search",
                    query="earlier event",
                )
                result, receipt = create_memory_outcome(
                    search,
                    status="available",
                    values=("reference-only",),
                )
                turn = advance_with_memory(
                    turn,
                    search,
                    result,
                    receipt,
                    provider_attempts=1,
                )
                final = final_for_turn(turn, owner_message=owner_message)
                with self.assertRaisesRegex(
                    MemoryAwareTurnError,
                    "final_obligation_unsatisfied",
                ):
                    complete_turn(turn, final, provider_attempts=1)

    def test_request_preflight_and_progress_fingerprint_are_source_owned(self) -> None:
        turn = _turn()
        request = request_for_turn(
            turn,
            operation="profile_read",
            scope_id="profile",
            query="Profile Evidence",
        )
        self.assertEqual(preflight_memory_request(turn, request, provider_attempts=1), 1)
        variants = (
            " profile   evidence ",
            "profile-evidence!",
            "Ｐｒｏｆｉｌｅ，Ｅｖｉｄｅｎｃｅ！",
        )
        expected = memory_request_progress_fingerprint(request)
        for query in variants:
            with self.subTest(query=query):
                selected = replace(request, query=query)
                self.assertEqual(
                    memory_request_progress_fingerprint(selected),
                    expected,
                )
        refined = replace(request, query="profile evidence relationship")
        self.assertNotEqual(
            memory_request_progress_fingerprint(refined),
            expected,
        )

        cjk = replace(request, query="记忆证据")
        for query in ("记忆，证据", "记忆　证据", "記憶，證據"):
            with self.subTest(query=query):
                selected = replace(cjk, query=query)
                if query == "記憶，證據":
                    self.assertNotEqual(
                        memory_request_progress_fingerprint(selected),
                        memory_request_progress_fingerprint(cjk),
                    )
                else:
                    self.assertEqual(
                        memory_request_progress_fingerprint(selected),
                        memory_request_progress_fingerprint(cjk),
                    )

        empty = replace(request, query="，！？ …")
        with self.assertRaisesRegex(
            MemoryAwareTurnError,
            "memory_query_canonical_empty",
        ):
            preflight_memory_request(turn, empty, provider_attempts=1)

    def test_fourth_retrieval_round_is_rejected(self) -> None:
        budget = TurnBudget(
            absolute_deadline_ns=10_000,
            max_retrieval_rounds=3,
            max_provider_attempts=5,
        )
        turn = _turn(budget=budget)
        operations = (
            ("profile_read", "profile"),
            ("p08_temporal_read", "temporal"),
            ("p10b_trusted_time_read", "trusted-time"),
        )
        for operation, scope in operations:
            request = request_for_turn(
                turn,
                operation=operation,
                scope_id=scope,
                query=f"query {scope}",
            )
            result, receipt = create_memory_outcome(
                request,
                status="available",
                values=(f"result {scope}",),
            )
            turn = advance_with_memory(turn, request, result, receipt, provider_attempts=1)
        with self.assertRaisesRegex(MemoryAwareTurnError, "retrieval_round_budget_exhausted"):
            request_for_turn(
                turn,
                operation="profile_read",
                scope_id="profile",
                query="fourth request",
            )

    def test_each_nonavailable_status_requires_uncertain_final(self) -> None:
        for status in (
            "available_empty",
            "unavailable",
            "paused",
            "uninitialized",
            "denied",
            "budget_exhausted",
            "snapshot_drift",
            "conflict",
            "rejected",
        ):
            with self.subTest(status=status):
                turn = _turn(
                    "Our relationship changed",
                    catalog=_catalog(overrides={"profile_read": status}),
                )
                request = request_for_turn(
                    turn,
                    operation="profile_read",
                    scope_id="profile",
                    query="relationship evidence",
                )
                result, receipt = create_memory_outcome(request, status=status)
                turn = advance_with_memory(turn, request, result, receipt, provider_attempts=1)
                safe = final_for_turn(
                    turn,
                    owner_message="I am uncertain",
                    resolution="uncertain",
                )
                unsafe = replace(safe, resolution="answer")
                with self.assertRaisesRegex(
                    MemoryAwareTurnError,
                    "uncertain_evidence_answer_rejected",
                ):
                    complete_turn(turn, unsafe, provider_attempts=1)
                completed = complete_turn(turn, safe, provider_attempts=1)
                self.assertEqual(completed.resolution, "uncertain")

    def test_final_receipts_are_exact_and_repair_is_bounded(self) -> None:
        turn = _turn()
        missing = FinalBranch(
            owner_message="Synthetic answer",
            resolution="answer",
            receipt_digests=(_sha("f"),),
            uncertainty_statuses=(),
        )
        with self.assertRaises(MemoryAwareTurnError) as captured:
            complete_turn(turn, missing, provider_attempts=1)
        self.assertTrue(captured.exception.repairable)

        repaired = advance_for_repair(turn, provider_attempts=1)
        self.assertEqual(repaired.repairs_used, 1)
        self.assertEqual(repaired.provider_attempts_used, 1)
        with self.assertRaisesRegex(MemoryAwareTurnError, "repair_budget_exhausted"):
            advance_for_repair(repaired, provider_attempts=1)

    def test_strict_parser_rejects_mixed_unknown_duplicate_and_bad_encoding(self) -> None:
        turn = _turn()
        final = final_for_turn(turn, owner_message="Synthetic answer")
        valid = provider_response_payload(turn, final)
        cases: list[str | bytes] = []
        mixed = dict(valid)
        mixed["memory_request"] = {}
        cases.append(json.dumps(mixed))
        unknown = dict(valid)
        unknown["extra"] = True
        cases.append(json.dumps(unknown))
        cases.append(
            '{"schema":"%s","schema":"%s","branch":"final","bindings":{},"final":{}}'
            % (STEP_RESPONSE_SCHEMA, STEP_RESPONSE_SCHEMA)
        )
        cases.extend((b"\xff", "not-json"))
        for value in cases:
            with self.subTest(value=repr(value)[:80]):
                with self.assertRaises(MemoryAwareTurnError):
                    parse_provider_step(value, turn)

    def test_control_characters_and_oversized_output_are_rejected(self) -> None:
        turn = _turn()
        payload = provider_response_payload(
            turn,
            final_for_turn(turn, owner_message="Synthetic answer"),
        )
        payload["final"]["owner_message"] = "bad\u0001control"  # type: ignore[index]
        with self.assertRaisesRegex(MemoryAwareTurnError, "final_owner_message_invalid"):
            parse_provider_step(json.dumps(payload), turn)
        with self.assertRaisesRegex(MemoryAwareTurnError, "provider_response_budget_exhausted"):
            parse_provider_step("x" * (turn.budget.max_characters + 1), turn)

    def test_cross_binding_and_scope_escalation_fail_closed(self) -> None:
        turn = _turn()
        request = request_for_turn(
            turn,
            operation="profile_read",
            scope_id="profile",
            query="bounded profile read",
        )
        payload = provider_response_payload(turn, request)
        payload["bindings"]["turn_digest"] = _sha("e")  # type: ignore[index]
        with self.assertRaisesRegex(MemoryAwareTurnError, "provider_binding_mismatch"):
            parse_provider_step(json.dumps(payload), turn)

        escalated = provider_response_payload(turn, request)
        escalated["memory_request"]["scope_id"] = "another-owner"  # type: ignore[index]
        with self.assertRaisesRegex(MemoryAwareTurnError, "catalog_scope_not_authorized"):
            parse_provider_step(json.dumps(escalated), turn)

        arbitrary = provider_response_payload(turn, request)
        arbitrary["memory_request"]["operation"] = "execute_anything"  # type: ignore[index]
        with self.assertRaisesRegex(MemoryAwareTurnError, "memory_operation_invalid"):
            parse_provider_step(json.dumps(arbitrary), turn)

    def test_result_receipt_substitutions_reject_before_advance(self) -> None:
        turn = _turn()
        request = request_for_turn(
            turn,
            operation="profile_read",
            scope_id="profile",
            query="bounded profile read",
        )
        result, receipt = create_memory_outcome(
            request,
            status="available",
            values=("Synthetic profile value",),
        )
        substitutions = (
            replace(result, snapshot_digest=_sha("e")),
            replace(result, source_closure_digest=_sha("d")),
            replace(result, request_digest=_sha("c")),
        )
        for selected in substitutions:
            with self.subTest(selected=selected.content_free_payload()):
                with self.assertRaises(MemoryAwareTurnError):
                    validate_memory_outcome(turn, request, selected, receipt)
        with self.assertRaisesRegex(MemoryAwareTurnError, "receipt_binding_mismatch"):
            validate_memory_outcome(
                turn,
                request,
                result,
                replace(receipt, turn_digest=_sha("b")),
            )

    def test_p08_temporal_read_binds_state_snapshot_and_source_closure(self) -> None:
        turn = _turn()
        request = request_for_turn(
            turn,
            operation="p08_temporal_read",
            scope_id="temporal",
            query="resident temporal facts",
        )
        result, receipt = create_memory_outcome(
            request,
            status="available_empty",
        )
        validate_memory_outcome(turn, request, result, receipt)
        advanced = advance_with_memory(
            turn,
            request,
            result,
            receipt,
            provider_attempts=1,
        )
        self.assertEqual(advanced.results[-1].status, "available_empty")
        for substituted in (
            replace(result, snapshot_digest=_sha("e")),
            replace(result, source_closure_digest=_sha("d")),
            replace(result, status="conflict"),
        ):
            with self.subTest(substituted=substituted.content_free_payload()):
                with self.assertRaises(MemoryAwareTurnError):
                    validate_memory_outcome(turn, request, substituted, receipt)

    def test_fetch_requires_exact_search_receipt_and_selection(self) -> None:
        turn = _turn()
        search = request_for_turn(
            turn,
            operation="p07_search_references",
            scope_id="raw-search",
            query="find source",
        )
        result, receipt = create_memory_outcome(
            search,
            status="available",
            values=("reference",),
        )
        turn = advance_with_memory(turn, search, result, receipt, provider_attempts=1)
        with self.assertRaisesRegex(MemoryAwareTurnError, "fetch_search_binding_mismatch"):
            request_for_turn(
                turn,
                operation="p07_fetch_sources",
                scope_id="raw-fetch",
                query="fetch source",
                selection_digest=_sha("e"),
                parent_receipt_digest=receipt.digest,
            )

    def test_server_intents_are_distinct_and_never_renderable(self) -> None:
        turn = _turn()
        intent = ServerIntentProposal(
            intent_id="intent-synthetic",
            kind="follow_up_proposal",
            proposal_digest=_sha("a"),
        )
        final = final_for_turn(
            turn,
            owner_message="Only this text is renderable",
            server_intents=(intent,),
        )
        parsed = parse_provider_step(_json(turn, final), turn)
        self.assertIsInstance(parsed, FinalBranch)
        self.assertEqual(parsed.owner_message, "Only this text is renderable")
        self.assertNotIn(parsed.server_intents[0].proposal_digest, parsed.owner_message)

        injected = provider_response_payload(turn, final)
        injected["final"]["server_intents"][0]["owner_message"] = "injected"  # type: ignore[index]
        with self.assertRaisesRegex(MemoryAwareTurnError, "provider_server_intent_invalid"):
            parse_provider_step(json.dumps(injected), turn)

        profile_intent = ServerIntentProposal.profile_state(
            intent_id="profile-state-proposal-synthetic",
            requested_delta=10_000,
            reason_category="episode_end",
            source_interval_id="ti_" + "f" * 64,
        )
        profile_final = final_for_turn(
            turn,
            owner_message="A confirmation is required before any Profile change.",
            server_intents=(profile_intent,),
        )
        profile_parsed = parse_provider_step(_json(turn, profile_final), turn)
        self.assertEqual(profile_parsed.server_intents, (profile_intent,))
        self.assertNotIn(profile_intent.proposal_digest, profile_parsed.owner_message)

    def test_character_byte_token_output_result_and_attempt_budgets_bind(self) -> None:
        with self.assertRaises(MemoryAwareTurnError):
            _turn(
                budget=TurnBudget(
                    absolute_deadline_ns=10_000,
                    max_retrieval_rounds=3,
                    max_provider_attempts=4,
                )
            )
        turn = _turn(
            budget=TurnBudget(
                absolute_deadline_ns=10_000,
                max_characters=5_000,
                max_utf8_bytes=20_000,
                max_input_token_upper_bound=50,
            )
        )
        provider = FakeProvider([_json(turn, final_for_turn(turn, owner_message="answer"))])
        with self.assertRaisesRegex(MemoryAwareTurnError, "provider_input_token_budget_exhausted"):
            invoke_provider_step(provider, turn)

        turn = _turn()
        provider = FakeProvider(
            [_json(turn, final_for_turn(turn, owner_message="answer"))],
            output_tokens=turn.budget.output_token_reservation + 1,
        )
        with self.assertRaisesRegex(MemoryAwareTurnError, "provider_output_token_budget_exhausted"):
            invoke_provider_step(provider, turn)

        request = request_for_turn(
            turn,
            operation="profile_read",
            scope_id="profile",
            query="result limit",
        )
        result, receipt = create_memory_outcome(
            request,
            status="available",
            values=tuple(f"value-{index}" for index in range(turn.budget.max_result_count + 1)),
        )
        with self.assertRaisesRegex(MemoryAwareTurnError, "result_count_budget_exhausted"):
            advance_with_memory(turn, request, result, receipt, provider_attempts=1)

    def test_cumulative_result_character_and_byte_budgets_reject_before_advance(self) -> None:
        character_turn = _turn(
            "x",
            budget=TurnBudget(
                absolute_deadline_ns=10_000,
                max_characters=8,
                max_utf8_bytes=100,
            ),
        )
        first_request = request_for_turn(
            character_turn,
            operation="profile_read",
            scope_id="profile",
            query="first",
        )
        first_result, first_receipt = create_memory_outcome(
            first_request,
            status="available",
            values=("1234",),
        )
        character_turn = advance_with_memory(
            character_turn,
            first_request,
            first_result,
            first_receipt,
            provider_attempts=1,
        )
        second_request = request_for_turn(
            character_turn,
            operation="profile_read",
            scope_id="profile",
            query="second",
        )
        second_result, second_receipt = create_memory_outcome(
            second_request,
            status="available",
            values=("56789",),
        )
        with self.assertRaisesRegex(
            MemoryAwareTurnError,
            "result_character_budget_exhausted",
        ) as captured:
            advance_with_memory(
                character_turn,
                second_request,
                second_result,
                second_receipt,
                provider_attempts=1,
            )
        self.assertEqual(len(character_turn.results), 1)
        self.assertNotIn(
            "56789",
            json.dumps(captured.exception.content_free_projection(character_turn)),
        )

        byte_turn = _turn(
            "x",
            budget=TurnBudget(
                absolute_deadline_ns=10_000,
                max_characters=100,
                max_utf8_bytes=8,
            ),
        )
        first_request = request_for_turn(
            byte_turn,
            operation="profile_read",
            scope_id="profile",
            query="first",
        )
        first_result, first_receipt = create_memory_outcome(
            first_request,
            status="available",
            values=("你",),
        )
        byte_turn = advance_with_memory(
            byte_turn,
            first_request,
            first_result,
            first_receipt,
            provider_attempts=1,
        )
        second_request = request_for_turn(
            byte_turn,
            operation="profile_read",
            scope_id="profile",
            query="second",
        )
        second_result, second_receipt = create_memory_outcome(
            second_request,
            status="available",
            values=("好好",),
        )
        with self.assertRaisesRegex(
            MemoryAwareTurnError,
            "result_byte_budget_exhausted",
        ) as captured:
            advance_with_memory(
                byte_turn,
                second_request,
                second_result,
                second_receipt,
                provider_attempts=1,
            )
        self.assertEqual(len(byte_turn.results), 1)
        self.assertNotIn(
            "好好",
            json.dumps(captured.exception.content_free_projection(byte_turn)),
        )

    def test_provider_internal_attempts_and_failures_are_content_free(self) -> None:
        turn = _turn()
        final = final_for_turn(turn, owner_message="Synthetic answer")
        provider = FakeProvider([_json(turn, final)], attempts=2)
        branch, attempts = invoke_provider_step(provider, turn)
        completed = complete_turn(turn, branch, provider_attempts=attempts)
        self.assertEqual(completed.provider_attempts_used, 2)

        failure = ProviderError(
            "synthetic_upstream",
            "private upstream detail",
            retryable=False,
            attempts=3,
        )
        with self.assertRaises(MemoryAwareTurnError) as captured:
            invoke_provider_step(FakeProvider([failure]), turn)
        self.assertEqual(captured.exception.attempts, 3)
        projection = captured.exception.content_free_projection(turn)
        self.assertNotIn("private", json.dumps(projection))

    def test_canonical_digests_are_order_independent_and_content_free(self) -> None:
        first = _turn("Synthetic private marker omega")
        second = _turn("Synthetic private marker omega")
        self.assertEqual(first.turn_digest, second.turn_digest)
        self.assertEqual(first.continuation_digest, second.continuation_digest)
        projection = MemoryAwareTurnError("synthetic_rejection").content_free_projection(first)
        encoded = json.dumps(projection, sort_keys=True)
        self.assertNotIn("omega", encoded)
        self.assertNotIn(first.owner_message, encoded)

    def test_provider_envelope_is_exact_and_deterministic(self) -> None:
        turn = _turn()
        final = final_for_turn(turn, owner_message="Synthetic answer")
        first = _json(turn, final)
        second = _json(turn, final)
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)["schema"], STEP_RESPONSE_SCHEMA)

    def test_unicode_round_trip_preserves_only_the_typed_owner_message(self) -> None:
        turn = _turn("今晚想聊聊海边的风")
        final = final_for_turn(turn, owner_message="可以继续聊这段回忆🙂")

        parsed = parse_provider_step(_json(turn, final), turn)
        completed = complete_turn(turn, parsed, provider_attempts=1)

        self.assertEqual(completed.owner_message, "可以继续聊这段回忆🙂")


if __name__ == "__main__":
    unittest.main()
