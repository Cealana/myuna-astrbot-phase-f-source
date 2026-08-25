from __future__ import annotations

import json
import unittest

from myuna_core.owner_profile.loader import parse_profile_bytes
from myuna_core.owner_profile.write_candidate import (
    ANALYSIS_TYPE,
    CandidateAnalysis,
    CandidateChange,
    OwnerProfileCandidateError,
    analyze_candidate_with_local_provider,
    build_candidate_analysis_request,
    build_candidate_retrieval_query,
    candidate_audit_projection,
    parse_candidate_analysis,
    prepare_profile_candidate,
    render_candidate_preview,
    validate_confirmation_code,
)
from myuna_core.providers.base import ModelRequest, ModelResponse, ProviderError


BASE_PROFILE = """\
schema_version = 1
document_type = "owner_profile_baseline"
profile_id = "synthetic-owner"
profile_revision = 2

[[sections]]
section_id = "preference-communication"
topic_key = "preference.communication"
category = "long_term_preference"
title = "Communication"
body = "Prefers direct and low-pressure communication."
keywords = ["direct", "low pressure"]

[[sections]]
section_id = "project-lab"
topic_key = "project.synthetic_lab"
category = "ongoing_project"
title = "Synthetic lab"
body = "Maintains a synthetic home-lab project."
keywords = ["lab", "server"]
""".encode("utf-8")


def analysis_document(
    *,
    action: str = "add",
    topic_key: str = "goal.synthetic_language",
    category: str = "long_term_goal",
    title: str = "Language practice",
    body: str = "Wants to keep practising a second language over the long term.",
    keywords: list[str] | None = None,
    basis: str = "explicit_owner_statement",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "analysis_type": ANALYSIS_TYPE,
        "outcome": "candidate",
        "changes": [
            {
                "action": action,
                "category": category,
                "topic_key": topic_key,
                "title": title,
                "body": body,
                "keywords": keywords if keywords is not None else ["language", "practice"],
                "basis": basis,
            }
        ],
        "excluded_categories": [],
    }


class FakeProvider:
    default_model = "myuna-local-owner-v1"
    max_attempts = 1

    def __init__(
        self,
        document: dict[str, object],
        *,
        name: str = "local",
        response_provider: str = "local",
        finish_reason: str = "stop",
        error: ProviderError | None = None,
    ) -> None:
        self.name = name
        self.document = document
        self.response_provider = response_provider
        self.finish_reason = finish_reason
        self.error = error
        self.requests: list[ModelRequest] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return ModelResponse(
            provider=self.response_provider,
            model="myuna-local-owner-v1",
            text=json.dumps(self.document, ensure_ascii=False),
            input_tokens=10,
            output_tokens=10,
            cache_hit_tokens=0,
            cache_miss_tokens=10,
            reasoning_tokens=0,
            finish_reason=self.finish_reason,
        )


class CandidateAnalysisTests(unittest.TestCase):
    def test_parses_strict_unicode_candidate(self) -> None:
        document = analysis_document(
            title="长期学习",
            body="希望长期继续学习第二语言。",
            keywords=["语言", "长期学习"],
        )
        result = parse_candidate_analysis(json.dumps(document, ensure_ascii=False))
        self.assertEqual(result.outcome, "candidate")
        self.assertEqual(result.changes[0].title, "长期学习")

    def test_rejects_unknown_field(self) -> None:
        document = analysis_document()
        document["confidence"] = 0.9
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "malformed_candidate_analysis"
        ):
            parse_candidate_analysis(json.dumps(document))

    def test_strict_parser_rejects_string_schema_version(self) -> None:
        document = analysis_document()
        document["schema_version"] = "1"
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "unknown_candidate_schema"
        ):
            parse_candidate_analysis(json.dumps(document))

    def test_strict_parser_rejects_comma_separated_keywords(self) -> None:
        document = analysis_document()
        document["changes"][0]["keywords"] = "language, practice"
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "candidate_analysis_oversize"
        ):
            parse_candidate_analysis(json.dumps(document))

    def test_rejects_inferred_basis(self) -> None:
        document = analysis_document(basis="model_inference")
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "candidate_not_committable"
        ):
            parse_candidate_analysis(json.dumps(document))

    def test_rejects_temporal_body(self) -> None:
        document = analysis_document(body="Currently preparing a synthetic deadline.")
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "candidate_contains_temporal_content"
        ):
            parse_candidate_analysis(json.dumps(document))

    def test_rejects_sensitive_body(self) -> None:
        document = analysis_document(body="The API key is a synthetic secret value.")
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "candidate_contains_sensitive_content"
        ):
            parse_candidate_analysis(json.dumps(document))

    def test_non_candidate_outcome_cannot_include_changes(self) -> None:
        document = analysis_document()
        document["outcome"] = "no_change"
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "malformed_candidate_analysis"
        ):
            parse_candidate_analysis(json.dumps(document))


class CandidatePreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = parse_profile_bytes(BASE_PROFILE)

    def _analysis(self, **overrides: object) -> CandidateAnalysis:
        document = analysis_document(**overrides)
        return parse_candidate_analysis(json.dumps(document, ensure_ascii=False))

    def test_prepares_deterministic_add_revision(self) -> None:
        candidate = prepare_profile_candidate(self.base, self._analysis())
        self.assertEqual(candidate.target.profile_revision, 3)
        self.assertEqual(candidate.summary.added_sections, 1)
        self.assertEqual(candidate.summary.updated_sections, 0)
        self.assertEqual(len(candidate.confirmation_code), 12)
        self.assertEqual(candidate.target.sha256, parse_profile_bytes(candidate.target_bytes).sha256)
        repeated = prepare_profile_candidate(self.base, self._analysis())
        self.assertEqual(candidate.target_bytes, repeated.target_bytes)

    def test_updates_existing_topic_without_changing_section_id(self) -> None:
        analysis = self._analysis(
            action="update",
            topic_key="preference.communication",
            category="long_term_preference",
            title="Communication style",
            body="Prefers concise, direct and low-pressure communication.",
            keywords=["direct", "concise"],
        )
        candidate = prepare_profile_candidate(self.base, analysis)
        updated = next(
            section
            for section in candidate.target.sections
            if section.topic_key == "preference.communication"
        )
        self.assertEqual(updated.section_id, "preference-communication")
        self.assertEqual(candidate.summary.updated_sections, 1)

    def test_rejects_add_to_existing_topic(self) -> None:
        with self.assertRaisesRegex(OwnerProfileCandidateError, "candidate_topic_conflict"):
            prepare_profile_candidate(
                self.base,
                self._analysis(
                    topic_key="preference.communication",
                    category="long_term_preference",
                ),
            )

    def test_rejects_duplicate_content(self) -> None:
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "candidate_duplicate_content"
        ):
            prepare_profile_candidate(
                self.base,
                self._analysis(body="Maintains a synthetic home-lab project."),
            )

    def test_preview_contains_exact_changed_content_and_confirmation(self) -> None:
        candidate = prepare_profile_candidate(
            self.base,
            self._analysis(title="长期学习", body="希望长期继续学习第二语言。"),
        )
        preview = render_candidate_preview(candidate)
        self.assertIn("希望长期继续学习第二语言。", preview)
        self.assertIn(candidate.confirmation_code, preview)
        self.assertIn("尚未写入", preview)

    def test_confirmation_code_is_exact(self) -> None:
        candidate = prepare_profile_candidate(self.base, self._analysis())
        self.assertEqual(
            validate_confirmation_code(candidate.confirmation_code),
            candidate.confirmation_code,
        )
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "candidate_confirmation_rejected"
        ):
            validate_confirmation_code(candidate.confirmation_code.lower())


class CandidateProviderTests(unittest.TestCase):
    def test_retrieval_query_is_relevant_and_bounded(self) -> None:
        source = "长期偏好直接沟通。" * 80
        query = build_candidate_retrieval_query(source)
        self.assertEqual(query, source[:256])
        self.assertEqual(len(query), 256)

    def test_request_is_json_only_and_bounded(self) -> None:
        request = build_candidate_analysis_request(
            request_id="synthetic-request",
            source_text="I want to practise a second language for years.",
            relevant_profile_context=None,
        )
        self.assertEqual(request.response_format, "json_object")
        self.assertEqual(request.model, "myuna-local-owner-v1")
        self.assertEqual(len(request.messages), 2)
        self.assertIn(
            "workflow preference and must use long_term_preference",
            request.messages[0]["content"],
        )
        self.assertIn(
            "self_introduction is only stable factual identity",
            request.messages[0]["content"],
        )
        self.assertIn("existing_profile_reference_do_not_extract", request.messages[1]["content"])
        self.assertNotIn('"relevant_profile_context"', request.messages[1]["content"])

    def test_local_provider_result_is_strictly_parsed(self) -> None:
        provider = FakeProvider(analysis_document())
        result = analyze_candidate_with_local_provider(
            provider,
            request_id="synthetic-request",
            source_text="I want to practise a second language for years.",
            relevant_profile_context=None,
        )
        self.assertEqual(result.outcome, "candidate")
        self.assertEqual(len(provider.requests), 1)

    def test_local_provider_exact_string_schema_version_is_normalized(self) -> None:
        document = analysis_document()
        document["schema_version"] = "1"
        provider = FakeProvider(document)
        result = analyze_candidate_with_local_provider(
            provider,
            request_id="synthetic-request",
            source_text="I want to practise a second language for years.",
            relevant_profile_context=None,
        )
        self.assertEqual(result.outcome, "candidate")

    def test_local_provider_other_string_schema_version_is_rejected(self) -> None:
        document = analysis_document()
        document["schema_version"] = "2"
        provider = FakeProvider(document)
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "unknown_candidate_schema"
        ):
            analyze_candidate_with_local_provider(
                provider,
                request_id="synthetic-request",
                source_text="Synthetic stable preference.",
                relevant_profile_context=None,
            )

    def test_local_provider_comma_separated_keywords_are_normalized(self) -> None:
        document = analysis_document()
        document["changes"][0]["keywords"] = "language, practice"
        provider = FakeProvider(document)
        result = analyze_candidate_with_local_provider(
            provider,
            request_id="synthetic-request",
            source_text="Synthetic stable preference.",
            relevant_profile_context=None,
        )
        self.assertEqual(result.changes[0].keywords, ("language", "practice"))

    def test_local_provider_oversize_keyword_string_is_rejected(self) -> None:
        document = analysis_document()
        document["changes"][0]["keywords"] = "a,b,c,d,e,f,g"
        provider = FakeProvider(document)
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "candidate_analysis_oversize"
        ):
            analyze_candidate_with_local_provider(
                provider,
                request_id="synthetic-request",
                source_text="Synthetic stable preference.",
                relevant_profile_context=None,
            )

    def test_local_provider_narrow_chinese_workflow_category_is_corrected(self) -> None:
        document = analysis_document(
            category="self_introduction",
            topic_key="self_introduction",
        )
        provider = FakeProvider(document)
        result = analyze_candidate_with_local_provider(
            provider,
            request_id="synthetic-request",
            source_text=(
                "对于复杂任务，我希望在实际变更前先明确完成条件和恢复方案。"
            ),
            relevant_profile_context=None,
        )
        self.assertEqual(result.changes[0].category, "long_term_preference")
        self.assertEqual(
            result.changes[0].topic_key,
            "preference.project_acceptance_rollback",
        )

    def test_local_provider_narrow_chinese_generic_workflow_key_is_corrected(self) -> None:
        document = analysis_document(
            category="long_term_preference",
            topic_key="workflow",
        )
        provider = FakeProvider(document)
        result = analyze_candidate_with_local_provider(
            provider,
            request_id="synthetic-request",
            source_text=(
                "对于复杂任务，我希望在实际变更前先明确完成条件和恢复方案。"
            ),
            relevant_profile_context=None,
        )
        self.assertEqual(result.changes[0].category, "long_term_preference")
        self.assertEqual(
            result.changes[0].topic_key,
            "preference.project_acceptance_rollback",
        )

    def test_local_provider_does_not_broadly_reclassify_chinese(self) -> None:
        document = analysis_document(
            category="self_introduction",
            topic_key="self_introduction",
        )
        provider = FakeProvider(document)
        result = analyze_candidate_with_local_provider(
            provider,
            request_id="synthetic-request",
            source_text="我希望未来完成一个长期学习目标。",
            relevant_profile_context=None,
        )
        self.assertEqual(result.changes[0].category, "self_introduction")
        self.assertEqual(result.changes[0].topic_key, "self_introduction")

    def test_external_provider_is_rejected_before_call(self) -> None:
        provider = FakeProvider(analysis_document(), name="deepseek")
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "candidate_provider_forbidden"
        ):
            analyze_candidate_with_local_provider(
                provider,
                request_id="synthetic-request",
                source_text="Synthetic stable preference.",
                relevant_profile_context=None,
            )
        self.assertEqual(provider.requests, [])

    def test_truncated_provider_result_is_rejected(self) -> None:
        provider = FakeProvider(analysis_document(), finish_reason="length")
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "candidate_provider_response_rejected"
        ):
            analyze_candidate_with_local_provider(
                provider,
                request_id="synthetic-request",
                source_text="Synthetic stable preference.",
                relevant_profile_context=None,
            )

    def test_provider_failure_is_content_free(self) -> None:
        provider = FakeProvider(
            analysis_document(),
            error=ProviderError(
                "local_timeout",
                "synthetic upstream text",
                retryable=True,
            ),
        )
        with self.assertRaisesRegex(
            OwnerProfileCandidateError, "candidate_provider_unavailable"
        ) as caught:
            analyze_candidate_with_local_provider(
                provider,
                request_id="synthetic-request",
                source_text="Synthetic stable preference.",
                relevant_profile_context=None,
            )
        self.assertTrue(caught.exception.retryable)

    def test_audit_projection_contains_no_content(self) -> None:
        analysis = parse_candidate_analysis(json.dumps(analysis_document()))
        candidate = prepare_profile_candidate(parse_profile_bytes(BASE_PROFILE), analysis)
        projection = candidate_audit_projection(
            operation="prepare",
            outcome="accepted",
            analysis=analysis,
            candidate=candidate,
        )
        serialized = json.dumps(projection, sort_keys=True)
        self.assertNotIn("Language practice", serialized)
        self.assertFalse(projection["raw_input_recorded"])
        self.assertFalse(projection["candidate_content_recorded"])
        self.assertFalse(projection["identity_recorded"])


if __name__ == "__main__":
    unittest.main()
