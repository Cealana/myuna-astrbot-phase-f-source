from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest

from myuna_core.authenticated_conversation import (
    SCHEMA_VERSION as CONTEXT_SCHEMA_VERSION,
    AuthenticatedConversationContext,
)
from myuna_core.channel_capability import ChannelNeutralCapabilityProfile
from myuna_core.owner_profile.contracts import RetrievalResult
from myuna_core.owner_profile.loader import parse_profile_bytes
from myuna_core.owner_profile.write_candidate import ANALYSIS_TYPE
from myuna_core.owner_profile.write_runtime import (
    FilesystemOwnerProfileCandidateBackend,
    OwnerProfileWriteAccessError,
    OwnerProfileWriteAccessPolicy,
    OwnerProfileWriteRuntime,
    PublishedProfileCandidate,
)
from myuna_core.owner_profile.write_store import (
    OwnerProfileCandidateStoreError,
    initialize_candidate_store,
)
from myuna_core.providers.base import ModelRequest, ModelResponse


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
""".encode("utf-8")


def write_profile() -> ChannelNeutralCapabilityProfile:
    return ChannelNeutralCapabilityProfile.from_document(
        {
            "schema_version": 1,
            "profile_id": "owner-private-profile-write-v1",
            "environment": "dev",
            "response_scope": "owner_private_dev_profile_write_v1",
            "subject": {
                "channel_kinds": ["astrbot_telegram"],
                "conversation_kinds": ["private"],
                "authority_levels": ["owner"],
            },
            "delivery_capabilities": ["text"],
            "memory_protocol": "profile-write-v1",
            "capabilities": {
                "conversation": True,
                "long_term_memory_read": True,
                "long_term_memory_write": True,
                "vision": False,
                "tools": False,
                "external_data": False,
                "external_actions": False,
                "system_administration": False,
            },
        }
    )


def owner_context(
    *,
    conversation_id: str = "conversation-synthetic",
    consent: bool = True,
) -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version=CONTEXT_SCHEMA_VERSION,
        request_id="request-synthetic",
        correlation_id="correlation-synthetic",
        client_id="telegram-owner-private",
        channel_kind="astrbot_telegram",
        binding_id="binding-synthetic",
        principal_id="principal-synthetic",
        namespace_id="namespace-synthetic",
        authority_level="owner",
        channel_instance="telegram-dev",
        conversation_id=conversation_id,
        conversation_kind="private",
        event_id="event-synthetic",
        trace_id="trace-synthetic",
        occurred_at=datetime(2035, 1, 2, tzinfo=timezone.utc),
        delivery_capabilities=("text",),
        consent_memory_candidate=consent,
    )


def analysis_document(*, outcome: str = "candidate") -> dict[str, object]:
    changes: list[dict[str, object]] = []
    if outcome == "candidate":
        changes.append(
            {
                "action": "add",
                "category": "long_term_goal",
                "topic_key": "goal.synthetic_electronics",
                "title": "Synthetic electronics",
                "body": "Wants to keep learning synthetic electronics.",
                "keywords": ["electronics", "learning"],
                "basis": "explicit_owner_statement",
            }
        )
    return {
        "schema_version": 1,
        "analysis_type": ANALYSIS_TYPE,
        "outcome": outcome,
        "changes": changes,
        "excluded_categories": ["duplicate"] if outcome == "no_change" else [],
    }


class FakeProvider:
    default_model = "myuna-local-owner-v1"
    max_attempts = 1

    def __init__(self, *, name: str = "local", outcome: str = "candidate") -> None:
        self.name = name
        self.outcome = outcome
        self.requests: list[ModelRequest] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return ModelResponse(
            provider=self.name,
            model="myuna-local-owner-v1",
            text=json.dumps(analysis_document(outcome=self.outcome)),
            input_tokens=10,
            output_tokens=10,
            cache_hit_tokens=0,
            cache_miss_tokens=10,
            reasoning_tokens=0,
            finish_reason="stop",
        )


class FakeReadRuntime:
    def __init__(self, base_sha256: str) -> None:
        self.base_sha256 = base_sha256
        self.calls: list[tuple[str, str]] = []

    def retrieve(self, query: str, *, request_id: str, channel_kind: str) -> RetrievalResult:
        self.calls.append((query, channel_kind))
        return RetrievalResult(
            state="empty",
            profile_revision=2,
            profile_sha256=self.base_sha256,
            query_characters=len(query),
            sections=(),
            context=None,
        )


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, object]]] = []

    def emit(
        self,
        event: str,
        *,
        outcome: str,
        request_id: str,
        details: dict[str, object],
    ) -> None:
        self.events.append((event, outcome, dict(details)))


class OwnerProfileWriteRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "candidate-store"
        initialize_candidate_store(self.root, expected_uid=os.geteuid())
        self.active = parse_profile_bytes(BASE_PROFILE)
        self.published = []
        self.read_runtime = FakeReadRuntime(self.active.sha256)
        self.audit = FakeAudit()
        self.provider = FakeProvider()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _publisher(self, stored) -> PublishedProfileCandidate:
        target = parse_profile_bytes(stored.target_profile_bytes)
        self.published.append(stored.record_sha256)
        self.active = target
        return PublishedProfileCandidate(
            target_revision=target.profile_revision,
            target_sha256=target.sha256,
        )

    def _runtime(self, provider=None, publisher=None) -> OwnerProfileWriteRuntime:
        backend = FilesystemOwnerProfileCandidateBackend(
            store_root=self.root,
            active_profile_loader=lambda: self.active,
            publisher=publisher or self._publisher,
            expected_uid=os.geteuid(),
        )
        return OwnerProfileWriteRuntime(
            access_policy=OwnerProfileWriteAccessPolicy(write_profile()),
            read_runtime=self.read_runtime,
            provider=provider or self.provider,
            backend=backend,
            audit=self.audit,
        )

    def test_proposal_then_exact_confirmation_writes_once(self) -> None:
        runtime = self._runtime()
        proposal = runtime.handle(
            "/Benchmark I want to keep learning synthetic electronics.",
            request_id="proposal-synthetic",
            authenticated_context=owner_context(),
            now=datetime(2035, 1, 2, 3, tzinfo=timezone.utc),
        )
        self.assertEqual(proposal.action, "prepared")
        self.assertFalse(proposal.memory_write_performed)
        self.assertEqual(self.active.profile_revision, 2)
        code = proposal.reply.split("/Benchmark confirm ", 1)[1].splitlines()[0]
        confirmed = runtime.handle(
            f"/Benchmark confirm {code}",
            request_id="confirm-synthetic",
            authenticated_context=owner_context(),
            now=datetime(2035, 1, 2, 4, tzinfo=timezone.utc),
        )
        self.assertTrue(confirmed.memory_write_performed)
        self.assertEqual(confirmed.target_revision, 3)
        self.assertEqual(self.active.profile_revision, 3)
        self.assertEqual(len(self.published), 1)
        self.assertFalse(self.audit.events[0][2]["raw_input_recorded"])
        self.assertFalse(self.audit.events[0][2]["candidate_content_recorded"])

    def test_confirmation_from_different_conversation_cannot_find_candidate(self) -> None:
        runtime = self._runtime()
        proposal = runtime.handle(
            "/Benchmark I want to keep learning synthetic electronics.",
            request_id="proposal-synthetic",
            authenticated_context=owner_context(),
            now=datetime(2035, 1, 2, 3, tzinfo=timezone.utc),
        )
        code = proposal.reply.split("/Benchmark confirm ", 1)[1].splitlines()[0]
        with self.assertRaisesRegex(OwnerProfileCandidateStoreError, "candidate_not_found"):
            runtime.handle(
                f"/Benchmark confirm {code}",
                request_id="confirm-other-scope",
                authenticated_context=owner_context(conversation_id="other-conversation"),
                now=datetime(2035, 1, 2, 4, tzinfo=timezone.utc),
            )

    def test_retry_after_publish_before_candidate_consumption_is_idempotent(self) -> None:
        attempts = 0

        def crash_once(stored) -> PublishedProfileCandidate:
            nonlocal attempts
            attempts += 1
            target = parse_profile_bytes(stored.target_profile_bytes)
            self.active = target
            if attempts == 1:
                raise RuntimeError("synthetic post-publish crash")
            return PublishedProfileCandidate(
                target_revision=target.profile_revision,
                target_sha256=target.sha256,
                already_published=True,
            )

        runtime = self._runtime(publisher=crash_once)
        proposal = runtime.handle(
            "/Benchmark I want to keep learning synthetic electronics.",
            request_id="proposal-crash-synthetic",
            authenticated_context=owner_context(),
            now=datetime(2035, 1, 2, 3, tzinfo=timezone.utc),
        )
        code = proposal.reply.split("/Benchmark confirm ", 1)[1].splitlines()[0]
        with self.assertRaisesRegex(RuntimeError, "synthetic post-publish crash"):
            runtime.handle(
                f"/Benchmark confirm {code}",
                request_id="confirm-crash-synthetic",
                authenticated_context=owner_context(),
                now=datetime(2035, 1, 2, 4, tzinfo=timezone.utc),
            )
        confirmed = runtime.handle(
            f"/Benchmark confirm {code}",
            request_id="confirm-retry-synthetic",
            authenticated_context=owner_context(),
            now=datetime(2035, 1, 2, 5, tzinfo=timezone.utc),
        )
        self.assertTrue(confirmed.memory_write_performed)
        self.assertEqual(attempts, 2)

    def test_no_change_does_not_stage_or_publish(self) -> None:
        provider = FakeProvider(outcome="no_change")
        result = self._runtime(provider).handle(
            "/Benchmark This synthetic preference is already present.",
            request_id="no-change-synthetic",
            authenticated_context=owner_context(),
            now=datetime(2035, 1, 2, 3, tzinfo=timezone.utc),
        )
        self.assertEqual(result.action, "no_change")
        self.assertFalse(result.memory_write_performed)
        self.assertEqual(self.published, [])

    def test_missing_consent_rejects_before_read_or_provider(self) -> None:
        runtime = self._runtime()
        with self.assertRaises(OwnerProfileWriteAccessError) as caught:
            runtime.handle(
                "/Benchmark Synthetic stable preference.",
                request_id="no-consent-synthetic",
                authenticated_context=owner_context(consent=False),
                now=datetime(2035, 1, 2, 3, tzinfo=timezone.utc),
            )
        self.assertEqual(caught.exception.code, "memory_candidate_consent_required")
        self.assertEqual(self.read_runtime.calls, [])
        self.assertEqual(self.provider.requests, [])

    def test_external_provider_rejects_before_profile_retrieval(self) -> None:
        provider = FakeProvider(name="deepseek")
        with self.assertRaises(OwnerProfileWriteAccessError) as caught:
            self._runtime(provider).handle(
                "/Benchmark Synthetic stable preference.",
                request_id="external-provider-synthetic",
                authenticated_context=owner_context(),
                now=datetime(2035, 1, 2, 3, tzinfo=timezone.utc),
            )
        self.assertEqual(caught.exception.code, "candidate_provider_forbidden")
        self.assertEqual(self.read_runtime.calls, [])
        self.assertEqual(provider.requests, [])

    def test_cancel_closes_candidate_without_publish(self) -> None:
        runtime = self._runtime()
        proposal = runtime.handle(
            "/Benchmark I want to keep learning synthetic electronics.",
            request_id="proposal-synthetic",
            authenticated_context=owner_context(),
            now=datetime(2035, 1, 2, 3, tzinfo=timezone.utc),
        )
        code = proposal.reply.split("/Benchmark confirm ", 1)[1].splitlines()[0]
        cancelled = runtime.handle(
            f"/Benchmark cancel {code}",
            request_id="cancel-synthetic",
            authenticated_context=owner_context(),
            now=datetime(2035, 1, 2, 4, tzinfo=timezone.utc),
        )
        self.assertEqual(cancelled.action, "cancelled")
        self.assertFalse(cancelled.memory_write_performed)
        self.assertEqual(self.published, [])


if __name__ == "__main__":
    unittest.main()
