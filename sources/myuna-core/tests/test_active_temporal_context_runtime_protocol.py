from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.active_temporal_context import (
    ActiveTemporalContextRuntime,
    TemporalAccessPolicy,
    TemporalContextStore,
    TemporalFactDraft,
    TrustedTimeSample,
)
from myuna_core.active_temporal_context.protocol import (
    ActiveSnapshotReceipt,
    BOUNDARY,
    CONTENT_FREE_STATUS_SCHEMA,
    CONTENT_FREE_STATUS_SOURCE_IDENTITY,
    SCHEMA,
    process_request,
)
from myuna_core.authenticated_conversation import AuthenticatedConversationContext


NOW = datetime(2026, 8, 5, 6, 0, tzinfo=timezone.utc)


class _Clock:
    def __init__(self) -> None:
        self.sequence = 0

    def sample(self) -> TrustedTimeSample:
        self.sequence += 1
        return TrustedTimeSample(
            NOW + timedelta(seconds=self.sequence),
            "synthetic-clock-v1",
            "synthetic",
            self.sequence,
        )


class _EvidenceClock:
    def __init__(self) -> None:
        self.sequence = 0

    def sample(self) -> TrustedTimeSample:
        self.sequence += 1
        return TrustedTimeSample(
            NOW + timedelta(seconds=self.sequence),
            "myuna-trusted-local-v1",
            "trusted_local",
            self.sequence,
            authority="synthetic-authority",
            uncertainty_microseconds=1_000,
            synchronized=True,
            boot_id="synthetic-boot",
            monotonic_ns=10_000 + self.sequence,
        )


def _context(request_id: str, *, consent: bool = True) -> AuthenticatedConversationContext:
    return AuthenticatedConversationContext(
        schema_version="myuna.authenticated-conversation-context.v1",
        request_id=request_id,
        correlation_id=request_id,
        client_id="telegram-owner-runtime-v1",
        channel_kind="astrbot_telegram",
        binding_id="binding-v1",
        principal_id="owner-v1",
        namespace_id="telegram-owner-v1",
        authority_level="owner",
        channel_instance="telegram-primary",
        conversation_id="owner-private-v1",
        conversation_kind="private",
        event_id="event-v1",
        trace_id="trace-v1",
        occurred_at=NOW,
        delivery_capabilities=("text",),
        consent_memory_candidate=consent,
    )


class RuntimeProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "private"
        root.mkdir(mode=0o700)
        store = TemporalContextStore.create(root / "temporal.sqlite3")
        self.runtime = ActiveTemporalContextRuntime(store, _Clock())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _call(self, request_id: str, operation: str, body: dict[str, object]) -> dict[str, object]:
        raw = json.dumps(
            {
                "schema": SCHEMA,
                "boundary": BOUNDARY,
                "operation": operation,
                "request_id": request_id,
                "authenticated_context": _context(request_id).as_payload(),
                "input": body,
            }
        ).encode()
        return json.loads(
            process_request(
                raw,
                self.runtime,
                authenticated_client_id="telegram-owner-runtime-v1",
                authenticated_channel_kind="astrbot_telegram",
            )
        )

    def _status_body(
        self,
        request_id: str,
        **overrides: object,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "expected_scope_digest": TemporalAccessPolicy()
            .authorize_read(_context(request_id))
            .scope_sha256,
            "expected_source_identity": CONTENT_FREE_STATUS_SOURCE_IDENTITY,
            "minimum_lifecycle_watermark": 0,
            "request_nonce": "a" * 64,
            "response_schema": CONTENT_FREE_STATUS_SCHEMA,
        }
        payload.update(overrides)
        return payload

    def test_propose_confirm_retrieve_round_trip(self) -> None:
        draft = TemporalFactDraft(
            "temporary_plan",
            "dinner-plan",
            "Dinner with a friend tonight",
            "owner_statement",
            "telegram",
            "telegram-event-v1",
            NOW,
            None,
            NOW + timedelta(days=1),
        )
        proposal = self._call(
            "request-propose",
            "propose",
            {
                "explicit_intent": True,
                "action": "create",
                "draft": draft.as_payload(),
                "target_fact_id": None,
                "ttl_seconds": 300,
            },
        )
        self.assertTrue(proposal["ok"])
        confirmed = self._call(
            "request-confirm",
            "confirm",
            {
                "explicit_intent": True,
                "proposal_id": proposal["output"]["proposal_id"],
                "confirmation_code": proposal["output"]["confirmation_code"],
            },
        )
        self.assertEqual(confirmed["output"]["outcome"], "active")
        retrieved = self._call(
            "request-retrieve",
            "retrieve",
            {"query": "dinner plan", "categories": [], "slot_keys": []},
        )
        self.assertEqual(retrieved["output"]["state"], "selected")
        self.assertEqual(retrieved["output"]["fact_count"], 1)
        self.assertFalse(retrieved["model_called"])

    def test_context_client_mismatch_fails_closed(self) -> None:
        raw = json.dumps(
            {
                "schema": SCHEMA,
                "boundary": BOUNDARY,
                "operation": "retrieve",
                "request_id": "request-v1",
                "authenticated_context": _context("request-v1").as_payload(),
                "input": {"query": "plan", "categories": [], "slot_keys": []},
            }
        ).encode()
        response = json.loads(
            process_request(
                raw,
                self.runtime,
                authenticated_client_id="wrong-client",
                authenticated_channel_kind="astrbot_telegram",
            )
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_no_time_sample_after_unauthorized_read(self) -> None:
        clock = _Clock()
        self.runtime.trusted_time = clock
        context = _context("request-v1")
        object.__setattr__(context, "authority_level", "member")
        with self.assertRaises(Exception):
            self.runtime.retrieve(context, query="plan")
        self.assertEqual(clock.sequence, 0)

    def test_active_snapshot_returns_all_or_none_with_one_evidence_sample(self) -> None:
        clock = _EvidenceClock()
        self.runtime.trusted_time = clock
        response = self._call("request-snapshot", "snapshot_active", {})
        self.assertTrue(response["ok"])
        self.assertEqual(response["output"]["fact_count"], 0)
        self.assertIn("all_or_none=true", response["output"]["context"])
        self.assertTrue(response["output"]["trusted_time"]["synchronized"])
        receipt = ActiveSnapshotReceipt.from_payload(
            response["output"]["active_snapshot_receipt"]
        )
        self.assertEqual(receipt.request_id, "request-snapshot")
        self.assertEqual(receipt.after_event_sequence, 0)
        self.assertTrue(
            receipt.matches_lifecycle_page(
                after_event_sequence=0,
                transitions=response["output"]["lifecycle_transitions"],
                lifecycle_watermark=response["output"]["lifecycle_watermark"],
                lifecycle_has_more=response["output"]["lifecycle_has_more"],
            )
        )
        self.assertTrue(
            receipt.matches_trusted_time_payload(
                response["output"]["trusted_time"]
            )
        )
        self.assertTrue(
            receipt.matches_source_tuple(
                request_id="request-snapshot",
                after_event_sequence=0,
                fact_count=response["output"]["fact_count"],
                transitions=response["output"]["lifecycle_transitions"],
                lifecycle_watermark=response["output"]["lifecycle_watermark"],
                lifecycle_has_more=response["output"]["lifecycle_has_more"],
                trusted_time=response["output"]["trusted_time"],
            )
        )
        self.assertFalse(
            receipt.matches_source_tuple(
                request_id="request-substituted",
                after_event_sequence=0,
                fact_count=response["output"]["fact_count"],
                transitions=response["output"]["lifecycle_transitions"],
                lifecycle_watermark=response["output"]["lifecycle_watermark"],
                lifecycle_has_more=response["output"]["lifecycle_has_more"],
                trusted_time=response["output"]["trusted_time"],
            )
        )
        self.assertEqual(clock.sequence, 1)

    def test_active_snapshot_receipt_binds_request_cursor_and_non_rendered_fields(
        self,
    ) -> None:
        self.runtime.trusted_time = _EvidenceClock()
        first = self._call(
            "request-snapshot-a",
            "snapshot_active",
            {"after_event_sequence": 0},
        )
        second = self._call(
            "request-snapshot-b",
            "snapshot_active",
            {"after_event_sequence": 0},
        )
        first_receipt = ActiveSnapshotReceipt.from_payload(
            first["output"]["active_snapshot_receipt"]
        )
        second_receipt = ActiveSnapshotReceipt.from_payload(
            second["output"]["active_snapshot_receipt"]
        )
        self.assertNotEqual(
            first_receipt.response_identity,
            second_receipt.response_identity,
        )
        self.assertNotEqual(first_receipt.receipt_digest, second_receipt.receipt_digest)

    def test_active_snapshot_rejects_whole_layer_overflow(self) -> None:
        self.runtime.trusted_time = _EvidenceClock()
        with patch(
            "myuna_core.active_temporal_context.runtime.MAX_ACTIVE_SNAPSHOT_CHARACTERS",
            1,
        ):
            response = self._call("request-overflow", "snapshot_active", {})
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "active_projection_overflow")

    def test_content_free_status_returns_complete_identity_without_temporal_text(self) -> None:
        self.runtime.trusted_time = _EvidenceClock()
        private_summary = "synthetic private dinner by the riverside"
        draft = TemporalFactDraft(
            "temporary_plan",
            "private-dinner-plan",
            private_summary,
            "owner_statement",
            "telegram",
            "private-event-v1",
            NOW,
            None,
            NOW + timedelta(days=1),
        )
        proposal = self._call(
            "request-status-propose",
            "propose",
            {
                "explicit_intent": True,
                "action": "create",
                "draft": draft.as_payload(),
                "target_fact_id": None,
                "ttl_seconds": 300,
            },
        )
        self._call(
            "request-status-confirm",
            "confirm",
            {
                "explicit_intent": True,
                "proposal_id": proposal["output"]["proposal_id"],
                "confirmation_code": proposal["output"]["confirmation_code"],
            },
        )
        response = self._call(
            "request-status",
            "status_content_free",
            self._status_body("request-status"),
        )
        self.assertTrue(response["ok"])
        output = response["output"]
        self.assertEqual(
            set(output),
            {
                "active_fact_count",
                "active_set_complete",
                "active_set_digest",
                "lifecycle_complete",
                "lifecycle_digest",
                "lifecycle_event_count",
                "lifecycle_watermark",
                "pending_proposal_count",
                "request_nonce",
                "response_digest",
                "scope_binding_digest",
                "source_identity",
                "status_digest",
                "status_schema",
                "total_fact_count",
                "trusted_time_binding_digest",
                "trusted_time_evidence_complete",
            },
        )
        self.assertEqual(output["active_fact_count"], 1)
        self.assertEqual(output["lifecycle_event_count"], 1)
        self.assertEqual(output["lifecycle_watermark"], 1)
        self.assertTrue(output["active_set_complete"])
        self.assertTrue(output["lifecycle_complete"])
        self.assertTrue(output["trusted_time_evidence_complete"])
        self.assertEqual(output["source_identity"], CONTENT_FREE_STATUS_SOURCE_IDENTITY)
        self.assertEqual(output["status_schema"], CONTENT_FREE_STATUS_SCHEMA)
        for field in (
            "model_called",
            "profile_written",
            "session_written",
            "legacy_namespace_written",
            "channel_called",
            "health_called",
            "private_content_returned",
            "provider_called",
        ):
            self.assertIs(response[field], False)
        serialized = json.dumps(response, ensure_ascii=False, sort_keys=True)
        for forbidden in (
            private_summary,
            "private-dinner-plan",
            "private-event-v1",
            '"context":',
            '"trusted_time":',
            '"fact_id":',
            '"source_ref":',
            '"query":',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_content_free_status_binds_nonce_scope_source_and_watermark(self) -> None:
        clock = _EvidenceClock()
        self.runtime.trusted_time = clock
        first = self._call(
            "request-status-a",
            "status_content_free",
            self._status_body("request-status-a"),
        )
        second = self._call(
            "request-status-b",
            "status_content_free",
            self._status_body("request-status-b", request_nonce="b" * 64),
        )
        self.assertTrue(first["ok"])
        self.assertTrue(second["ok"])
        self.assertEqual(first["output"]["status_digest"], second["output"]["status_digest"])
        self.assertNotEqual(
            first["output"]["response_digest"], second["output"]["response_digest"]
        )

        wrong_scope = self._call(
            "request-status-scope",
            "status_content_free",
            self._status_body("request-status-scope", expected_scope_digest="f" * 64),
        )
        self.assertFalse(wrong_scope["ok"])
        self.assertEqual(wrong_scope["error"]["code"], "status_scope_mismatch")

        wrong_source = self._call(
            "request-status-source",
            "status_content_free",
            self._status_body("request-status-source", expected_source_identity="f" * 64),
        )
        self.assertFalse(wrong_source["ok"])
        self.assertEqual(wrong_source["error"]["code"], "invalid_request")

        stale = self._call(
            "request-status-stale",
            "status_content_free",
            self._status_body("request-status-stale", minimum_lifecycle_watermark=1),
        )
        self.assertFalse(stale["ok"])
        self.assertEqual(stale["error"]["code"], "status_lifecycle_stale")

        malformed = self._status_body("request-status-malformed", request_nonce="short")
        malformed["unexpected"] = False
        rejected = self._call(
            "request-status-malformed",
            "status_content_free",
            malformed,
        )
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["error"]["code"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
