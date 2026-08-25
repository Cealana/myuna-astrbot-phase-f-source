from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4


from degradation_shadow_enqueue import DegradationShadowJob
from gateway_degradation_protocol import (
    CANONICAL_DEGRADATION_REPLIES,
    CORE_FAILURE_PROVENANCE_SCHEMA,
    CORE_FAILURE_PROVENANCE_SCHEMA_V1,
    CORE_FAILURE_RESPONSE_SCHEMA,
    CORE_FAILURE_RESPONSE_SCHEMA_V1,
    SAFE_DEGRADATION_SCHEMA,
    _CORE_PRE_PROVIDER_FAILURE_GATES as GATEWAY_PRE_PROVIDER_FAILURE_GATES,
    deterministic_gateway_failure_provenance,
    deterministic_gateway_projection,
    validate_core_failure_response_with_provenance,
)
from gateway_post_reply import PostConnectionFanout, serve_accepted_connection
from incident_history_runtime_adapter_v1 import (
    INCIDENT_HISTORY_MARKER,
    INCIDENT_HISTORY_ROOT,
    INCIDENT_HISTORY_SELECTOR_SCHEMA,
    append_incident_history_after_response,
    build_incident_history_job,
    http_outcome_class,
    latency_bucket,
    load_approved_incident_history_selector,
    validate_incident_history_selector,
)
from incident_history_v1 import (
    EVIDENCE_SCHEMA_V1,
    IncidentEvidence,
    IncidentHistoryStore,
    _CORE_PRE_PROVIDER_FAILURE_GATES as HISTORY_PRE_PROVIDER_FAILURE_GATES,
)
import qq_owner_runtime_gateway as qq_runtime
import telegram_owner_runtime_gateway as telegram_runtime
from myuna_core.degradation_bridge import _PROVIDER_CODE_MAP
from myuna_core.degradation_http import attach_provider_failure_metadata
from myuna_core.degradation_http import (
    _PRE_PROVIDER_FAILURE_GATES as CORE_PRE_PROVIDER_FAILURE_GATES,
)


NOW = datetime(2026, 8, 6, 8, 0, tzinfo=timezone.utc)
RELEASE_SET_ID = "a" * 64


def selector_payload(*, root: Path = INCIDENT_HISTORY_ROOT) -> dict[str, object]:
    return {
        "schema": INCIDENT_HISTORY_SELECTOR_SCHEMA,
        "status": "approved",
        "channel": "telegram",
        "marker_path": str(INCIDENT_HISTORY_MARKER),
        "history_root": str(root),
        "capacity": 128,
        "bundle_digest": "1" * 64,
        "core_release_digest": "2" * 64,
        "runtime_release_digest": "3" * 64,
        "plugin_release_digest": "4" * 64,
        "adapter_release_digest": "5" * 64,
        "core_source_commit": "6" * 40,
        "deploy_source_commit": "7" * 40,
        "public_reply_contract": "unchanged",
        "write_boundary": "post_response_failure_only",
    }


def projection(
    detail: str,
    *,
    category: str,
    retryable: bool,
    owner_action_required: bool = False,
) -> dict[str, object]:
    return {
        "schema": SAFE_DEGRADATION_SCHEMA,
        "status": "degraded",
        "category": category,
        "retryable": retryable,
        "owner_action_required": owner_action_required,
        "safe_detail_code": detail,
        "recovery_state": "active",
        "fingerprint": f"{category}:synthetic:{detail}",
        "reply": CANONICAL_DEGRADATION_REPLIES[category],
    }


def provenance(
    stage: str,
    *,
    outcome: str,
    attempts: int | None,
    provider_called: bool | None,
    model_called: bool | None,
    profile_called: bool | None,
    persona: str = "not_evaluated",
    output_guard: bool | None = False,
    failure_gate: str = "unknown",
) -> dict[str, object]:
    return {
        "schema": CORE_FAILURE_PROVENANCE_SCHEMA,
        "failure_gate": failure_gate,
        "stage": stage,
        "provider_outcome_class": outcome,
        "attempt_count": attempts,
        "provider_called": provider_called,
        "model_called": model_called,
        "profile_called": profile_called,
        "memory_called": False if provider_called is False else None,
        "tool_called": False if provider_called is False else None,
        "persona_grounding_class": persona,
        "output_guard_applied": output_guard,
    }


def degradation_job(value: dict[str, object], *, channel: str = "telegram") -> DegradationShadowJob:
    return DegradationShadowJob.from_projection(
        value,
        projection_source="gateway" if str(value["safe_detail_code"]).startswith("gateway-") else "core",
        channel=channel,
        request_id=f"synthetic-{uuid4()}",
    )


class FakeConnection:
    def __init__(self) -> None:
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.closed = True


class P16IncidentHistoryRuntimeAdapterV1Tests(unittest.TestCase):
    def test_pre_provider_gate_allowlists_are_byte_semantic_parity(self) -> None:
        self.assertEqual(
            CORE_PRE_PROVIDER_FAILURE_GATES,
            GATEWAY_PRE_PROVIDER_FAILURE_GATES,
        )
        self.assertEqual(
            GATEWAY_PRE_PROVIDER_FAILURE_GATES,
            HISTORY_PRE_PROVIDER_FAILURE_GATES,
        )

    def test_default_off_does_not_touch_history_root(self) -> None:
        item = degradation_job(
            deterministic_gateway_projection("gateway-core-invalid-response")
        )
        job = build_incident_history_job(
            item,
            failure_provenance=deterministic_gateway_failure_provenance(
                "gateway-core-invalid-response"
            ),
            http_status=None,
            elapsed_seconds=1.0,
            release_set_id=None,
            pending_after=None,
            observed_at=NOW,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "absent"
            self.assertEqual(
                append_incident_history_after_response(
                    job,
                    root=root,
                    marker_check=lambda _: False,
                ),
                "disabled",
            )
            self.assertFalse(root.exists())

    def test_marker_or_selector_alone_cannot_enable_history(self) -> None:
        item = degradation_job(
            deterministic_gateway_projection("gateway-core-invalid-response")
        )
        job = build_incident_history_job(
            item,
            failure_provenance=deterministic_gateway_failure_provenance(
                "gateway-core-invalid-response"
            ),
            http_status=None,
            elapsed_seconds=1.0,
            release_set_id=None,
            pending_after=None,
            observed_at=NOW,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "absent"
            self.assertEqual(
                append_incident_history_after_response(
                    job,
                    root=root,
                    marker_check=lambda _: True,
                    selector_load=lambda _: None,
                ),
                "disabled",
            )
            self.assertEqual(
                append_incident_history_after_response(
                    job,
                    root=root,
                    marker_check=lambda _: False,
                    selector_load=lambda _: selector_payload(root=root),
                ),
                "disabled",
            )
            self.assertFalse(root.exists())

    def test_selector_is_canonical_exact_scope_and_symlink_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selector = root / "selector.json"
            payload = selector_payload()
            selector.write_bytes(
                json.dumps(
                    payload,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
                + b"\n"
            )
            selector.chmod(0o440)
            loaded = load_approved_incident_history_selector(
                selector,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            self.assertEqual(loaded, payload)
            link = root / "selector-link.json"
            link.symlink_to(selector)
            self.assertIsNone(
                load_approved_incident_history_selector(
                    link,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )
            )
            selector.chmod(0o640)
            self.assertIsNone(
                load_approved_incident_history_selector(
                    selector,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )
            )
        for drift in (
            {"channel": "qq"},
            {"capacity": 129},
            {"public_reply_contract": "changed"},
            {"extra": "forbidden"},
        ):
            with self.subTest(drift=drift):
                value = {**selector_payload(), **drift}
                with self.assertRaises(ValueError):
                    validate_incident_history_selector(value)

    def test_fixed_stage_matrix_preserves_precise_content_free_provenance(self) -> None:
        cases = (
            (
                projection(
                    "core-request-rejected",
                    category="core_or_gateway_failure",
                    retryable=False,
                    owner_action_required=True,
                ),
                provenance(
                    "request_parser",
                    outcome="not_called",
                    attempts=0,
                    provider_called=False,
                    model_called=False,
                    profile_called=False,
                    failure_gate="core_request_rejected",
                ),
                "request_parser",
                "invalid_conversation_request",
            ),
            (
                projection(
                    "owner-memory-read-failed",
                    category="memory_service_failure",
                    retryable=True,
                ),
                provenance(
                    "profile_projection",
                    outcome="not_called",
                    attempts=0,
                    provider_called=False,
                    model_called=False,
                    profile_called=True,
                    failure_gate="owner_memory_read_failed",
                ),
                "profile_projection",
                "profile_reader_fail_closed",
            ),
            (
                projection(
                    "provider-transport-failure",
                    category="provider_transient_failure",
                    retryable=True,
                ),
                provenance(
                    "provider_request",
                    outcome="transport_failure",
                    attempts=2,
                    provider_called=True,
                    model_called=True,
                    profile_called=True,
                    persona="soft_persona_daily_life",
                    failure_gate="transport_failure",
                ),
                "provider_request",
                "transport_failure",
            ),
            (
                projection(
                    "reply-runtime-guard-rejected",
                    category="reply_contract_rejected",
                    retryable=True,
                ),
                provenance(
                    "output_repair",
                    outcome="invalid_response",
                    attempts=1,
                    provider_called=True,
                    model_called=True,
                    profile_called=True,
                    persona="real_world_observation",
                    output_guard=True,
                    failure_gate="reply_runtime_guard_rejected",
                ),
                "output_repair",
                "reply_runtime_guard_rejected",
            ),
            (
                projection(
                    "core-runtime-fail-closed",
                    category="core_or_gateway_failure",
                    retryable=True,
                ),
                provenance(
                    "core_pre_provider",
                    outcome="not_called",
                    attempts=0,
                    provider_called=False,
                    model_called=False,
                    profile_called=True,
                    failure_gate="projection_character_budget_exceeded",
                ),
                "core_pre_provider",
                "projection_character_budget_exceeded",
            ),
            (
                deterministic_gateway_projection("gateway-core-invalid-response"),
                deterministic_gateway_failure_provenance(
                    "gateway-core-invalid-response"
                ),
                "core_response",
                "core_invalid_response",
            ),
            (
                deterministic_gateway_projection("gateway-temporal-unavailable"),
                deterministic_gateway_failure_provenance(
                    "gateway-temporal-unavailable"
                ),
                "temporal_context",
                "temporal_unavailable",
            ),
        )
        for safe_projection, fixed_provenance, stage, gate in cases:
            with self.subTest(stage=stage):
                job = build_incident_history_job(
                    degradation_job(safe_projection),
                    failure_provenance=fixed_provenance,
                    http_status=503,
                    elapsed_seconds=65 if stage == "provider_request" else 1,
                    release_set_id=RELEASE_SET_ID,
                    pending_after=0,
                    observed_at=NOW,
                )
                payload = job.evidence.payload
                self.assertEqual(payload["stage"], stage)
                self.assertEqual(payload["typed_gate"], gate)
                self.assertEqual(payload["attempt_count"], fixed_provenance["attempt_count"])
                self.assertEqual(
                    payload["persona_grounding_class"],
                    fixed_provenance["persona_grounding_class"],
                )
                self.assertEqual(
                    payload["output_guard_applied"],
                    fixed_provenance["output_guard_applied"],
                )
                self.assertEqual(payload["public_code_status"], "unavailable")
                self.assertIsNone(payload["public_code"])

    def test_append_is_idempotent_and_bound_to_same_incident_ref_after_close(self) -> None:
        degradation = degradation_job(
            deterministic_gateway_projection("gateway-core-invalid-response")
        )
        history = build_incident_history_job(
            degradation,
            failure_provenance=deterministic_gateway_failure_provenance(
                "gateway-core-invalid-response"
            ),
            http_status=None,
            elapsed_seconds=1,
            release_set_id=None,
            pending_after=None,
            observed_at=NOW,
        )
        self.assertEqual(history.incident_ref, degradation.incident_ref)
        connection = FakeConnection()
        calls: list[str] = []

        def append_after_close(item):
            self.assertTrue(connection.closed)
            calls.append(str(item.incident_ref))
            return "appended"

        serve_accepted_connection(
            connection,
            lambda _: PostConnectionFanout(
                degradation=degradation,
                incident_history=history,
            ),
            marker_check=lambda _: False,
            fault_receipt_write=lambda _: "written",
            incident_history_append=append_after_close,
        )
        self.assertEqual(calls, [degradation.incident_ref])
        with self.assertRaises(ValueError):
            PostConnectionFanout(
                degradation=degradation,
                incident_history=build_incident_history_job(
                    degradation_job(
                        deterministic_gateway_projection(
                            "gateway-core-invalid-response"
                        )
                    ),
                    failure_provenance=deterministic_gateway_failure_provenance(
                        "gateway-core-invalid-response"
                    ),
                    http_status=None,
                    elapsed_seconds=1,
                    release_set_id=None,
                    pending_after=None,
                    observed_at=NOW,
                ),
            )

    def test_enabled_store_appends_then_deduplicates_without_overwrite(self) -> None:
        degradation = degradation_job(
            deterministic_gateway_projection("gateway-owner-rate-limited")
        )
        job = build_incident_history_job(
            degradation,
            failure_provenance=deterministic_gateway_failure_provenance(
                "gateway-owner-rate-limited"
            ),
            http_status=None,
            elapsed_seconds=0.1,
            release_set_id=None,
            pending_after=None,
            observed_at=NOW,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            channel_root = root / "telegram"
            channel_root.mkdir(mode=0o700)
            first = append_incident_history_after_response(
                job,
                root=root,
                marker_check=lambda _: True,
                selector_load=lambda _: selector_payload(root=root),
            )
            before = (channel_root / "history-v1.json").read_bytes()
            replay = append_incident_history_after_response(
                job,
                root=root,
                marker_check=lambda _: True,
                selector_load=lambda _: selector_payload(root=root),
            )
            after = (channel_root / "history-v1.json").read_bytes()
        self.assertEqual(first, "appended")
        self.assertEqual(replay, "duplicate")
        self.assertEqual(before, after)

    def test_existing_v1_chain_accepts_a_later_v2_occurrence(self) -> None:
        first_degradation = degradation_job(
            deterministic_gateway_projection("gateway-owner-rate-limited")
        )
        first_v2 = build_incident_history_job(
            first_degradation,
            failure_provenance=deterministic_gateway_failure_provenance(
                "gateway-owner-rate-limited"
            ),
            http_status=None,
            elapsed_seconds=1,
            release_set_id=None,
            pending_after=None,
            observed_at=NOW,
        ).evidence.as_payload()
        current_replay = IncidentEvidence(dict(first_v2))
        for field in (
            "attempt_count",
            "persona_grounding_class",
            "output_guard_applied",
        ):
            first_v2.pop(field)
        first_v2["schema"] = EVIDENCE_SCHEMA_V1
        legacy = IncidentEvidence(first_v2)
        second = build_incident_history_job(
            degradation_job(
                deterministic_gateway_projection("gateway-core-invalid-response")
            ),
            failure_provenance=deterministic_gateway_failure_provenance(
                "gateway-core-invalid-response"
            ),
            http_status=None,
            elapsed_seconds=2,
            release_set_id=None,
            pending_after=None,
            observed_at=NOW.replace(minute=1),
        ).evidence
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentHistoryStore(Path(directory))
            first = store.append(legacy)
            replay = store.append(current_replay)
            store.append(second)
            state = store.read()
        self.assertEqual(replay.status, "duplicate")
        self.assertEqual(replay.occurrence_digest, first.occurrence_digest)
        self.assertEqual(
            [item["schema"] for item in state["occurrences"]],
            ["myuna.incident-occurrence.v1", "myuna.incident-occurrence.v2"],
        )

    def test_core_v1_compatibility_and_v2_provenance_are_both_strict(self) -> None:
        safe_projection = projection(
            "provider-transport-failure",
            category="provider_transient_failure",
            retryable=True,
        )
        legacy = {
            "error": "provider_unavailable",
            "failure_schema": CORE_FAILURE_RESPONSE_SCHEMA_V1,
            "retryable": True,
            "safe_degradation": safe_projection,
        }
        _projection, legacy_provenance = validate_core_failure_response_with_provenance(
            503, legacy
        )
        self.assertEqual(legacy_provenance["stage"], "unknown")
        fixed = provenance(
            "provider_request",
            outcome="transport_failure",
            attempts=2,
            provider_called=True,
            model_called=True,
            profile_called=True,
        )
        current = {
            **legacy,
            "failure_schema": CORE_FAILURE_RESPONSE_SCHEMA,
            "failure_provenance": fixed,
        }
        _projection, current_provenance = validate_core_failure_response_with_provenance(
            503, current
        )
        self.assertEqual(current_provenance, fixed)
        legacy_fixed = {**fixed, "schema": CORE_FAILURE_PROVENANCE_SCHEMA_V1}
        legacy_fixed.pop("failure_gate")
        _projection, accepted_legacy_fixed = (
            validate_core_failure_response_with_provenance(
                503,
                {**current, "failure_provenance": legacy_fixed},
            )
        )
        self.assertEqual(accepted_legacy_fixed, legacy_fixed)
        with self.assertRaises(ValueError):
            validate_core_failure_response_with_provenance(
                503, {**current, "private_message": "forbidden"}
            )
        contradictory = {
            **current,
            "failure_provenance": {
                **fixed,
                "stage": "core_runtime",
            },
        }
        with self.assertRaises(ValueError):
            validate_core_failure_response_with_provenance(503, contradictory)
        with self.assertRaises(ValueError):
            validate_core_failure_response_with_provenance(
                503,
                {
                    **current,
                    "failure_provenance": {
                        **fixed,
                        "stage": "core_pre_provider",
                        "provider_outcome_class": "not_called",
                        "attempt_count": 0,
                        "provider_called": False,
                        "model_called": False,
                        "failure_gate": "unreviewed_future_gate",
                    },
                },
            )

    def test_qq_and_telegram_runtime_fanout_carry_history_only_with_exact_evidence(self) -> None:
        qq_projection = deterministic_gateway_projection(
            "gateway-core-invalid-response"
        )
        qq_fanout = qq_runtime._degradation_fanout(
            qq_projection,
            projection_source="gateway",
            request_id="qq-synthetic-request",
            failure_provenance=deterministic_gateway_failure_provenance(
                "gateway-core-invalid-response"
            ),
            elapsed_seconds=1,
        )
        self.assertIsNotNone(qq_fanout)
        assert qq_fanout is not None
        self.assertIsNotNone(qq_fanout.incident_history)
        self.assertEqual(
            qq_fanout.incident_history.evidence.payload["stage"],
            "core_response",
        )
        temporal_projection = deterministic_gateway_projection(
            "gateway-temporal-unavailable"
        )
        telegram_fanout = telegram_runtime._degradation_fanout(
            temporal_projection,
            projection_source="gateway",
            request_id="telegram-synthetic-request",
            failure_provenance=deterministic_gateway_failure_provenance(
                "gateway-temporal-unavailable"
            ),
            elapsed_seconds=1,
            release_set_id=RELEASE_SET_ID,
            pending_after=0,
        )
        self.assertIsNotNone(telegram_fanout)
        assert telegram_fanout is not None
        self.assertEqual(
            telegram_fanout.incident_history.evidence.payload["stage"],
            "temporal_context",
        )
        no_evidence = telegram_runtime._degradation_fanout(
            deterministic_gateway_projection("gateway-core-unreachable"),
            projection_source="gateway",
            request_id="telegram-unknown-request",
        )
        self.assertIsNotNone(no_evidence)
        assert no_evidence is not None
        self.assertIsNone(no_evidence.incident_history)

    def test_every_frozen_provider_code_crosses_core_gateway_history_without_collapse(self) -> None:
        for provider_code in sorted(_PROVIDER_CODE_MAP):
            with self.subTest(provider_code=provider_code):
                core_payload = attach_provider_failure_metadata(
                    {"error": "provider_unavailable", "retryable": True},
                    request_id="provider-cross-component",
                    provider_code=provider_code,
                    attempt_count=2,
                    profile_called=True,
                    persona_grounding_class="not_evaluated",
                )
                safe_projection = core_payload["safe_degradation"]
                core_payload["retryable"] = safe_projection["retryable"]
                status = 503 if safe_projection["retryable"] else 502
                validated_projection, validated_provenance = (
                    validate_core_failure_response_with_provenance(
                        status, core_payload
                    )
                )
                history = build_incident_history_job(
                    degradation_job(validated_projection),
                    failure_provenance=validated_provenance,
                    http_status=status,
                    elapsed_seconds=60 if provider_code in {
                        "transport_failure",
                        "local_timeout",
                    } else 1,
                    release_set_id=RELEASE_SET_ID,
                    pending_after=0,
                    observed_at=NOW,
                )
                self.assertNotEqual(
                    history.evidence.payload["typed_namespace"], "unknown"
                )
                self.assertEqual(
                    history.evidence.payload["stage"],
                    validated_provenance["stage"],
                )

    def test_latency_http_and_history_payload_have_fixed_safe_shapes(self) -> None:
        self.assertEqual([latency_bucket(v) for v in (0, 5, 30, 60)], [
            "lt5s", "5to29s", "30to59s", "gte60s"
        ])
        self.assertEqual([http_outcome_class(v) for v in (200, 400, 503, None)], [
            "2xx", "4xx", "5xx", "none"
        ])
        job = build_incident_history_job(
            degradation_job(
                deterministic_gateway_projection("gateway-temporal-unavailable"),
                channel="qq",
            ),
            failure_provenance=deterministic_gateway_failure_provenance(
                "gateway-temporal-unavailable"
            ),
            http_status=None,
            elapsed_seconds=1,
            release_set_id=None,
            pending_after=None,
            observed_at=NOW,
        )
        forbidden = {
            "message",
            "profile",
            "db_row",
            "raw_log",
            "secret",
            "provider_payload",
            "model_response",
            "request_id",
            "path",
            "amount",
        }
        self.assertTrue(forbidden.isdisjoint(job.evidence.payload))


if __name__ == "__main__":
    unittest.main()
