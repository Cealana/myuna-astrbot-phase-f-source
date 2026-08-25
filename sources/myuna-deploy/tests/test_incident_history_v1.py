from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from incident_history_v1 import (  # noqa: E402
    HISTORY_SCHEMA,
    OCCURRENCE_SCHEMA,
    PROBLEM_ATTACHMENT_SCHEMA,
    IncidentEvidence,
    IncidentHistoryRejected,
    IncidentHistoryStore,
    build_incident_evidence,
)
from gateway_degradation_protocol import CANONICAL_DEGRADATION_REPLIES  # noqa: E402


NOW = datetime(2026, 8, 5, 1, 0, tzinfo=timezone.utc)
RELEASE_SET_ID = "a" * 64
FINGERPRINTS = {
    "core-runtime-fail-closed": "b" * 64,
    "provider-transport-failure": "c" * 64,
}


def projection(detail: str, category: str, retryable: bool) -> dict[str, object]:
    fingerprint = FINGERPRINTS.get(detail)
    payload: dict[str, object] = {
        "schema": "myuna.safe-degradation.v1",
        "status": "degraded",
        "category": category,
        "retryable": retryable,
        "owner_action_required": False,
        "safe_detail_code": detail,
        "recovery_state": "active",
        "reply": CANONICAL_DEGRADATION_REPLIES[category],
    }
    if fingerprint is not None:
        payload["fingerprint"] = fingerprint
    return payload


def evidence(
    *,
    detail: str = "core-runtime-fail-closed",
    category: str = "core_or_gateway_failure",
    retryable: bool = True,
    observed_at: datetime = NOW,
    incident_ref: str | None = "inc-111111111111",
    latency_bucket: str = "lt5s",
    http_outcome_class: str = "5xx",
    provider_called: bool = False,
    model_called: bool = False,
    summary_delta: int = 0,
):
    return build_incident_evidence(
        projection(detail, category, retryable),
        observed_at=observed_at,
        trusted_time_status="trusted",
        channel="telegram",
        release_set_id=RELEASE_SET_ID,
        incident_ref=incident_ref,
        public_code=None,
        latency_bucket=latency_bucket,
        http_outcome_class=http_outcome_class,
        provider_called=provider_called,
        model_called=model_called,
        profile_called=False,
        memory_called=False,
        tool_called=False,
        service_observation_class="active_stable",
        restart_observation_class="none_observed",
        epoch_revision_delta=0,
        turn_delta=0,
        summary_delta=summary_delta,
        pending_after=0,
        delivery_delta=0,
    )


class IncidentHistoryV1Tests(unittest.TestCase):
    def make_store(self, root: Path, *, capacity: int = 8) -> IncidentHistoryStore:
        return IncidentHistoryStore(root, capacity=capacity)

    def test_synthetic_observed_pattern_preserves_three_distinct_faults(self) -> None:
        fixture = json.loads(
            (ROOT / "tests/fixtures/p16_incident_history_v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(fixture["schema"], "myuna.p16-incident-history.synthetic.v1")
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory))
            successes = 0
            occurrence_digests: list[str] = []
            for event in fixture["events"]:
                if event["kind"] == "success":
                    successes += 1
                    continue
                item = build_incident_evidence(
                    projection(
                        event["safe_detail_code"],
                        event["category"],
                        event["retryable"],
                    ),
                    observed_at=datetime.fromisoformat(
                        event["observed_at"].replace("Z", "+00:00")
                    ),
                    trusted_time_status="trusted",
                    channel="telegram",
                    release_set_id=fixture["release_set_id"],
                    incident_ref=event["incident_ref"],
                    public_code=None,
                    latency_bucket=event["latency_bucket"],
                    http_outcome_class=event["http_outcome_class"],
                    provider_called=event["provider_called"],
                    model_called=event["model_called"],
                    profile_called=False,
                    memory_called=False,
                    tool_called=False,
                    service_observation_class="active_stable",
                    restart_observation_class="none_observed",
                    epoch_revision_delta=event["epoch_revision_delta"],
                    turn_delta=event["turn_delta"],
                    summary_delta=event["summary_delta"],
                    pending_after=event["pending_after"],
                    delivery_delta=event["delivery_delta"],
                )
                outcome = store.append(item)
                occurrence_digests.append(outcome.occurrence_digest)
            state = store.read()

        self.assertEqual(len(state["occurrences"]), fixture["expected"]["fault_count"])
        self.assertEqual(successes, fixture["expected"]["success_count"])
        self.assertEqual(len(set(occurrence_digests)), 3)
        first, second, third = state["occurrences"]
        self.assertEqual(first["typed_gate"], "core_pre_provider_fail_closed")
        self.assertEqual(second["typed_gate"], "core_pre_provider_fail_closed")
        self.assertEqual(first["fingerprint_digest"], second["fingerprint_digest"])
        self.assertNotEqual(first["occurrence_digest"], second["occurrence_digest"])
        self.assertEqual(third["typed_namespace"], "provider")
        self.assertEqual(third["typed_gate"], "transport_failure")
        self.assertEqual(third["provider_outcome_class"], "transport_failure")
        self.assertTrue(third["retryable"])
        self.assertEqual(third["latency_bucket"], "gte60s")
        self.assertEqual(third["summary_delta"], 1)
        self.assertEqual(third["pending_after"], fixture["expected"]["final_pending"])
        self.assertEqual(third["delivery_delta"], 0)

    def test_exact_duplicate_is_idempotent_and_does_not_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = self.make_store(root)
            first = store.append(evidence())
            before = (root / "history-v1.json").read_bytes()
            replay = store.append(evidence())
            after = (root / "history-v1.json").read_bytes()
        self.assertEqual(first.status, "appended")
        self.assertEqual(replay.status, "duplicate")
        self.assertEqual(first.occurrence_digest, replay.occurrence_digest)
        self.assertEqual(before, after)

    def test_reused_incident_ref_for_distinct_event_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory))
            store.append(evidence())
            with self.assertRaises(IncidentHistoryRejected):
                store.append(evidence(observed_at=NOW.replace(minute=1)))

    def test_unfrozen_gate_and_invented_public_code_are_rejected(self) -> None:
        payload = evidence().as_payload()
        payload["typed_gate"] = "new_unreviewed_gate"
        with self.assertRaises(ValueError):
            IncidentEvidence(payload)
        with self.assertRaises(ValueError):
            build_incident_evidence(
                projection(
                    "provider-transport-failure",
                    "provider_transient_failure",
                    True,
                ),
                observed_at=NOW,
                trusted_time_status="trusted",
                channel="telegram",
                release_set_id=RELEASE_SET_ID,
                incident_ref=None,
                public_code="MYU-FAKE-99",
                latency_bucket="gte60s",
                http_outcome_class="5xx",
                provider_called=True,
                model_called=True,
                profile_called=False,
                memory_called=False,
                tool_called=False,
                service_observation_class="active_stable",
                restart_observation_class="none_observed",
                epoch_revision_delta=0,
                turn_delta=0,
                summary_delta=0,
                pending_after=0,
                delivery_delta=0,
            )

    def test_retention_rolls_oldest_into_content_free_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory), capacity=2)
            store.append(evidence())
            store.append(
                evidence(
                    observed_at=NOW.replace(minute=1),
                    incident_ref="inc-222222222222",
                )
            )
            store.append(
                evidence(
                    detail="provider-transport-failure",
                    category="provider_transient_failure",
                    observed_at=NOW.replace(minute=2),
                    incident_ref="inc-333333333333",
                    latency_bucket="gte60s",
                    provider_called=True,
                    model_called=True,
                )
            )
            state = store.read()
        self.assertEqual(state["schema"], HISTORY_SCHEMA)
        self.assertEqual(len(state["occurrences"]), 2)
        self.assertEqual(state["rollup"]["occurrence_count"], 1)
        self.assertRegex(state["rollup"]["summary_digest"], r"^[0-9a-f]{64}$")
        self.assertNotIn("incident_ref", state["rollup"])
        self.assertNotIn("public_code", state["rollup"])

    def test_unknown_evidence_never_invents_code_ref_or_fingerprint(self) -> None:
        item = build_incident_evidence(
            None,
            observed_at=NOW,
            trusted_time_status="trusted",
            channel="telegram",
            release_set_id=None,
            incident_ref=None,
            public_code=None,
            latency_bucket="unknown",
            http_outcome_class="unknown",
            provider_called=None,
            model_called=None,
            profile_called=None,
            memory_called=None,
            tool_called=None,
            service_observation_class="unknown",
            restart_observation_class="unknown",
            epoch_revision_delta=None,
            turn_delta=None,
            summary_delta=None,
            pending_after=None,
            delivery_delta=None,
        )
        payload = item.as_payload()
        self.assertEqual(payload["typed_namespace"], "unknown")
        self.assertEqual(payload["typed_gate"], "unknown")
        self.assertEqual(payload["fingerprint_status"], "unavailable")
        self.assertIsNone(payload["fingerprint_digest"])
        self.assertEqual(payload["incident_ref_status"], "unavailable")
        self.assertIsNone(payload["incident_ref"])
        self.assertEqual(payload["public_code_status"], "unavailable")
        self.assertIsNone(payload["public_code"])

    def test_telegram_and_qq_share_typed_semantics_without_sharing_events(self) -> None:
        base = dict(
            observed_at=NOW,
            trusted_time_status="trusted",
            release_set_id=RELEASE_SET_ID,
            incident_ref=None,
            public_code=None,
            latency_bucket="gte60s",
            http_outcome_class="5xx",
            provider_called=True,
            model_called=True,
            profile_called=False,
            memory_called=False,
            tool_called=False,
            service_observation_class="active_stable",
            restart_observation_class="none_observed",
            epoch_revision_delta=0,
            turn_delta=0,
            summary_delta=0,
            pending_after=0,
            delivery_delta=0,
        )
        source = projection(
            "provider-transport-failure",
            "provider_transient_failure",
            True,
        )
        telegram = build_incident_evidence(source, channel="telegram", **base)
        qq = build_incident_evidence(source, channel="qq", **base)
        for field in (
            "category",
            "stage",
            "typed_namespace",
            "typed_gate",
            "provider_outcome_class",
            "retryable",
            "fingerprint_digest",
        ):
            self.assertEqual(telegram.payload[field], qq.payload[field])
        self.assertNotEqual(telegram.event_digest, qq.event_digest)

    def test_problem_management_seam_attaches_only_content_free_refs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory))
            outcome = store.append(evidence())
            attachment = store.problem_attachment(outcome.occurrence_digest)
        self.assertEqual(attachment["schema"], PROBLEM_ATTACHMENT_SCHEMA)
        self.assertEqual(attachment["occurrence_digest"], outcome.occurrence_digest)
        self.assertRegex(attachment["fingerprint_digest"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(attachment["fingerprint_digest"], "b" * 64)
        self.assertEqual(attachment["attachment_status"], "eligible")
        self.assertEqual(
            set(attachment),
            {
                "schema",
                "occurrence_digest",
                "fingerprint_status",
                "fingerprint_digest",
                "attachment_status",
            },
        )

    def test_digest_type_permission_symlink_and_concurrency_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = self.make_store(root)
            store.append(evidence())
            state_path = root / "history-v1.json"
            original = state_path.read_bytes()

            state_path.write_bytes(original.replace(b'"channel":"telegram"', b'"channel":"qq"'))
            with self.assertRaises(IncidentHistoryRejected):
                store.read()
            state_path.write_bytes(original)
            os.chmod(state_path, 0o666)
            with self.assertRaises(IncidentHistoryRejected):
                store.read()
            os.chmod(state_path, 0o640)

            (root / ".append.lock").write_text("locked", encoding="ascii")
            with self.assertRaises(IncidentHistoryRejected):
                store.append(evidence(observed_at=NOW.replace(minute=1)))
            (root / ".append.lock").unlink()

            state_path.unlink()
            state_path.symlink_to(root / "missing.json")
            with self.assertRaises(IncidentHistoryRejected):
                store.read()

    def test_crash_artifact_and_stale_post_rollup_replay_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = self.make_store(root, capacity=1)
            store.append(evidence())
            store.append(
                evidence(
                    observed_at=NOW.replace(minute=1),
                    incident_ref="inc-222222222222",
                )
            )
            with self.assertRaises(IncidentHistoryRejected):
                store.append(
                    evidence(
                        observed_at=NOW,
                        incident_ref="inc-999999999999",
                    )
                )
            (root / ".history-v1.crash.tmp").write_bytes(b"partial")
            with self.assertRaises(IncidentHistoryRejected):
                store.append(
                    evidence(
                        observed_at=NOW.replace(minute=2),
                        incident_ref="inc-333333333333",
                    )
                )

    def test_encoding_and_chain_are_deterministic_and_content_free(self) -> None:
        snapshots = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                store = self.make_store(Path(directory))
                result = store.append(evidence())
                payload = store.read()
                snapshots.append(json.dumps(payload, sort_keys=True, separators=(",", ":")))
                occurrence = payload["occurrences"][0]
                self.assertEqual(occurrence["schema"], OCCURRENCE_SCHEMA)
                self.assertIsNone(occurrence["previous_event_digest"])
                self.assertEqual(result.occurrence_digest, occurrence["occurrence_digest"])
        self.assertEqual(snapshots[0], snapshots[1])
        forbidden_fields = {
            "message",
            "prompt",
            "response",
            "profile",
            "session",
            "database_row",
            "secret",
            "token",
            "cost",
            "amount",
            "request_id",
            "path",
            "details",
            "raw_error",
            "stack",
        }
        payload = json.loads(snapshots[0])
        observed_fields = set(payload)
        observed_fields.update(payload["rollup"])
        for occurrence in payload["occurrences"]:
            observed_fields.update(occurrence)
        self.assertTrue(forbidden_fields.isdisjoint(observed_fields))


if __name__ == "__main__":
    unittest.main()
