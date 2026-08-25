from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

from myuna_core.natural_degradation import (
    DegradationCategory,
    FailureEnvelope,
    NotificationCursor,
    RecoveryState,
    classify_unavailable_capability_request,
    decide_degradation_notification,
    notification_cursor,
    render_natural_degradation,
    reply_tail_violations,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 22, 9, 0, tzinfo=timezone(timedelta(hours=8)))


class FakeManifest:
    def __init__(self, enabled: set[str] | None = None) -> None:
        self.enabled = enabled or {"conversation", "long_term_memory_read", "qq_channel"}

    def capability_enabled(self, name: str) -> bool:
        return name in self.enabled


def envelope(
    *,
    category: DegradationCategory = DegradationCategory.REPLY_CONTRACT_REJECTED,
    component: str = "myuna-core",
    detail: str = "reply-guard-rejected",
    owner_action_required: bool = False,
    recovery_state: RecoveryState = RecoveryState.ACTIVE,
) -> FailureEnvelope:
    return FailureEnvelope(
        event_id="event-001",
        correlation_id="correlation-001",
        category=category,
        component=component,
        retryable=True,
        owner_action_required=owner_action_required,
        confirmed_facts=("provider-returned",),
        unknown_facts=("discarded-content",),
        safe_detail_code=detail,
        first_seen_at=NOW,
        last_seen_at=NOW,
        occurrence_count=1,
        recovery_state=recovery_state,
    )


class NaturalDegradationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = FakeManifest()
        self.golden = json.loads(
            (ROOT / "fixtures/natural_degradation_reply_tail_v1_golden.json").read_text(
                encoding="utf-8"
            )
        )

    def test_failure_envelope_rejects_free_form_or_secret_shaped_fields(self) -> None:
        with self.assertRaises(ValueError):
            FailureEnvelope(
                event_id="event contains spaces",
                correlation_id="correlation-001",
                category=DegradationCategory.REPLY_CONTRACT_REJECTED,
                component="myuna-core",
                retryable=True,
                owner_action_required=False,
                confirmed_facts=(),
                unknown_facts=(),
                safe_detail_code="reply-rejected",
                first_seen_at=NOW,
                last_seen_at=NOW,
                occurrence_count=1,
                recovery_state=RecoveryState.ACTIVE,
            )

    def test_failure_envelope_requires_ordered_aware_timestamps(self) -> None:
        with self.assertRaises(ValueError):
            FailureEnvelope(
                event_id="event-001",
                correlation_id="correlation-001",
                category=DegradationCategory.REPLY_CONTRACT_REJECTED,
                component="myuna-core",
                retryable=True,
                owner_action_required=False,
                confirmed_facts=(),
                unknown_facts=(),
                safe_detail_code="reply-rejected",
                first_seen_at=NOW,
                last_seen_at=NOW - timedelta(seconds=1),
                occurrence_count=1,
                recovery_state=RecoveryState.ACTIVE,
            )

    def test_request_classifier_golden_matrix(self) -> None:
        for case in self.golden["request_cases"]:
            with self.subTest(case=case["id"]):
                result = classify_unavailable_capability_request(case["text"], self.manifest)
                actual = result.category.value if result is not None else None
                self.assertEqual(actual, case["expected"])

    def test_enabled_capability_is_not_denied(self) -> None:
        result = classify_unavailable_capability_request(
            "如果我发一张图片，你能看懂里面是什么吗",
            FakeManifest({"conversation", "vision"}),
        )
        self.assertIsNone(result)

    def test_reply_tail_golden_matrix(self) -> None:
        for case in self.golden["tail_cases"]:
            with self.subTest(case=case["id"]):
                category = DegradationCategory(case["category"])
                self.assertEqual(
                    reply_tail_violations(case["reply"], category, self.manifest),
                    case["expected"],
                )

    def test_every_deterministic_template_passes_tail_and_capability_guards(self) -> None:
        for category in DegradationCategory:
            with self.subTest(category=category.value):
                item = envelope(category=category, detail="safe-detail")
                rendered = render_natural_degradation(item)
                self.assertEqual(reply_tail_violations(rendered, category, self.manifest), [])
                self.assertNotIn("##", rendered)

    def test_dedup_emits_first_observation(self) -> None:
        decision = decide_degradation_notification(
            envelope(), None, now=NOW, reminder_interval=timedelta(hours=1)
        )
        self.assertEqual((decision.emit, decision.reason), (True, "first_observation"))

    def test_dedup_suppresses_same_fingerprint_within_interval(self) -> None:
        item = envelope()
        cursor = notification_cursor(item, emitted_at=NOW)
        decision = decide_degradation_notification(
            item,
            cursor,
            now=NOW + timedelta(minutes=5),
            reminder_interval=timedelta(hours=1),
        )
        self.assertEqual((decision.emit, decision.reason), (False, "duplicate_suppressed"))

    def test_dedup_emits_when_category_changes(self) -> None:
        previous = envelope()
        cursor = notification_cursor(previous, emitted_at=NOW)
        current = envelope(
            category=DegradationCategory.PROVIDER_TRANSIENT_FAILURE,
            detail="provider-timeout",
        )
        decision = decide_degradation_notification(
            current,
            cursor,
            now=NOW + timedelta(minutes=1),
            reminder_interval=timedelta(hours=1),
        )
        self.assertEqual((decision.emit, decision.reason), (True, "fingerprint_changed"))

    def test_dedup_emits_recovery_transition(self) -> None:
        active = envelope()
        cursor = notification_cursor(active, emitted_at=NOW)
        recovered = envelope(recovery_state=RecoveryState.RECOVERED)
        decision = decide_degradation_notification(
            recovered,
            cursor,
            now=NOW + timedelta(minutes=1),
            reminder_interval=timedelta(hours=1),
        )
        self.assertEqual((decision.emit, decision.reason), (True, "recovery_state_changed"))

    def test_dedup_emits_new_owner_action_requirement(self) -> None:
        item = envelope(owner_action_required=True)
        cursor = NotificationCursor(
            fingerprint=item.fingerprint,
            recovery_state=item.recovery_state,
            owner_action_required=False,
            emitted_at=NOW,
        )
        decision = decide_degradation_notification(
            item,
            cursor,
            now=NOW + timedelta(minutes=1),
            reminder_interval=timedelta(hours=1),
        )
        self.assertEqual(
            (decision.emit, decision.reason),
            (True, "owner_action_became_required"),
        )

    def test_dedup_emits_after_reminder_interval(self) -> None:
        item = envelope()
        cursor = notification_cursor(item, emitted_at=NOW)
        decision = decide_degradation_notification(
            item,
            cursor,
            now=NOW + timedelta(hours=1),
            reminder_interval=timedelta(hours=1),
        )
        self.assertEqual(
            (decision.emit, decision.reason),
            (True, "reminder_interval_elapsed"),
        )


if __name__ == "__main__":
    unittest.main()
