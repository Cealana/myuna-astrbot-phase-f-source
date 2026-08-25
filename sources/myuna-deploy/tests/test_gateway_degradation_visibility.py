from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(1, "/srv/myuna/repos/deploy/scripts")

from gateway_degradation_visibility import (  # noqa: E402
    VISIBILITY_POLICY_SCHEMA,
    VisibilityMode,
    VisibilityPolicyError,
    decide_visible_degradation,
    load_visibility_policy,
)
from gateway_degradation_protocol import CANONICAL_DEGRADATION_REPLIES  # noqa: E402


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def projection(
    category: str = "core_or_gateway_failure",
    *,
    recovery_state: str = "active",
) -> dict[str, object]:
    return {
        "schema": "myuna.safe-degradation.v1",
        "status": "degraded",
        "category": category,
        "retryable": True,
        "owner_action_required": False,
        "safe_detail_code": "gateway-core-unreachable",
        "recovery_state": recovery_state,
        "fingerprint": f"{category}:gateway:gateway-core-unreachable",
        "reply": CANONICAL_DEGRADATION_REPLIES[category],
    }


def policy_payload(*categories: str) -> dict[str, object]:
    return {
        "schema": VISIBILITY_POLICY_SCHEMA,
        "enabled_categories": [
            {
                "category": category,
                "evidence_receipt_sha256": DIGEST_A,
                "approval_plan_digest": DIGEST_B,
            }
            for category in categories
        ],
    }


class VisibilityPolicyTests(unittest.TestCase):
    def test_empty_policy_preserves_legacy_for_every_category(self) -> None:
        policy = load_visibility_policy(policy_payload())
        for category in CANONICAL_DEGRADATION_REPLIES:
            decision = decide_visible_degradation(projection(category), policy)
            self.assertIs(decision.mode, VisibilityMode.LEGACY_UNAVAILABLE)
            self.assertEqual(decision.reason, "category_not_authorized")
            self.assertIsNone(decision.response)

    def test_one_authorized_category_returns_typed_safe_reply(self) -> None:
        policy = load_visibility_policy(policy_payload("core_or_gateway_failure"))
        decision = decide_visible_degradation(projection(), policy)
        self.assertIs(decision.mode, VisibilityMode.SAFE_DEGRADED_REPLY)
        self.assertEqual(decision.reason, "category_authorized")
        self.assertEqual(decision.response["kind"], "safe_degraded_reply")
        self.assertEqual(
            decision.response["degradation"]["reply"],
            CANONICAL_DEGRADATION_REPLIES["core_or_gateway_failure"],
        )

    def test_authorization_is_category_scoped(self) -> None:
        policy = load_visibility_policy(policy_payload("provider_transient_failure"))
        decision = decide_visible_degradation(projection(), policy)
        self.assertIs(decision.mode, VisibilityMode.LEGACY_UNAVAILABLE)

    def test_recovered_projection_is_not_visible_in_r2d0(self) -> None:
        policy = load_visibility_policy(policy_payload("core_or_gateway_failure"))
        decision = decide_visible_degradation(
            projection(recovery_state="recovered"), policy
        )
        self.assertIs(decision.mode, VisibilityMode.LEGACY_UNAVAILABLE)
        self.assertEqual(decision.reason, "recovery_notice_not_authorized")

    def test_unknown_or_extra_policy_fields_fail_closed(self) -> None:
        payload = policy_payload()
        payload["automatic_acceptance"] = True
        with self.assertRaises(VisibilityPolicyError):
            load_visibility_policy(payload)

    def test_authorization_requires_evidence_and_approval_digests(self) -> None:
        payload = policy_payload("core_or_gateway_failure")
        payload["enabled_categories"][0]["evidence_receipt_sha256"] = "missing"
        with self.assertRaises(VisibilityPolicyError):
            load_visibility_policy(payload)

    def test_duplicate_category_fails_closed(self) -> None:
        with self.assertRaises(VisibilityPolicyError):
            load_visibility_policy(
                policy_payload("core_or_gateway_failure", "core_or_gateway_failure")
            )

    def test_same_channel_offline_categories_cannot_be_enabled(self) -> None:
        for category in ("onebot_or_napcat_offline", "host_or_network_unreachable"):
            with self.subTest(category=category):
                with self.assertRaises(VisibilityPolicyError):
                    load_visibility_policy(policy_payload(category))

    def test_malformed_projection_fails_closed(self) -> None:
        policy = load_visibility_policy(policy_payload("core_or_gateway_failure"))
        broken = deepcopy(projection())
        broken["reply"] = "free form"
        with self.assertRaises(VisibilityPolicyError):
            decide_visible_degradation(broken, policy)

    def test_policy_does_not_read_or_infer_observation_state(self) -> None:
        source = (ROOT / "scripts/gateway_degradation_visibility.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "trace.jsonl",
            "waiting_for_real_failure",
            "real_failure_rows",
            "systemctl",
            "subprocess",
            "socket",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()

