from __future__ import annotations

from datetime import datetime, timezone
import unittest

from myuna_core.relationship_context import (
    AuthoritativeRelationshipState,
    RelationshipContext,
    RelationshipContextError,
)


class RelationshipContextTests(unittest.TestCase):
    def test_missing_affection_state_is_conservative(self) -> None:
        context = RelationshipContext.from_state(None)
        self.assertFalse(context.authoritative)
        self.assertTrue(context.allows("Cealana"))
        for nickname in ("Lana", "Lana-chan", "Darling", "Honey"):
            self.assertFalse(context.allows(nickname))
            self.assertTrue(context.validate_reply(f"晚安，{nickname}"))
        self.assertTrue(context.validate_reply("晚安，LANA"))
        self.assertFalse(context.validate_reply("晚安，Cealana"))

    def test_compound_nickname_does_not_false_match_shorter_name(self) -> None:
        state = AuthoritativeRelationshipState(
            source="Affection State v1",
            observed_at=datetime(2026, 7, 26, tzinfo=timezone.utc),
            allowed_nicknames=("Cealana", "Lana-chan"),
        )
        context = RelationshipContext.from_state(state)
        self.assertFalse(context.validate_reply("晚安，Lana-chan"))

    def test_authoritative_allowlist_not_numeric_inference_controls_names(self) -> None:
        state = AuthoritativeRelationshipState(
            source="Affection State v1",
            observed_at=datetime(2026, 7, 26, tzinfo=timezone.utc),
            allowed_nicknames=("Cealana", "Lana"),
            affection_score=60,
        )
        context = RelationshipContext.from_state(state)
        self.assertTrue(context.allows("Lana"))
        self.assertFalse(context.validate_reply("晚安，Lana"))
        self.assertTrue(context.validate_reply("晚安，Darling"))

    def test_state_requires_cealana_and_aware_time(self) -> None:
        with self.assertRaises(RelationshipContextError):
            AuthoritativeRelationshipState(
                source="test",
                observed_at=datetime(2026, 7, 26),
                allowed_nicknames=("Lana",),
            )

    def test_prompt_boundary_never_exposes_numeric_score(self) -> None:
        state = AuthoritativeRelationshipState(
            source="Affection State v1",
            observed_at=datetime(2026, 7, 26, tzinfo=timezone.utc),
            allowed_nicknames=("Cealana",),
            affection_score=60,
        )
        boundary = RelationshipContext.from_state(state).prompt_boundary()
        self.assertNotIn("60", boundary)
        self.assertIn("Cealana", boundary)


if __name__ == "__main__":
    unittest.main()
