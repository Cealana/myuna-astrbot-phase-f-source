from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timezone
import unittest

from myuna_core.episodic_memory import (
    ContextLimits,
    CompleteTurn,
    DynamicContextOracle,
    EpisodicMemoryError,
    local_date_interval,
    resolve_relative_date,
    project_all_active_temporal_items,
)

from tests.episodic_memory_fixtures import make_turns


def character_token_counter(messages: tuple[dict[str, str], ...]) -> int:
    return sum(len(item["content"]) for item in messages)


def empty_temporal():
    return project_all_active_temporal_items(
        (),
        maximum_characters=10_000,
        maximum_serialized_bytes=10_000,
        maximum_tokens=10_000,
        token_counter=lambda fragments: 0,
    )


class ContextCalendarTests(unittest.TestCase):
    def test_no_summary_lane_has_no_fixed_turn_ceiling(self) -> None:
        turns = make_turns(70, text_size=2)
        oracle = DynamicContextOracle(ContextLimits(), token_counter=character_token_counter)
        selected = oracle.project_all_or_fail(
            fixed_messages=({"role": "system", "content": "synthetic definition"},),
            turns=turns,
            current_message="current synthetic message",
            trusted_time_binding=turns[-1].draft.time_binding,
            temporal_projection=empty_temporal(),
        )
        self.assertEqual(selected.occupancy.projected_complete_turns, 70)
        self.assertFalse(selected.occupancy.summary_used)
        self.assertTrue(selected.occupancy.fit)
        self.assertNotIn("synthetic definition", str(selected.occupancy.audit_projection()))

    def test_each_capacity_oracle_fails_closed_with_stable_reason(self) -> None:
        turns = make_turns(2, text_size=20)
        cases = (
            (
                ContextLimits(
                    request_characters=20,
                    projection_characters=10_000,
                    serialized_bytes=10_000,
                    input_tokens=10_000,
                    output_reserve_characters=1,
                    output_reserve_bytes=1,
                    output_reserve_tokens=1,
                ),
                "context_request_characters_exceeded",
            ),
            (
                ContextLimits(
                    request_characters=10_000,
                    projection_characters=20,
                    serialized_bytes=10_000,
                    input_tokens=10_000,
                    output_reserve_characters=1,
                    output_reserve_bytes=1,
                    output_reserve_tokens=1,
                ),
                "context_projection_characters_exceeded",
            ),
            (
                ContextLimits(
                    request_characters=10_000,
                    projection_characters=10_000,
                    serialized_bytes=30,
                    input_tokens=10_000,
                    output_reserve_characters=1,
                    output_reserve_bytes=1,
                    output_reserve_tokens=1,
                ),
                "context_serialized_bytes_exceeded",
            ),
            (
                ContextLimits(
                    request_characters=10_000,
                    projection_characters=10_000,
                    serialized_bytes=10_000,
                    input_tokens=20,
                    output_reserve_characters=1,
                    output_reserve_bytes=1,
                    output_reserve_tokens=1,
                ),
                "context_input_tokens_exceeded",
            ),
        )
        for limits, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(EpisodicMemoryError, expected):
                    DynamicContextOracle(
                        limits, token_counter=character_token_counter
                    ).project_all_or_fail(
                        fixed_messages=({"role": "system", "content": "fixed"},),
                        turns=turns,
                        current_message="current",
                        trusted_time_binding=turns[-1].draft.time_binding,
                        temporal_projection=empty_temporal(),
                    )

    def test_raw_first_keeps_relevant_older_turn_and_contiguous_recent_tail(self) -> None:
        turns = make_turns(8, text_size=20)
        limits = ContextLimits(
            request_characters=560,
            projection_characters=550,
            serialized_bytes=4_000,
            input_tokens=4_000,
            output_reserve_characters=5,
            output_reserve_bytes=5,
            output_reserve_tokens=5,
        )
        selected = DynamicContextOracle(
            limits, token_counter=lambda messages: len(messages)
        ).project_raw_first(
            fixed_messages=({"role": "system", "content": "fixed"},),
            turns=turns,
            current_message="current",
            trusted_time_binding=turns[-1].draft.time_binding,
            temporal_projection=empty_temporal(),
            relevant_sequences=(2,),
        )
        self.assertIn(2, selected.selected_sequences)
        recent = [value for value in selected.selected_sequences if value > 2]
        if recent:
            self.assertEqual(recent, list(range(min(recent), 9)))
        self.assertLess(selected.occupancy.projected_complete_turns, 8)
        self.assertFalse(selected.occupancy.summary_used)

    def test_token_oracle_unavailable_fails_before_projection(self) -> None:
        binding = make_turns(1)[0].draft.time_binding
        with self.assertRaisesRegex(EpisodicMemoryError, "token_capacity_oracle_unavailable"):
            DynamicContextOracle(ContextLimits(), token_counter=None).project_all_or_fail(
                fixed_messages=(),
                turns=(),
                current_message="synthetic",
                trusted_time_binding=binding,
                temporal_projection=empty_temporal(),
            )

    def test_raw_chain_drift_fails_before_context_projection(self) -> None:
        turns = make_turns(2)
        drifted = CompleteTurn.create(
            replace(turns[1].draft, previous_turn_digest="f" * 64)
        )
        with self.assertRaisesRegex(EpisodicMemoryError, "archive_turn_chain_drifted"):
            DynamicContextOracle(
                ContextLimits(), token_counter=character_token_counter
            ).project_all_or_fail(
                fixed_messages=(),
                turns=(turns[0], drifted),
                current_message="synthetic",
                trusted_time_binding=turns[-1].draft.time_binding,
                temporal_projection=empty_temporal(),
            )

    def test_shanghai_and_los_angeles_day_boundaries_use_iana_dst(self) -> None:
        shanghai = local_date_interval(date(2026, 8, 8), "Asia/Shanghai")
        self.assertEqual(shanghai.start, datetime(2026, 8, 7, 16, tzinfo=timezone.utc))
        summer = local_date_interval(date(2026, 7, 1), "America/Los_Angeles")
        winter = local_date_interval(date(2026, 1, 1), "America/Los_Angeles")
        self.assertEqual(summer.start.hour, 7)
        self.assertEqual(winter.start.hour, 8)
        spring_forward = local_date_interval(date(2026, 3, 8), "America/Los_Angeles")
        self.assertEqual((spring_forward.end - spring_forward.start).total_seconds(), 23 * 3600)

    def test_relative_date_changes_query_boundary_not_historical_timestamp(self) -> None:
        reference = datetime(2026, 8, 8, 2, tzinfo=timezone.utc)
        shanghai = resolve_relative_date("昨天", reference_utc=reference)
        los_angeles = resolve_relative_date(
            "昨天", reference_utc=reference, zone_name="America/Los_Angeles"
        )
        self.assertNotEqual(shanghai.start, los_angeles.start)
        self.assertEqual(reference, datetime(2026, 8, 8, 2, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
