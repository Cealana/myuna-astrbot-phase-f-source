from __future__ import annotations

import unittest

from myuna_core.episodic_memory import (
    CALENDAR_ZONE_SELECTION_SCHEMA,
    EpisodicMemoryError,
    calendar_zone_selection_digest,
    calendar_zone_selection_payload,
)


class CalendarZoneSelectionTests(unittest.TestCase):
    def test_supported_zone_payload_and_digest_are_exact(self) -> None:
        shanghai = calendar_zone_selection_payload("Asia/Shanghai")
        los_angeles = calendar_zone_selection_payload("America/Los_Angeles")
        self.assertEqual(shanghai["schema"], CALENDAR_ZONE_SELECTION_SCHEMA)
        self.assertEqual(shanghai["selected_zone"], "Asia/Shanghai")
        self.assertEqual(los_angeles["selected_zone"], "America/Los_Angeles")
        self.assertFalse(shanghai["historical_turn_rewrite"])
        self.assertFalse(los_angeles["resample_on_zone_switch"])
        self.assertEqual(
            calendar_zone_selection_digest("Asia/Shanghai"),
            calendar_zone_selection_digest("Asia/Shanghai"),
        )
        self.assertNotEqual(
            calendar_zone_selection_digest("Asia/Shanghai"),
            calendar_zone_selection_digest("America/Los_Angeles"),
        )

    def test_unknown_zone_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            EpisodicMemoryError, "calendar_zone_selection_unsupported"
        ):
            calendar_zone_selection_payload("UTC")


if __name__ == "__main__":
    unittest.main()
