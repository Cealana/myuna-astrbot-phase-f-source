from __future__ import annotations

import unittest

from myuna_core.persona_routing import (
    ChrynaWakeController,
    ChrynaWakeInput,
    PersonaRoute,
    PersonaRouteParser,
    WakeDecision,
)


class PersonaRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = PersonaRouteParser()
        self.controller = ChrynaWakeController()

    def test_direct_chryna_name_and_prefix_bypass_myuna(self) -> None:
        for text in ("Chryna", "Chryna，确认一下", "chryna: status"):
            with self.subTest(text=text):
                self.assertIs(
                    self.parser.parse(text, requested_mode="auto"),
                    PersonaRoute.CHRYNA,
                )

    def test_direct_myuna_keeps_chryna_asleep(self) -> None:
        route = self.parser.parse("Myuna，过来一下", requested_mode="auto")
        result = self.controller.decide(ChrynaWakeInput(route))
        self.assertIs(route, PersonaRoute.MYUNA)
        self.assertIs(result.decision, WakeDecision.SLEEP)

    def test_explicit_plural_route_is_dual(self) -> None:
        for text in (
            "Myuna 和 Chryna，你们都怎么看？",
            "你们两个确认一下",
            "你们怎么看这个方案",
        ):
            with self.subTest(text=text):
                route = self.parser.parse(text, requested_mode="auto")
                self.assertIs(route, PersonaRoute.DUAL)
                self.assertIs(
                    self.controller.decide(ChrynaWakeInput(route)).decision,
                    WakeDecision.DUAL,
                )

    def test_ordinary_turn_does_not_wake_chryna(self) -> None:
        route = self.parser.parse("我回来啦", requested_mode="auto")
        result = self.controller.decide(ChrynaWakeInput(route))
        self.assertIs(result.decision, WakeDecision.SLEEP)
        self.assertEqual(result.reason, "ordinary_myuna_turn")

    def test_internal_precision_wake_is_typed_not_text_inference(self) -> None:
        result = self.controller.decide(
            ChrynaWakeInput(
                PersonaRoute.MYUNA,
                internal_precision_request=True,
            )
        )
        self.assertIs(result.decision, WakeDecision.DUAL)
        self.assertEqual(result.reason, "typed_precision_request")

    def test_takeover_threshold_is_90_and_bounded(self) -> None:
        below = self.controller.decide(
            ChrynaWakeInput(PersonaRoute.MYUNA, risk_score=89)
        )
        at = self.controller.decide(
            ChrynaWakeInput(PersonaRoute.MYUNA, risk_score=90)
        )
        self.assertIs(below.decision, WakeDecision.SLEEP)
        self.assertIs(at.decision, WakeDecision.CHRYNA)
        self.assertEqual(at.reason, "takeover_threshold")
        with self.assertRaises(ValueError):
            ChrynaWakeController(True)

    def test_testflight_first_is_dual_and_later_is_chryna_only(self) -> None:
        first = self.controller.decide(
            ChrynaWakeInput(PersonaRoute.MYUNA, first_testflight=True)
        )
        later = self.controller.decide(
            ChrynaWakeInput(PersonaRoute.MYUNA, later_testflight=True)
        )
        self.assertIs(first.decision, WakeDecision.DUAL)
        self.assertIs(later.decision, WakeDecision.CHRYNA)


if __name__ == "__main__":
    unittest.main()
