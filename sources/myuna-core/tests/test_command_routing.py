from __future__ import annotations

import unittest

from myuna_core.command_routing import (
    CommandName,
    CommandParseError,
    CommandParser,
    render_command_error,
)


class CommandRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = CommandParser()

    def test_plain_blueout_and_slash_blueout_are_immediate(self) -> None:
        for text in ("Blueout", "  blueOUT  ", "/Blueout"):
            with self.subTest(text=text):
                parsed = self.parser.parse(text)
                self.assertIsNotNone(parsed)
                assert parsed is not None
                self.assertIs(parsed.name, CommandName.BLUEOUT)
                self.assertTrue(parsed.is_immediate_stop)

    def test_embedded_command_words_are_plain_text(self) -> None:
        for text in (
            "我们后面再用 /TestFlight",
            "TestFlight 以后再说",
            "今天不是 Blueout 的语境",
        ):
            with self.subTest(text=text):
                self.assertIsNone(self.parser.parse(text))

    def test_command_is_whole_message_casefolded_and_parameter_preserved(self) -> None:
        parsed = self.parser.parse(" /cHeCk   心情 / 情绪状态 ")
        assert parsed is not None
        self.assertIs(parsed.name, CommandName.CHECK)
        self.assertEqual(parsed.parameter, "心情 / 情绪状态")

    def test_canonical_commands_are_known(self) -> None:
        expected = {
            "/TestFlight": CommandName.TESTFLIGHT,
            "/Checklist": CommandName.CHECKLIST,
            "/Info": CommandName.INFO,
            "/Workbench": CommandName.WORKBENCH,
            "/ExitWorkbench": CommandName.EXIT_WORKBENCH,
            "/Check": CommandName.CHECK,
            "/Diary": CommandName.DIARY,
            "/Benchmark": CommandName.BENCHMARK,
        }
        for text, expected_name in expected.items():
            with self.subTest(text=text):
                parsed = self.parser.parse(text)
                assert parsed is not None
                self.assertIs(parsed.name, expected_name)

    def test_unknown_and_multiline_commands_fail_deterministically(self) -> None:
        for text, code in (
            ("/Example", "unknown_command"),
            ("/Exit-Workbench", "unknown_command"),
            ("/Check\nhello", "malformed_command"),
            ("/Blueout later", "blueout_rejects_parameters"),
        ):
            with self.subTest(text=text):
                with self.assertRaises(CommandParseError) as caught:
                    self.parser.parse(text)
                self.assertEqual(caught.exception.code, code)

    def test_unknown_command_error_is_system_text(self) -> None:
        error = CommandParseError("unknown_command", "/Example")
        self.assertEqual(
            render_command_error(error),
            "[COMMAND ERROR]\n未知指令：/Example",
        )


if __name__ == "__main__":
    unittest.main()
