from __future__ import annotations

import unittest

from myuna_core.context_window import (
    ContextWindowPolicy,
    ContextWindowPolicyError,
)


class ContextWindowPolicyTests(unittest.TestCase):
    def test_default_remains_current_runtime_boundary(self) -> None:
        policy = ContextWindowPolicy.default()
        self.assertEqual(policy.max_messages, 12)
        self.assertEqual(policy.max_characters, 16000)

    def test_24_36_128_and_256_are_supported_by_contract(self) -> None:
        for max_messages in (24, 36, 128, 256):
            with self.subTest(max_messages=max_messages):
                policy = ContextWindowPolicy(
                    max_messages=max_messages,
                    max_characters=262144,
                )
                self.assertEqual(policy.max_messages, max_messages)

    def test_odd_or_unbounded_windows_fail_closed(self) -> None:
        for max_messages in (1, 13, 257, 258, True):
            with self.subTest(max_messages=max_messages):
                with self.assertRaises(ContextWindowPolicyError):
                    ContextWindowPolicy(
                        max_messages=max_messages,  # type: ignore[arg-type]
                        max_characters=16000,
                    )


if __name__ == "__main__":
    unittest.main()
