from __future__ import annotations

import json
import sys
from pathlib import Path
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from context_window_policy import (  # noqa: E402
    ContextWindowPolicy,
    ContextWindowRejected,
    ConversationHistory,
    InMemoryContextStore,
)


class GatewayContextWindowPolicyTests(unittest.TestCase):
    def test_contract_supports_staged_and_long_target_windows(self) -> None:
        for max_messages in (12, 24, 36, 128, 256):
            with self.subTest(max_messages=max_messages):
                policy = ContextWindowPolicy(max_messages, 262144)
                self.assertEqual(policy.max_messages, max_messages)

    def test_invalid_windows_fail_closed(self) -> None:
        for max_messages in (1, 13, 258, True):
            with self.subTest(max_messages=max_messages):
                with self.assertRaises(ContextWindowRejected):
                    ContextWindowPolicy(max_messages, 16000)  # type: ignore[arg-type]

    def test_history_trims_whole_turns_and_preserves_latest_user(self) -> None:
        history = ConversationHistory(4, 4000)
        for index in range(4):
            request = history.request_messages("owner-private", f"u{index}")
            history.commit_reply("owner-private", request, f"a{index}")
        request = history.request_messages("owner-private", "latest")
        self.assertEqual(
            [item["role"] for item in request],
            ["user", "assistant", "user"],
        )
        self.assertEqual(request[-1]["content"], "latest")

    def test_store_is_replaceable_and_copies_messages(self) -> None:
        store = InMemoryContextStore()
        history = ConversationHistory(24, 24000, store=store)
        request = history.request_messages("owner-private", "hello")
        history.commit_reply("owner-private", request, "hi")
        loaded = store.load("owner-private")
        loaded[0]["content"] = "mutated"
        self.assertEqual(store.load("owner-private")[0]["content"], "hello")
        self.assertEqual(history.public_metadata()["store"], "InMemoryContextStore")

    def test_profile_catalog_keeps_12_default_and_larger_profiles_inactive(self) -> None:
        catalog = json.loads(
            (SCRIPTS.parent / "config" / "context-window-profiles-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(catalog["schema"], "myuna.gateway.context-window-profiles.v1")
        profiles = catalog["profiles"]
        self.assertEqual(profiles["current-12"]["status"], "current-default")
        self.assertEqual(profiles["qa-24"]["status"], "offline-qa-only")
        self.assertEqual(profiles["qa-36"]["status"], "offline-qa-only")
        self.assertEqual(profiles["target-128"]["status"], "contract-only")
        self.assertEqual(profiles["contract-maximum-256"]["status"], "contract-only")


if __name__ == "__main__":
    unittest.main()
