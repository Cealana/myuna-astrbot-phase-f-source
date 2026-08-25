from __future__ import annotations

import os
from unittest import TestCase, mock

from myuna_core.conversation import ReplyContractError, parse_model_reply_envelope


class ReplyContractV2CandidateTests(TestCase):
    def test_plain_text_fallback_is_disabled_by_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ReplyContractError):
                parse_model_reply_envelope("嗯，收到啦")

    def test_plain_text_fallback_accepts_normal_chinese(self) -> None:
        with mock.patch.dict(os.environ, {"MYUNA_REPLY_PLAIN_FALLBACK_ENABLED": "true"}):
            parsed = parse_model_reply_envelope("嗯，收到啦")
        self.assertEqual(parsed.reply, "嗯，收到啦")
        self.assertEqual(parsed.normalization, "guarded_plain_text")

    def test_plain_text_fallback_accepts_action_markup(self) -> None:
        value = "嗯，过来啦\n（她在旁边坐下）"
        with mock.patch.dict(os.environ, {"MYUNA_REPLY_PLAIN_FALLBACK_ENABLED": "true"}):
            parsed = parse_model_reply_envelope(value)
        self.assertEqual(parsed.reply, value)

    def test_malformed_json_like_output_still_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {"MYUNA_REPLY_PLAIN_FALLBACK_ENABLED": "true"}):
            for value in ('{"reply": broken}', "[not-json]", "```text\nhello\n```"):
                with self.subTest(value=value):
                    with self.assertRaises(ReplyContractError):
                        parse_model_reply_envelope(value)

    def test_empty_output_still_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {"MYUNA_REPLY_PLAIN_FALLBACK_ENABLED": "true"}):
            with self.assertRaises(ReplyContractError):
                parse_model_reply_envelope("   ")
