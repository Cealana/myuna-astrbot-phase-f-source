from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import telegram_owner_binding as binding
import telegram_owner_discovery as discovery


class TelegramOwnerBindingR2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
        self.raw_id = "123456789"
        self.pepper = b"synthetic-identity-pepper-32-bytes-minimum"
        self.challenge = "c" * 43
        self.payload = discovery.build_discovery_evidence(
            self.raw_id,
            self.pepper,
            now=self.now,
        )
        serialized = binding.canonical_json(self.payload)
        self.evidence = binding.DiscoveryEvidence.from_payload(
            self.payload,
            evidence_sha256=sha256(serialized).hexdigest(),
            now=self.now + timedelta(seconds=1),
        )

    def test_discovery_evidence_contains_fingerprint_but_no_raw_id(self) -> None:
        rendered = repr(self.payload)
        self.assertNotIn(self.raw_id, rendered)
        self.assertFalse(self.payload["raw_account_id_stored"])
        self.assertEqual(self.payload["channel_kind"], "astrbot_telegram")

    def test_private_start_parser_is_exact_and_private(self) -> None:
        valid = {
            "update_id": 1,
            "message": {
                "chat": {"id": 123456789, "type": "private"},
                "from": {"id": 123456789, "is_bot": False},
                "text": f"/start {self.challenge}",
            },
        }
        self.assertEqual(
            discovery.private_start_sender_id(valid, self.challenge),
            self.raw_id,
        )
        for mutation in (
            "group",
            "bot",
            "other_text",
            "different_challenge",
            "different_chat",
        ):
            candidate = {
                "update_id": 1,
                "message": {
                    "chat": {"id": 123456789, "type": "private"},
                    "from": {"id": 123456789, "is_bot": False},
                    "text": f"/start {self.challenge}",
                },
            }
            if mutation == "group":
                candidate["message"]["chat"]["type"] = "group"
            elif mutation == "bot":
                candidate["message"]["from"]["is_bot"] = True
            elif mutation == "other_text":
                candidate["message"]["text"] = "hello"
            elif mutation == "different_challenge":
                candidate["message"]["text"] = f"/start {'d' * 43}"
            else:
                candidate["message"]["chat"]["id"] = 987654321
            self.assertIsNone(
                discovery.private_start_sender_id(candidate, self.challenge)
            )

    def test_public_preview_binds_full_fingerprint_without_showing_it(self) -> None:
        private_plan = binding.build_pending_plan(self.evidence)
        preview = binding.public_pending_preview(self.evidence)
        self.assertEqual(preview["plan_digest"], binding.plan_digest(private_plan))
        self.assertNotIn(
            self.evidence.account_fingerprint,
            repr(preview),
        )
        self.assertIn("...", preview["fingerprint_preview"])
        self.assertFalse(preview["raw_account_id_stored"])

    def test_pending_sql_adds_only_one_binding_to_existing_owner(self) -> None:
        sql = binding.build_pending_insert_sql()
        self.assertIn("INSERT INTO myuna_identity.account_binding", sql)
        self.assertNotIn("INSERT INTO myuna_identity.principal", sql)
        self.assertNotIn("INSERT INTO memory.memory_namespace", sql)
        self.assertNotIn("UPDATE myuna_identity.principal", sql)
        self.assertNotIn("UPDATE memory.memory_namespace", sql)
        self.assertIn("binding-astrbot-telegram-owner-cealana", sql)

    def test_finalization_updates_only_telegram_binding(self) -> None:
        sql = binding.build_finalization_sql()
        self.assertIn("UPDATE myuna_identity.account_binding", sql)
        self.assertNotIn("UPDATE myuna_identity.principal", sql)
        self.assertNotIn("UPDATE memory.memory_namespace", sql)
        self.assertIn("channel_kind = 'astrbot_telegram'", sql)
        self.assertIn("owner_challenge_matched", sql)

    def test_discovery_polling_discards_stale_update_then_accepts_new_start(self) -> None:
        calls: list[tuple[str, object]] = []

        def fake_api(token: str, method: str, parameters):
            self.assertEqual(token, "synthetic")
            calls.append((method, parameters))
            if method == "getMe":
                return {"is_bot": True}
            if method == "getWebhookInfo":
                return {"url": ""}
            if parameters.get("offset") == -1:
                return [{"update_id": 40}]
            return [
                {
                    "update_id": 41,
                    "message": {
                        "chat": {"id": 123456789, "type": "private"},
                        "from": {"id": 123456789, "is_bot": False},
                        "text": f"/start {self.challenge}",
                    },
                }
            ]

        evidence = discovery.discover_private_start(
            "synthetic",
            self.pepper,
            challenge=self.challenge,
            api_call=fake_api,
            deadline_seconds=10,
        )
        self.assertFalse(evidence["raw_account_id_stored"])
        self.assertFalse(evidence["discovery_command_challenge_stored"])
        self.assertEqual(calls[1], ("getWebhookInfo", {}))
        self.assertEqual(calls[2], ("getUpdates", {"offset": -1, "timeout": 0}))
        self.assertEqual(calls[3][1]["offset"], 41)

    def test_discovery_rejects_active_webhook_before_polling(self) -> None:
        calls: list[str] = []

        def fake_api(_token: str, method: str, _parameters):
            calls.append(method)
            if method == "getMe":
                return {"is_bot": True}
            if method == "getWebhookInfo":
                return {"url": "https://example.invalid/hook"}
            self.fail("polling must not start while a webhook is active")

        with self.assertRaises(discovery.DiscoveryRejected):
            discovery.discover_private_start(
                "synthetic",
                self.pepper,
                challenge=self.challenge,
                api_call=fake_api,
                deadline_seconds=10,
            )
        self.assertEqual(calls, ["getMe", "getWebhookInfo"])


if __name__ == "__main__":
    unittest.main()
