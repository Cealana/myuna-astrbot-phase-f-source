from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from context_window_policy import (  # noqa: E402
    ContextWindowRejected,
    ConversationHistory,
    SqliteContextStore,
)


class SqliteContextStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "state" / "context.db"

    def _store(
        self,
        *,
        database: Path | None = None,
        namespace: str = "qq-owner-private-v1",
    ) -> SqliteContextStore:
        return SqliteContextStore(database or self.database, namespace=namespace)

    def test_restart_restores_exact_bounded_snapshot(self) -> None:
        history = ConversationHistory(
            128,
            131072,
            store=self._store(),
        )
        for index in range(64):
            request = history.request_messages("synthetic-owner", f"用户-{index}")
            history.commit_reply("synthetic-owner", request, f"回复-{index}")

        restored = ConversationHistory(
            128,
            131072,
            store=self._store(),
        )
        request = restored.request_messages("synthetic-owner", "重启后的新问题")
        self.assertEqual(len(request), 127)
        self.assertEqual(request[0]["content"], "用户-1")
        self.assertEqual(request[-1]["content"], "重启后的新问题")
        restored.commit_reply("synthetic-owner", request, "重启后的新回复")
        saved = self._store().load("synthetic-owner")
        self.assertEqual(len(saved), 128)
        self.assertNotIn("用户-0", [item["content"] for item in saved])
        self.assertEqual(saved[-1]["content"], "重启后的新回复")

    def test_database_and_directory_permissions_are_private(self) -> None:
        store = self._store()
        store.save(
            "synthetic-owner",
            [
                {"role": "user", "content": "你好"},
                {"role": "assistant", "content": "你好呀"},
            ],
        )
        if os.name == "posix":
            self.assertEqual(
                stat.S_IMODE(self.database.parent.stat().st_mode),
                0o700,
            )
            self.assertEqual(stat.S_IMODE(self.database.stat().st_mode), 0o600)

    def test_channel_and_conversation_isolation(self) -> None:
        qq = self._store(database=self.root / "qq" / "context.db")
        telegram = self._store(
            database=self.root / "telegram" / "context.db",
            namespace="telegram-owner-private-v1",
        )
        qq.save(
            "same-synthetic-conversation",
            [
                {"role": "user", "content": "仅QQ"},
                {"role": "assistant", "content": "QQ回复"},
            ],
        )
        telegram.save(
            "same-synthetic-conversation",
            [
                {"role": "user", "content": "仅Telegram"},
                {"role": "assistant", "content": "Telegram回复"},
            ],
        )
        self.assertEqual(qq.load("same-synthetic-conversation")[0]["content"], "仅QQ")
        self.assertEqual(
            telegram.load("same-synthetic-conversation")[0]["content"],
            "仅Telegram",
        )
        self.assertEqual(qq.load("different-synthetic-conversation"), [])

    def test_conversation_change_replaces_without_mixing(self) -> None:
        store = self._store()
        store.save(
            "first",
            [
                {"role": "user", "content": "first-user"},
                {"role": "assistant", "content": "first-assistant"},
            ],
        )
        self.assertEqual(store.load("second"), [])
        store.save(
            "second",
            [
                {"role": "user", "content": "second-user"},
                {"role": "assistant", "content": "second-assistant"},
            ],
        )
        self.assertEqual(store.load("first"), [])
        self.assertEqual(store.load("second")[0]["content"], "second-user")

    def test_raw_conversation_id_is_not_persisted(self) -> None:
        store = self._store()
        raw_conversation_id = "raw-conversation-marker-a0f352"
        store.save(
            raw_conversation_id,
            [
                {"role": "user", "content": "synthetic-user"},
                {"role": "assistant", "content": "synthetic-assistant"},
            ],
        )
        marker = raw_conversation_id.encode("utf-8")
        for path in (
            self.database,
            Path(f"{self.database}-wal"),
            Path(f"{self.database}-shm"),
        ):
            if path.exists():
                self.assertNotIn(marker, path.read_bytes())

    def test_corruption_is_rejected_without_returning_content(self) -> None:
        store = self._store()
        store.save(
            "synthetic-owner",
            [
                {"role": "user", "content": "before"},
                {"role": "assistant", "content": "valid"},
            ],
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE context_snapshot SET messages_json = ? WHERE singleton = 1",
                ('[{"role":"user","content":"tampered"}]',),
            )
        with self.assertRaises(ContextWindowRejected):
            store.load("synthetic-owner")

    def test_failed_transaction_preserves_last_good_snapshot(self) -> None:
        store = self._store()
        original = [
            {"role": "user", "content": "before"},
            {"role": "assistant", "content": "stable"},
        ]
        store.save("synthetic-owner", original)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                """
                CREATE TRIGGER reject_context_update
                BEFORE UPDATE ON context_snapshot
                BEGIN
                    SELECT RAISE(ABORT, 'synthetic write failure');
                END
                """
            )
        with self.assertRaises(ContextWindowRejected):
            store.save(
                "synthetic-owner",
                [
                    {"role": "user", "content": "after"},
                    {"role": "assistant", "content": "must-not-commit"},
                ],
            )
        self.assertEqual(store.load("synthetic-owner"), original)

    def test_invalid_roles_and_incomplete_turns_are_rejected(self) -> None:
        store = self._store()
        invalid_snapshots = [
            [{"role": "user", "content": "incomplete"}],
            [
                {"role": "assistant", "content": "wrong"},
                {"role": "user", "content": "order"},
            ],
            [
                {"role": "user", "content": "extra"},
                {"role": "assistant", "content": "key", "name": "unsafe"},
            ],
        ]
        for snapshot in invalid_snapshots:
            with self.subTest(snapshot=snapshot):
                with self.assertRaises(ContextWindowRejected):
                    store.save("synthetic-owner", snapshot)  # type: ignore[arg-type]

    def test_clear_removes_snapshot_but_keeps_database(self) -> None:
        store = self._store()
        marker = "clear-marker-7f99671d"
        store.save(
            "synthetic-owner",
            [
                {"role": "user", "content": marker},
                {"role": "assistant", "content": "clear-confirmed"},
            ],
        )
        self.assertTrue(store.clear())
        self.assertEqual(store.load("synthetic-owner"), [])
        self.assertTrue(self.database.exists())
        for path in (
            self.database,
            Path(f"{self.database}-wal"),
            Path(f"{self.database}-shm"),
        ):
            if path.exists():
                self.assertNotIn(marker.encode("utf-8"), path.read_bytes())
        self.assertFalse(store.clear())


if __name__ == "__main__":
    unittest.main()
