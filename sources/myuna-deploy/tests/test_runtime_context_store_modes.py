from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from context_window_policy import (  # noqa: E402
    ContextWindowRejected,
    ConversationHistory,
    InMemoryContextStore,
    SqliteContextStore,
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


qq = _load("persistent_context_qq_runtime_test", SCRIPTS / "qq_owner_runtime_gateway.py")
telegram = _load(
    "persistent_context_telegram_runtime_test",
    SCRIPTS / "telegram_owner_runtime_gateway.py",
)


class RuntimeContextStoreModeTests(unittest.TestCase):
    def test_memory_remains_default_and_rollback_mode(self) -> None:
        for runtime in (qq, telegram):
            with self.subTest(runtime=runtime.CHANNEL_KIND):
                with mock.patch.dict(os.environ, {}, clear=False):
                    os.environ.pop(runtime.CONTEXT_STORE_MODE_ENV, None)
                    self.assertIsInstance(
                        runtime._build_context_store(),
                        InMemoryContextStore,
                    )

    def test_unknown_mode_fails_closed(self) -> None:
        for runtime in (qq, telegram):
            with self.subTest(runtime=runtime.CHANNEL_KIND):
                with mock.patch.dict(
                    os.environ,
                    {runtime.CONTEXT_STORE_MODE_ENV: "unknown"},
                ):
                    with self.assertRaises(runtime.RuntimeRejected):
                        runtime._build_context_store()

    def test_sqlite_mode_uses_distinct_channel_namespaces_and_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = (
                (qq, root / "qq" / "context.db", "qq-owner-private-v1"),
                (
                    telegram,
                    root / "telegram" / "context.db",
                    "telegram-owner-private-v1",
                ),
            )
            for runtime, database, namespace in cases:
                with self.subTest(runtime=runtime.CHANNEL_KIND):
                    with (
                        mock.patch.object(runtime, "CONTEXT_DATABASE_PATH", database),
                        mock.patch.dict(
                            os.environ,
                            {runtime.CONTEXT_STORE_MODE_ENV: "sqlite-v1"},
                        ),
                    ):
                        store = runtime._build_context_store()
                    self.assertIsInstance(store, SqliteContextStore)
                    self.assertEqual(store.namespace, namespace)
                    self.assertEqual(store.database_path, database)

    def test_persistence_write_failure_keeps_reply_path_available(self) -> None:
        class FailingStore:
            def load(self, conversation_id: str) -> list[dict[str, str]]:
                return []

            def save(
                self,
                conversation_id: str,
                messages: list[dict[str, str]],
            ) -> None:
                raise ContextWindowRejected("synthetic persistence failure")

        history = ConversationHistory(128, 131072, store=FailingStore())
        request = history.request_messages("synthetic-owner", "synthetic-user")
        for runtime in (qq, telegram):
            with self.subTest(runtime=runtime.CHANNEL_KIND):
                with mock.patch.object(runtime, "_audit_stage") as audit:
                    self.assertFalse(
                        runtime._commit_reply_best_effort(
                            history,
                            "synthetic-owner",
                            request,
                            "synthetic-assistant",
                        )
                    )
                audit.assert_called_once_with("context_persistence_degraded")


if __name__ == "__main__":
    unittest.main()
