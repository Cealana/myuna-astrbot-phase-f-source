from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import session_context_admin as admin  # noqa: E402
from context_window_policy import SqliteContextStore  # noqa: E402


class SessionContextAdminTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "qq" / "context.db"
        self.channels = {
            "qq": (self.database, "qq-owner-private-v1"),
        }
        store = SqliteContextStore(
            self.database,
            namespace="qq-owner-private-v1",
        )
        store.save(
            "synthetic-owner",
            [
                {"role": "user", "content": "private-synthetic-input"},
                {"role": "assistant", "content": "private-synthetic-output"},
            ],
        )

    def test_metadata_inspection_omits_content_by_default(self) -> None:
        with mock.patch.dict(admin.CHANNELS, self.channels, clear=True):
            result = admin.inspect_channel("qq", show_content=False)
        self.assertTrue(result["present"])
        self.assertEqual(result["message_count"], 2)
        self.assertNotIn("messages", result)
        self.assertNotIn("private-synthetic-input", json.dumps(result))

    def test_content_requires_explicit_flag_and_root(self) -> None:
        with (
            mock.patch.dict(admin.CHANNELS, self.channels, clear=True),
            mock.patch.object(admin, "_is_root", return_value=False),
            self.assertRaisesRegex(SystemExit, "requires root"),
        ):
            admin.main(["inspect", "--channel", "qq", "--show-content"])

        with mock.patch.dict(admin.CHANNELS, self.channels, clear=True):
            result = admin.inspect_channel("qq", show_content=True)
        self.assertEqual(result["messages"][0]["content"], "private-synthetic-input")

    def test_clear_requires_exact_confirmation_and_root(self) -> None:
        with (
            mock.patch.dict(admin.CHANNELS, self.channels, clear=True),
            mock.patch.object(admin, "_is_root", return_value=True),
            self.assertRaisesRegex(SystemExit, "exactly match CLEAR-QQ"),
        ):
            admin.main(["clear", "--channel", "qq", "--confirm", "yes"])

        output = io.StringIO()
        with (
            mock.patch.dict(admin.CHANNELS, self.channels, clear=True),
            mock.patch.object(admin, "_is_root", return_value=True),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                admin.main(
                    ["clear", "--channel", "qq", "--confirm", "CLEAR-QQ"]
                ),
                0,
            )
            metadata = admin.inspect_channel("qq", show_content=False)
        self.assertEqual(json.loads(output.getvalue()), {"cleared": {"qq": True}})
        self.assertFalse(metadata["present"])


if __name__ == "__main__":
    unittest.main()
