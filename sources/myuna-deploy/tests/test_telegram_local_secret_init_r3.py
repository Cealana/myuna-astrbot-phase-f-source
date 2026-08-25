from __future__ import annotations

import itertools
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import telegram_local_secret_init as secret_init


class TelegramLocalSecretInitR3Tests(unittest.TestCase):
    def test_creates_three_distinct_fixed_secrets_without_receipt_material(self):
        values = iter((b"a" * 64, b"b" * 64, b"c" * 64))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "secrets"
            created = secret_init.initialize_local_secrets(
                root,
                secret_factory=lambda: next(values),
                uid=os.getuid(),
                gid=os.getgid(),
            )
            self.assertEqual(created, secret_init.SECRET_NAMES)
            contents = []
            for name in created:
                path = root / name
                metadata = path.stat()
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                contents.append(path.read_bytes().strip())
            self.assertEqual(len(set(contents)), 3)
            self.assertNotIn(contents[0].decode("ascii"), repr(created))

    def test_existing_target_fails_closed_without_changing_any_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "secrets"
            root.mkdir(mode=0o700)
            existing = root / secret_init.SECRET_NAMES[0]
            existing.write_bytes(b"existing\n")
            with self.assertRaises(secret_init.LocalSecretInitRejected):
                secret_init.initialize_local_secrets(
                    root,
                    secret_factory=lambda: b"x" * 64,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            self.assertEqual(existing.read_bytes(), b"existing\n")
            self.assertEqual(tuple(root.iterdir()), (existing,))

    def test_duplicate_or_invalid_generated_secret_rolls_back_all_targets(self):
        cases = (
            itertools.repeat(b"x" * 64),
            iter((b"a" * 64, b"contains space" * 5, b"c" * 64)),
        )
        for values in cases:
            with self.subTest():
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary) / "secrets"
                    with self.assertRaises(secret_init.LocalSecretInitRejected):
                        secret_init.initialize_local_secrets(
                            root,
                            secret_factory=lambda: next(values),
                            uid=os.getuid(),
                            gid=os.getgid(),
                        )
                    self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
