from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import unittest

from scripts.apply_owner_binding_pending import (
    APPROVED_PLAN_DIGEST,
    BINDING_ID,
    CHANNEL_KIND,
    NAMESPACE_ID,
    PRINCIPAL_ID,
    build_commit_sql,
    build_rollback_sql,
    public_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "apply_owner_binding_pending.py"
CLIPBOARD = ROOT / "scripts" / "copy_channel_secret_to_clipboard.sh"


class PendingOwnerApplyTests(unittest.TestCase):
    def test_commit_is_exact_pending_only_and_digest_bound(self) -> None:
        sql = build_commit_sql()
        self.assertIn("COMMIT;", sql)
        self.assertIn(":'fingerprint'", sql)
        self.assertIn(":'plan_digest'", sql)
        self.assertIn(PRINCIPAL_ID, sql)
        self.assertIn(NAMESPACE_ID, sql)
        self.assertIn(BINDING_ID, sql)
        self.assertIn(CHANNEL_KIND, sql)
        self.assertEqual(sql.count("'pending'"), 3)
        self.assertNotIn("'active'", sql)
        self.assertNotIn("'verified'", sql)

    def test_rollback_can_only_remove_matching_pending_rows(self) -> None:
        sql = build_rollback_sql()
        self.assertIn("binding_status = 'pending'", sql)
        self.assertIn("namespace_status = 'pending'", sql)
        self.assertIn("principal_status = 'pending'", sql)
        self.assertGreaterEqual(sql.count("metadata ->> 'approval_digest'"), 3)
        self.assertNotIn("DROP ", sql)
        self.assertNotIn("TRUNCATE ", sql)

    def test_public_receipt_excludes_full_fingerprint_and_challenge(self) -> None:
        fingerprint = "a" * 64
        receipt = public_receipt(
            fingerprint=fingerprint,
            expires_at=datetime(2026, 7, 16, tzinfo=timezone.utc),
            backups=[
                {
                    "filename": "synthetic.dump",
                    "label": "pre",
                    "sha256": "b" * 64,
                    "linux_path": "/synthetic/pre.dump",
                    "windows_path": "/synthetic/pre-copy.dump",
                }
            ],
        )
        rendered = repr(receipt)
        self.assertNotIn(fingerprint, rendered)
        self.assertNotIn("challenge_code", rendered)
        self.assertEqual(receipt["plan_digest"], APPROVED_PLAN_DIGEST)
        self.assertFalse(receipt["core_activated"])
        self.assertFalse(receipt["memory_activated"])
        self.assertFalse(receipt["model_activated"])
        self.assertFalse(receipt["tools_activated"])

    def test_script_requires_local_hidden_input_and_verified_backups(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("sys.stdin.isatty()", source)
        self.assertIn("getpass.getpass", source)
        self.assertIn("APPROVED_PLAN_DIGEST", source)
        self.assertIn("create_verified_backup(\"pre\"", source)
        self.assertIn("create_verified_backup(\"post\"", source)
        self.assertIn("pg_restore", source)
        self.assertIn('/var/backups/postgresql/myuna/owner-binding-v1', source)
        self.assertNotIn('LINUX_BACKUP_ROOT = Path("/srv/myuna/', source)
        self.assertIn("f\"{record['label']}-{source.name}\"", source)
        self.assertIn("myuna-channel-gateway-dev.socket", source)
        self.assertNotIn("systemctl\", \"start\", \"myuna-core", source)

    def test_clipboard_helper_supports_hidden_owner_challenge(self) -> None:
        source = CLIPBOARD.read_text(encoding="utf-8")
        self.assertIn("owner-challenge)", source)
        self.assertIn("owner-challenge-code-v1", source)
        self.assertNotIn("cat ${secret}", source)


if __name__ == "__main__":
    unittest.main()
