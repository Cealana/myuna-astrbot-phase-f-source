from __future__ import annotations

from pathlib import Path
import unittest

from scripts.apply_owner_binding_pending import (
    BINDING_ID,
    NAMESPACE_ID,
    PRINCIPAL_ID,
)
from scripts.finalize_owner_binding_verified import (
    build_commit_sql,
    build_compensating_rollback_sql,
    build_finalization_plan,
    finalization_digest,
    public_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "finalize_owner_binding_verified.py"


class OwnerBindingFinalizationTests(unittest.TestCase):
    def test_digest_is_stable_and_evidence_bound(self) -> None:
        first = build_finalization_plan("a" * 64)
        second = build_finalization_plan("b" * 64)
        self.assertEqual(finalization_digest(first), finalization_digest(first))
        self.assertNotEqual(finalization_digest(first), finalization_digest(second))
        self.assertEqual(first["evidence_sha256"], "a" * 64)

    def test_commit_is_exact_three_record_promotion(self) -> None:
        sql = build_commit_sql()
        self.assertIn(PRINCIPAL_ID, sql)
        self.assertIn(NAMESPACE_ID, sql)
        self.assertIn(BINDING_ID, sql)
        self.assertEqual(sql.count("SET principal_status = 'active'"), 1)
        self.assertEqual(sql.count("SET namespace_status = 'active'"), 1)
        self.assertEqual(sql.count("SET binding_status = 'verified'"), 1)
        self.assertIn("verified_at = :'verified_at'::timestamptz", sql)
        self.assertIn("COMMIT;", sql)
        self.assertNotIn("TRUNCATE ", sql)
        self.assertNotIn("DROP ", sql)

    def test_compensating_rollback_is_digest_bound(self) -> None:
        sql = build_compensating_rollback_sql()
        self.assertGreaterEqual(sql.count("finalization_approval_digest"), 6)
        self.assertIn("binding_status = 'pending'", sql)
        self.assertIn("namespace_status = 'pending'", sql)
        self.assertIn("principal_status = 'pending'", sql)
        self.assertIn("verified_at = NULL", sql)
        self.assertNotIn("DELETE FROM", sql)

    def test_receipt_is_safe_and_does_not_claim_runtime_activation(self) -> None:
        receipt = public_receipt(
            evidence_sha256="c" * 64,
            digest="d" * 64,
            verified_at="2026-07-16T03:42:20+00:00",
            backups=[
                {
                    "filename": "safe.dump",
                    "label": "pre",
                    "sha256": "e" * 64,
                    "linux_path": "/safe/pre.dump",
                }
            ],
        )
        rendered = repr(receipt)
        self.assertNotIn("event_id", rendered)
        self.assertNotIn("trace_id", rendered)
        self.assertFalse(receipt["core_activated"])
        self.assertFalse(receipt["memory_activated"])
        self.assertFalse(receipt["model_activated"])
        self.assertFalse(receipt["tools_activated"])

    def test_script_defaults_to_preview_and_cleans_only_one_time_gate(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--apply", action="store_true")', source)
        self.assertIn('parser.add_argument("--check-preconditions", action="store_true")', source)
        self.assertIn("if not args.apply:", source)
        self.assertIn('create_verified_backup("pre"', source)
        self.assertIn('create_verified_backup("post"', source)
        self.assertIn("cleanup_one_time_challenge_gate()", source)
        self.assertIn('pwd.getpwnam("myuna-gateway").pw_uid', source)
        self.assertNotIn("EVIDENCE_PATH.unlink", source)
        self.assertNotIn('systemctl", "start", "myuna-core', source)


if __name__ == "__main__":
    unittest.main()
