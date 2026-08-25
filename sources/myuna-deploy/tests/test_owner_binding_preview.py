from __future__ import annotations

import unittest

from scripts.preview_owner_binding import (
    BINDING_ID,
    NAMESPACE_ID,
    PRINCIPAL_ID,
    PreviewError,
    account_fingerprint,
    build_preview_sql,
    public_plan_summary,
)


PEPPER = b"synthetic-owner-binding-pepper-32-bytes-minimum"
ACCOUNT_ID = "123456789"


class OwnerBindingPreviewTests(unittest.TestCase):
    def test_fingerprint_matches_domain_separated_identity_contract(self) -> None:
        fingerprint = account_fingerprint(ACCOUNT_ID, PEPPER)
        self.assertEqual(len(fingerprint), 64)
        self.assertNotIn(ACCOUNT_ID, fingerprint)
        self.assertNotEqual(fingerprint, account_fingerprint("987654321", PEPPER))

    def test_invalid_account_and_short_pepper_are_rejected(self) -> None:
        for invalid in ("", "012345", "abc123", "1234", "1" * 21):
            with self.subTest(invalid=invalid), self.assertRaises(PreviewError):
                account_fingerprint(invalid, PEPPER)
        with self.assertRaises(PreviewError):
            account_fingerprint(ACCOUNT_ID, b"short")

    def test_sql_contains_only_fingerprint_and_is_rollback_only(self) -> None:
        fingerprint = account_fingerprint(ACCOUNT_ID, PEPPER)
        sql = build_preview_sql(fingerprint)
        self.assertIn(fingerprint, sql)
        self.assertNotIn(ACCOUNT_ID, sql)
        self.assertIn("BEGIN;", sql)
        self.assertIn("ROLLBACK;", sql)
        self.assertNotIn("COMMIT;", sql)
        self.assertIn(PRINCIPAL_ID, sql)
        self.assertIn(NAMESPACE_ID, sql)
        self.assertIn(BINDING_ID, sql)
        self.assertIn("'pending'", sql)

    def test_public_summary_excludes_full_fingerprint(self) -> None:
        fingerprint = account_fingerprint(ACCOUNT_ID, PEPPER)
        summary = public_plan_summary(fingerprint)
        self.assertNotIn(fingerprint, repr(summary))
        self.assertEqual(summary["writes_committed"], False)
        self.assertEqual(summary["result"], "transaction-preview-rolled-back")


if __name__ == "__main__":
    unittest.main()
