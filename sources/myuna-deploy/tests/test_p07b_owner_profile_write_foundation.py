from __future__ import annotations

from pathlib import Path
import unittest

from myuna_core.owner_profile import lifecycle as core_lifecycle


ROOT = Path(__file__).resolve().parents[1]
ADR = ROOT / "docs/ADR-054-owner-profile-write-lifecycle-v1.md"
THREAT_MODEL = ROOT / "docs/p07b-owner-profile-write-threat-model-v1.md"
CORE_LIFECYCLE = Path(core_lifecycle.__file__)


class P07BOwnerProfileWriteFoundationTests(unittest.TestCase):
    def test_adr_requires_exact_owner_confirmation_and_immutable_revision(self) -> None:
        text = ADR.read_text("utf-8")
        normalized = " ".join(text.split())
        for required in (
            "complete candidate Profile revision",
            "Owner to review the exact candidate and confirm that digest",
            "No event permits an in-place rewrite",
            "does not implement automatic extraction",
            "does not write legacy Owner Memory v1/v2",
            "creates one mode-`0600` pending file without overwrite",
            "Recovery is request-bound",
        ):
            self.assertIn(required, normalized)

    def test_deletion_is_two_phase_and_real_purge_is_a_hard_stop(self) -> None:
        text = ADR.read_text("utf-8")
        self.assertIn("`deletion_requested` is a reversible logical state", text)
        self.assertIn("Physical purge is irreversible and remains a hard stop", text)
        self.assertIn("does not purge the Owner's real revisions", text)
        self.assertIn("a purged release cannot be restored", text)

    def test_threat_model_forbids_model_authority_and_deepseek_egress(self) -> None:
        text = THREAT_MODEL.read_text("utf-8")
        for required in (
            "Model output is treated as write authority",
            "No extractor, summarizer or channel writer exists",
            "DeepSeek reads candidate or Profile",
            "No model call in write lifecycle",
            "No audit emission",
        ):
            self.assertIn(required, text)

    def test_core_lifecycle_source_has_no_runtime_or_legacy_writer_dependency(self) -> None:
        text = CORE_LIFECYCLE.read_text("utf-8")
        for forbidden in (
            "owner_readonly",
            "owner_readonly_v2",
            "psycopg",
            "conversation",
            "capability_runtime",
            "requests",
            "http.client",
            "socket",
            "subprocess",
        ):
            self.assertNotIn(forbidden, text)
        self.assertIn('AUDIT_NAMESPACE = "owner_profile_write_lifecycle_v1"', text)
        self.assertIn('"legacy_namespace_written": False', text)
        self.assertIn('"raw_content_recorded": False', text)


if __name__ == "__main__":
    unittest.main()
