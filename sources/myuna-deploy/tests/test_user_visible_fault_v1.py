from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO, StringIO
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fault_diagnostics_v1 import FAULT_PROFILES  # noqa: E402
import myuna_diagnose  # noqa: E402
import user_visible_fault_v1 as public_fault_module  # noqa: E402
from user_visible_fault_v1 import (  # noqa: E402
    CODEBOOK_VERSION,
    INCIDENT_INDEX_SCHEMA,
    PUBLIC_FAULT_SCHEMA,
    PUBLIC_FAULTS,
    ContentFreeIncidentIndex,
    IncidentIndexRecord,
    PublicFaultProjection,
    new_incident_ref,
    public_fault_for_diagnostic,
    public_fault_for_typed_input,
    render_public_fault,
    validate_incident_ref_v1,
)


NOW = datetime(2026, 8, 3, 10, 0, tzinfo=timezone.utc)


def ref_for(value: bytes) -> str:
    with patch.object(
        public_fault_module.secrets, "token_bytes", return_value=value
    ):
        return new_incident_ref()


class UserVisibleFaultV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.golden = json.loads(
            (ROOT / "tests/fixtures/user_visible_fault_v1_golden.json").read_text(
                encoding="utf-8"
            )
        )

    def test_schema_and_full_codebook_match_frozen_golden(self) -> None:
        self.assertEqual(PUBLIC_FAULT_SCHEMA, self.golden["schema"])
        self.assertEqual(CODEBOOK_VERSION, self.golden["codebook_version"])
        self.assertEqual(
            [PUBLIC_FAULTS[code].as_codebook_row() for code in PUBLIC_FAULTS],
            self.golden["cases"],
        )

    def test_new_refs_are_versioned_opaque_and_distinct(self) -> None:
        first = ref_for(b"\x01" * 16)
        second = ref_for(b"\x02" * 16)
        self.assertEqual(first, "inc1-" + "01" * 16)
        self.assertNotEqual(first, second)
        self.assertEqual(validate_incident_ref_v1(first), first)
        self.assertRegex(first, self.golden["incident_ref_grammar"])
        for invalid in ("inc-000000000000", "inc1-" + "0" * 31, None):
            with self.assertRaises(ValueError):
                validate_incident_ref_v1(invalid)

    def test_telegram_and_qq_have_same_semantics_but_different_incidents(self) -> None:
        descriptor = public_fault_for_diagnostic("local_provider_timeout")
        telegram = PublicFaultProjection.from_descriptor(
            descriptor, channel="telegram", incident_ref=ref_for(b"t" * 16)
        )
        qq = PublicFaultProjection.from_descriptor(
            descriptor, channel="qq", incident_ref=ref_for(b"q" * 16)
        )
        self.assertEqual(telegram.code, qq.code)
        self.assertEqual(telegram.category_zh, qq.category_zh)
        self.assertNotEqual(telegram.incident_ref, qq.incident_ref)
        self.assertEqual(
            render_public_fault(telegram).replace(str(telegram.incident_ref), "REF"),
            render_public_fault(qq).replace(str(qq.incident_ref), "REF"),
        )

    def test_same_correlated_incident_reuses_only_an_explicit_existing_ref(self) -> None:
        ref = ref_for(b"c" * 16)
        descriptor = public_fault_for_diagnostic("core_unreachable")
        first = PublicFaultProjection.from_descriptor(
            descriptor, channel="telegram", incident_ref=ref
        )
        second = PublicFaultProjection.from_descriptor(
            descriptor, channel="qq", incident_ref=ref
        )
        self.assertEqual(first.incident_ref, second.incident_ref)

    def test_missing_ref_is_explicit_and_never_fabricated(self) -> None:
        projection = PublicFaultProjection.from_descriptor(
            public_fault_for_diagnostic("unknown_insufficient_safe_evidence"),
            channel="telegram",
            incident_ref=None,
        )
        payload = projection.as_payload()
        self.assertIsNone(payload["incident_ref"])
        self.assertEqual(payload["incident_ref_status"], "unavailable")
        rendered = render_public_fault(projection)
        self.assertIn("事件号不可用", rendered)
        self.assertNotIn("inc-000000000000", rendered)

    def test_diagnostic_mapping_is_complete_and_normal_128_capacity_is_not_fault(self) -> None:
        non_fault = {
            "active",
            "listening",
            "secure",
            "match",
            "current",
            "session_capacity_128",
            "duplicate_suppressed",
            "recovery_episode_active",
        }
        for code, profile in FAULT_PROFILES.items():
            mapped = public_fault_for_diagnostic(code)
            if profile.state == "ok" or code in non_fault:
                self.assertIsNone(mapped, code)
            else:
                self.assertIsNotNone(mapped, code)
        self.assertIsNone(public_fault_for_diagnostic("session_capacity_128"))
        self.assertEqual(
            public_fault_for_diagnostic("session_capacity_mismatch").code,
            "MYU-SESSION-04",
        )

    def test_profile_failures_and_rejections_remain_distinct(self) -> None:
        codes = {
            public_fault_for_diagnostic(item).code
            for item in (
                "profile_read_unavailable",
                "profile_write_unavailable",
                "candidate_duplicate",
                "candidate_conflict",
                "boundary_rejected",
            )
        }
        self.assertEqual(
            codes,
            {
                "MYU-PROFILE-01",
                "MYU-PROFILE-02",
                "MYU-PROFILE-03",
                "MYU-PROFILE-04",
                "MYU-PROFILE-05",
            },
        )

    def test_typed_p08_p10b_mapping_does_not_accept_free_form_detail(self) -> None:
        self.assertEqual(
            public_fault_for_typed_input("trusted_time", "trusted_time_timeout").code,
            "MYU-TIME-01",
        )
        self.assertEqual(
            public_fault_for_typed_input(
                "active_temporal_context", "database_corrupt"
            ).code,
            "MYU-TEMPORAL-01",
        )
        self.assertEqual(
            public_fault_for_typed_input("unknown", "synthetic-private-marker").code,
            "MYU-UNKNOWN-01",
        )

    def test_content_free_index_is_bounded_idempotent_and_lookupable(self) -> None:
        index = ContentFreeIncidentIndex(max_records=2)
        ref = ref_for(b"a" * 16)
        projection = PublicFaultProjection.from_descriptor(
            public_fault_for_diagnostic("provider_timeout"),
            channel="telegram",
            incident_ref=ref,
        )
        record = IncidentIndexRecord.from_projection(projection, observed_at=NOW)
        self.assertEqual(index.add(record), "added")
        self.assertEqual(index.add(record), "idempotent")
        lookup = index.lookup(ref)
        self.assertEqual(lookup["schema"], INCIDENT_INDEX_SCHEMA)
        self.assertEqual(lookup["code"], "MYU-PROVIDER-01")
        self.assertEqual(lookup["diagnostic_conclusion"], "模型服务超时")
        self.assertNotIn("message", json.dumps(lookup, ensure_ascii=False).casefold())
        conflicting = IncidentIndexRecord(
            schema=record.schema,
            incident_ref=record.incident_ref,
            code="MYU-CORE-02",
            domain="core",
            category_zh="核心处理失败",
            channel="telegram",
            observed_at=record.observed_at,
            retryable=True,
            recovery_class="retry_later",
            recovery_gate="T2",
        )
        with self.assertRaises(ValueError):
            index.add(conflicting)
        for byte in (b"b", b"c"):
            other = PublicFaultProjection.from_descriptor(
                public_fault_for_diagnostic("provider_unavailable"),
                channel="qq",
                incident_ref=ref_for(byte * 16),
            )
            index.add(IncidentIndexRecord.from_projection(other, observed_at=NOW))
        with self.assertRaises(KeyError):
            index.lookup(ref)

    def test_index_allocation_never_reuses_a_retained_ref_for_a_new_incident(self) -> None:
        index = ContentFreeIncidentIndex(max_records=4)
        descriptor = public_fault_for_diagnostic("provider_timeout")
        values = iter((b"a" * 16, b"a" * 16, b"b" * 16))
        with patch.object(
            public_fault_module.secrets,
            "token_bytes",
            side_effect=lambda size: next(values),
        ):
            first = index.allocate(
                descriptor, channel="telegram", observed_at=NOW
            )
            second = index.allocate(
                descriptor, channel="telegram", observed_at=NOW
            )
        self.assertNotEqual(first.incident_ref, second.incident_ref)

    def test_projection_rejects_extra_or_forbidden_fields(self) -> None:
        projection = PublicFaultProjection.from_descriptor(
            public_fault_for_diagnostic("core_runtime_fail_closed"),
            channel="qq",
            incident_ref=ref_for(b"z" * 16),
        )
        payload = projection.as_payload()
        round_trip = PublicFaultProjection.from_payload(payload)
        self.assertEqual(round_trip, projection)
        for field in (
            "raw_exception",
            "path",
            "secret",
            "amount",
            "reservation",
            "ledger",
            "provider_payload",
            "model_response",
            "private_message",
            "profile",
            "db_row",
            "fingerprint",
        ):
            with self.assertRaises(ValueError):
                PublicFaultProjection.from_payload({**payload, field: "synthetic"})
        with self.assertRaises((TypeError, ValueError)):
            PublicFaultProjection.from_payload({**payload, "retryable": 1})
        with self.assertRaises((TypeError, ValueError)):
            PublicFaultProjection.from_payload({**payload, "codebook_version": True})

        record = IncidentIndexRecord.from_projection(projection, observed_at=NOW)
        with self.assertRaises((TypeError, ValueError)):
            IncidentIndexRecord.from_payload({**record.as_payload(), "retryable": 1})

    def test_index_requires_aware_time_and_deterministic_utc_projection(self) -> None:
        projection = PublicFaultProjection.from_descriptor(
            public_fault_for_diagnostic("release_drift"),
            channel="qq",
            incident_ref=ref_for(b"d" * 16),
        )
        record = IncidentIndexRecord.from_projection(
            projection,
            observed_at=NOW.astimezone(timezone(timedelta(hours=8))),
        )
        self.assertEqual(record.observed_at, "2026-08-03T10:00:00Z")
        with self.assertRaises(ValueError):
            IncidentIndexRecord.from_projection(
                projection, observed_at=datetime(2026, 8, 3, 10, 0)
            )

    def test_owner_cli_explicit_index_lookup_is_content_free_and_legacy_default_unchanged(self) -> None:
        index = ContentFreeIncidentIndex(max_records=4)
        ref = ref_for(b"e" * 16)
        projection = PublicFaultProjection.from_descriptor(
            public_fault_for_diagnostic("local_model_not_ready"),
            channel="telegram",
            incident_ref=ref,
        )
        index.add(IncidentIndexRecord.from_projection(projection, observed_at=NOW))
        encoded = json.dumps(index.as_payload()).encode("ascii")
        stdout = StringIO()
        stdin = type("Input", (), {"buffer": BytesIO(encoded)})()
        with patch.object(sys, "stdin", stdin), patch.object(
            sys, "stdout", stdout
        ):
            exit_code = myuna_diagnose.main(
                ["--incident-index", "-", "--incident-ref", ref]
            )
        self.assertEqual(exit_code, 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["code"], "MYU-LOCAL-03")
        self.assertEqual(report["incident_ref"], ref)
        self.assertEqual(report["diagnostic_conclusion"], "本地模型未就绪")
        self.assertEqual(report["recovery_gate"], "T2")
        source = (ROOT / "scripts/myuna_diagnose.py").read_text(encoding="utf-8")
        self.assertNotIn("/healthz", source)
        self.assertNotIn("/readyz", source)

    def test_new_public_projection_is_not_wired_into_legacy_gateway_paths(self) -> None:
        for relative in (
            "scripts/gateway_degradation_protocol.py",
            "scripts/fault_incident_v1.py",
            "scripts/fault_diagnostics_collector_v1.py",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("user_visible_fault_v1", source, relative)


if __name__ == "__main__":
    unittest.main()
