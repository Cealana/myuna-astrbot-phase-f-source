from __future__ import annotations

from pathlib import Path
import unittest


import build_p07_hybrid_live_releases_v1 as hybrid_builder
import build_p16_releases_v1 as p16_builder
import build_persistent_session_context_v1_release as persistent_builder
import incident_history_v1


ROOT = Path(__file__).resolve().parents[1]


class P16PackagedObservabilityParityV1Tests(unittest.TestCase):
    def test_every_runtime_builder_carries_the_complete_adapter_closure(self) -> None:
        runtime_names = {
            "degradation_shadow_enqueue.py",
            "fault_incident_v1.py",
            "gateway_degradation_protocol.py",
            "gateway_enqueue.py",
            "gateway_post_reply.py",
            "incident_history_runtime_adapter_v1.py",
            "incident_history_v1.py",
            "user_visible_fault_v1.py",
        }
        p16_names = {Path(path).name for path in p16_builder._GATEWAY_SHARED}
        persistent_names = {Path(path).name for path in persistent_builder.REPLACEMENTS}
        self.assertTrue(runtime_names.issubset(p16_names))
        self.assertTrue(runtime_names.issubset(persistent_names))
        self.assertTrue(runtime_names.issubset(set(hybrid_builder._RUNTIME_OVERLAYS)))

    def test_p16_core_overlay_carries_every_precise_provenance_source(self) -> None:
        required = {
            "src/myuna_core/conversation.py",
            "src/myuna_core/degradation_bridge.py",
            "src/myuna_core/degradation_http.py",
            "src/myuna_core/external_context/live.py",
            "src/myuna_core/http_api.py",
            "src/myuna_core/user_visible_fault.py",
            "tests/test_p16_failure_provenance_v1.py",
        }
        self.assertTrue(required.issubset(p16_builder._CORE_OVERLAYS))

    def test_temporal_mapping_is_packaged_but_not_an_ordinary_fallback_cause(self) -> None:
        self.assertEqual(
            incident_history_v1._TYPED_DETAILS["gateway-temporal-unavailable"],
            ("session", "temporal_context", "temporal_unavailable"),
        )
        telegram = (ROOT / "scripts/telegram_owner_runtime_gateway.py").read_text(
            encoding="utf-8"
        )
        temporal_branch = telegram[
            telegram.index("temporal_command = parse_temporal_command") :
            telegram.index("diary_control = diary_command_is_explicit")
        ]
        self.assertIn('"gateway-temporal-unavailable"', temporal_branch)
        self.assertIn('record_outcome(\n                    decision, "accepted"', temporal_branch)
        self.assertIn("build_incident_history_job", telegram)
        self.assertNotIn("gateway-temporal-unavailable", p16_builder._CORE_OVERLAYS)


if __name__ == "__main__":
    unittest.main()
