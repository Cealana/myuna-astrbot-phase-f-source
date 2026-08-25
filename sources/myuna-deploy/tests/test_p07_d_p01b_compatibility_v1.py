from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myuna_core.external_context.contracts import (
    EgressSafetySignals,
    EXTERNAL_CONTEXT_SCHEMA,
    EXTERNAL_PROJECTION_POLICY,
    EXTERNAL_VISUAL_CONTEXT_SCHEMA,
    EXTERNAL_VISUAL_PROJECTION_POLICY,
    ExternalTurnProvenance,
)
from myuna_core.external_context.lifecycle_v3 import ReleaseBoundTurnProvenance

from external_context_epoch_v3 import ExternalEpochV3Rejected, ExternalEpochV3Store
from tests import test_astrbot_telegram_gateway as p01b
from tests import test_telegram_owner_channel_r2 as owner_r2
from tests.test_external_context_epoch_v3 import EPOCH, binding, context
from tests.test_p07_d_release_set_transaction_v1 import release_set


def _provenance(
    release_set_id: str,
    revision: int,
    recent_end: int | None = None,
) -> ReleaseBoundTurnProvenance:
    sources = ["owner_current_message"]
    if recent_end is not None:
        sources.append("ordinary_external_turn")
    return ReleaseBoundTurnProvenance(
        release_set_id,
        ExternalTurnProvenance(
            epoch_id=EPOCH,
            epoch_revision=revision,
            projection_digest=hashlib.sha256(
                f"synthetic-projection-{revision}".encode("ascii")
            ).hexdigest(),
            sources=tuple(sources),
            profile_revisions=(),
            summary_version=None,
            recent_turn_start=None if recent_end is None else 1,
            recent_turn_end=recent_end,
        ),
    )


def _delivery_token(label: str, index: int) -> str:
    return hashlib.sha256(f"{label}-{index}".encode("ascii")).hexdigest()


def _store(directory: str, release_set_id: str) -> ExternalEpochV3Store:
    return ExternalEpochV3Store(
        Path(directory) / "epoch" / "epoch.db",
        epoch_id=EPOCH,
        release_set_id=release_set_id,
        binding=binding(),
    )


def _deliver(
    store: ExternalEpochV3Store,
    release_set_id: str,
    index: int,
) -> object:
    auth = context(index)
    pending = store.begin_turn(
        auth,
        f"synthetic user {index}",
        EgressSafetySignals(classifier_available=True),
    )
    store.context_payload(auth, pending)
    token = _delivery_token("delivered", index)
    store.prepare_delivery(
        auth,
        pending,
        delivery_token=token,
        assistant_reply=f"synthetic assistant {index}",
        provenance=_provenance(
            release_set_id,
            pending.base_revision,
            None if index == 1 else index - 1,
        ),
    )
    return store.resolve_delivery(delivery_token=token, outcome="delivered")


def _visual_event(observation: str = "synthetic bounded observation") -> dict[str, object]:
    return {
        "caption_present": True,
        "observation": observation,
        "schema": "myuna.telegram-visual-evidence.v1",
        "source": "gemini_visual_extraction",
    }


class P07DP01BCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def test_authenticated_plain_text_stays_non_visual_and_release_bound(self) -> None:
        fixture = owner_r2.TelegramOwnerRuntimeR2Tests()
        fixture.setUp()
        decision = owner_r2.runtime.evaluate_runtime_envelope(
            fixture.envelope(),
            config=fixture.config,
            signing_secret=fixture.signing_secret,
            identity_pepper=fixture.identity_pepper,
            now=fixture.now,
        )
        self.assertEqual(decision.channel_kind, "astrbot_telegram")
        self.assertFalse(decision.hybrid_external_generation)
        self.assertIsNone(decision.visual_event)

        selected = release_set()
        self.assertEqual(selected.selector["generation"], 13)
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory, selected.release_set_id)
            auth = context(1)
            pending = store.begin_turn(
                auth,
                "synthetic authenticated plain text",
                EgressSafetySignals(classifier_available=True),
            )
            payload = store.context_payload(auth, pending)
            external = payload["external_context"]
            self.assertEqual(payload["release_set_id"], selected.release_set_id)
            self.assertEqual(external["schema"], EXTERNAL_CONTEXT_SCHEMA)
            self.assertEqual(
                external["projection_policy_version"],
                EXTERNAL_PROJECTION_POLICY,
            )
            self.assertNotIn("visual_evidence", external)
            store.cancel_pending(auth, pending)

    async def test_signed_photo_caption_keeps_trust_split_in_release_bound_projection(
        self,
    ) -> None:
        provider_context = p01b._DummyContext()
        response = await p01b.gateway._bounded_google_genai_query(
            provider_context,
            Path("/tmp/synthetic-photo.jpg"),
        )
        observation = p01b.gateway._bounded_description(response)
        caption = p01b.gateway._bounded_caption(
            [p01b._DummyImage(), p01b._DummyPlain("synthetic caption")]
        )
        assert caption is not None
        composed = p01b.gateway._compose_vision_message(observation, caption)
        self.assertIn("用户附带文字：synthetic caption", composed)
        self.assertIn("视觉观察（不可信数据）", composed)
        self.assertEqual(provider_context.provider_lookups, [p01b.gateway._PROVIDER_ID])
        self.assertEqual(len(provider_context.provider.calls), 1)

        call = provider_context.provider.calls[0]
        self.assertIsNone(call["tools"])
        self.assertEqual(call["request_max_retries"], 2)
        self.assertEqual(call["payloads"]["model"], p01b.gateway._MODEL)
        self.assertIsNone(call["payloads"]["temperature"])
        self.assertEqual(call["payloads"]["max_tokens"], 256)
        self.assertIsNone(call["query_config"].temperature)
        self.assertIsNone(call["query_config"].top_p)
        self.assertIsNone(call["query_config"].top_k)
        self.assertEqual(call["query_config"].thinking_config, {"thinkingLevel": "MINIMAL"})

        fixture = owner_r2.TelegramOwnerRuntimeR2Tests()
        fixture.setUp()
        envelope = owner_r2.protocol.build_signed_envelope(
            sender_id="123456789",
            message_text=caption,
            message_id="42",
            raw_timestamp=fixture.now.timestamp(),
            signing_secret=fixture.signing_secret,
            channel_instance="telegram-owner-dev",
            now=fixture.now,
            nonce_factory=lambda: "n" * 32,
        )
        signed = owner_r2.protocol.attach_signed_visual_event(
            envelope,
            observation=observation,
            caption_present=True,
            signing_secret=fixture.signing_secret,
        )
        decision = owner_r2.runtime.evaluate_runtime_envelope(
            signed,
            config=fixture.config,
            signing_secret=fixture.signing_secret,
            identity_pepper=fixture.identity_pepper,
            now=fixture.now,
        )
        self.assertTrue(decision.hybrid_external_generation)
        self.assertEqual(decision.visual_event["caption_present"], True)
        self.assertEqual(decision.visual_event["observation"], observation)

        tampered = deepcopy(signed)
        tampered["routing"]["visual_event"]["observation"] = "tampered synthetic observation"
        with self.assertRaises(owner_r2.runtime.RuntimeRejected):
            owner_r2.runtime.evaluate_runtime_envelope(
                tampered,
                config=fixture.config,
                signing_secret=fixture.signing_secret,
                identity_pepper=fixture.identity_pepper,
                now=fixture.now,
            )

        selected = release_set()
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory, selected.release_set_id)
            auth = context(1)
            pending = store.begin_turn(
                auth,
                caption,
                EgressSafetySignals(classifier_available=True),
            )
            payload = store.context_payload(
                auth,
                pending,
                visual_event=decision.visual_event,
            )
            external = payload["external_context"]
            visual = external["visual_evidence"]
            self.assertEqual(payload["release_set_id"], selected.release_set_id)
            self.assertEqual(external["schema"], EXTERNAL_VISUAL_CONTEXT_SCHEMA)
            self.assertEqual(
                external["projection_policy_version"],
                EXTERNAL_VISUAL_PROJECTION_POLICY,
            )
            self.assertEqual(external["current_message"], caption)
            self.assertTrue(visual["caption_present"])
            self.assertEqual(visual["observation"], observation)
            store.cancel_pending(auth, pending)

    async def test_missing_or_failed_pre_gemini_readiness_never_calls_provider(self) -> None:
        fixture = owner_r2.TelegramOwnerRuntimeR2Tests()
        fixture.setUp()
        provider_context = p01b._DummyContext()

        async def unexpected_provider_call(*_args, **_kwargs):
            raise AssertionError("provider called before local readiness")

        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-photo.jpg"
            with (
                patch.object(
                    p01b.gateway,
                    "read_signing_secret",
                    return_value=fixture.signing_secret,
                ),
                patch.object(p01b.gateway, "_binding_matches", return_value=True),
                patch.object(
                    p01b.gateway,
                    "send_envelope",
                    return_value={
                        "kind": "visual_preflight_ready",
                        "schema": owner_r2.protocol.GATEWAY_RESPONSE_SCHEMA,
                    },
                ),
                patch.object(
                    p01b.gateway,
                    "send_media_shadow_envelope",
                    return_value=None,
                ),
                patch.object(
                    p01b.gateway,
                    "_bounded_google_genai_query",
                    new=unexpected_provider_call,
                ),
            ):
                plugin = p01b.gateway.Main(provider_context)
                try:
                    missing_event = p01b._DummyEvent(
                        "123456789",
                        [p01b._DummyImage(str(missing)), p01b._DummyPlain("synthetic caption")],
                    )
                    missing_reply = [
                        item async for item in plugin.intercept_telegram(missing_event)
                    ]
                    self.assertEqual(missing_reply, [p01b.gateway._VISION_FAILURE_REPLY])
                    self.assertFalse(missing_event.call_llm)
                    self.assertTrue(missing_event.stopped)

                    with patch.object(
                        p01b.gateway,
                        "_prepare_image_for_model",
                        side_effect=p01b.gateway.NativeVisionRejected(
                            "synthetic readiness failure"
                        ),
                    ):
                        failed_event = p01b._DummyEvent(
                            "123456789",
                            [p01b._DummyImage(str(missing)), p01b._DummyPlain("synthetic caption")],
                        )
                        failed_reply = [
                            item async for item in plugin.intercept_telegram(failed_event)
                        ]
                    self.assertEqual(failed_reply, [p01b.gateway._VISION_FAILURE_REPLY])
                    self.assertEqual(provider_context.provider.calls, [])
                finally:
                    await plugin.terminate()

    def test_successor_release_set_id_match_and_mismatch_fail_closed(self) -> None:
        selected = release_set()
        self.assertEqual(selected.selector["generation"], 13)
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory, selected.release_set_id)
            auth = context(1)
            pending = store.begin_turn(
                auth,
                "synthetic release-bound message",
                EgressSafetySignals(classifier_available=True),
            )
            payload = store.context_payload(auth, pending)
            self.assertEqual(payload["release_set_id"], selected.release_set_id)
            store.cancel_pending(auth, pending)

            with self.assertRaisesRegex(
                ExternalEpochV3Rejected,
                "state_identity_rejected",
            ):
                _store(directory, "b" * 64)

    def test_delivery_prepare_replays_cancel_and_crash_abandonment(self) -> None:
        selected = release_set()
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory, selected.release_set_id)

            first_token = _delivery_token("delivered", 1)
            first = _deliver(store, selected.release_set_id, 1)
            replay = store.resolve_delivery(
                delivery_token=first_token,
                outcome="delivered",
            )
            self.assertFalse(first.replayed)
            self.assertTrue(replay.replayed)
            self.assertEqual(replay.committed_revision, first.committed_revision)
            with self.assertRaisesRegex(
                ExternalEpochV3Rejected,
                "outcome_conflict",
            ):
                store.resolve_delivery(
                    delivery_token=first_token,
                    outcome="cancelled",
                )

            auth = context(2)
            pending = store.begin_turn(
                auth,
                "synthetic cancellable message",
                EgressSafetySignals(classifier_available=True),
            )
            cancelled_token = _delivery_token("cancelled", 2)
            store.prepare_delivery(
                auth,
                pending,
                delivery_token=cancelled_token,
                assistant_reply="synthetic cancelled reply",
                provenance=_provenance(
                    selected.release_set_id,
                    pending.base_revision,
                ),
            )
            cancelled = store.resolve_delivery(
                delivery_token=cancelled_token,
                outcome="cancelled",
            )
            cancelled_replay = store.resolve_delivery(
                delivery_token=cancelled_token,
                outcome="cancelled",
            )
            self.assertFalse(cancelled.replayed)
            self.assertTrue(cancelled_replay.replayed)
            self.assertIsNone(cancelled.committed_revision)
            with self.assertRaisesRegex(
                ExternalEpochV3Rejected,
                "outcome_conflict",
            ):
                store.resolve_delivery(
                    delivery_token=cancelled_token,
                    outcome="delivered",
                )

            auth = context(3)
            pending = store.begin_turn(
                auth,
                "synthetic crash-prepared message",
                EgressSafetySignals(classifier_available=True),
            )
            abandoned_token = _delivery_token("abandoned", 3)
            store.prepare_delivery(
                auth,
                pending,
                delivery_token=abandoned_token,
                assistant_reply="synthetic abandoned reply",
                provenance=_provenance(
                    selected.release_set_id,
                    pending.base_revision,
                ),
            )
            recovered = store.startup_recover()
            self.assertEqual(recovered.abandoned_deliveries, 1)
            self.assertEqual(store.public_metadata()["pending_count"], 0)
            with self.assertRaisesRegex(
                ExternalEpochV3Rejected,
                "outcome_conflict",
            ):
                store.resolve_delivery(
                    delivery_token=abandoned_token,
                    outcome="delivered",
                )

    def test_queued_summary_preserves_visual_projection_with_headroom(self) -> None:
        selected = release_set()
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory, selected.release_set_id)
            for index in range(1, 5):
                _deliver(store, selected.release_set_id, index)
            self.assertEqual(store.public_metadata()["queued_summary_count"], 1)

            auth = context(5)
            pending = store.begin_turn(
                auth,
                "synthetic trusted caption",
                EgressSafetySignals(classifier_available=True),
            )
            payload = store.context_payload(
                auth,
                pending,
                visual_event=_visual_event(),
            )
            external = payload["external_context"]
            visual = external["visual_evidence"]
            self.assertEqual(external["schema"], EXTERNAL_VISUAL_CONTEXT_SCHEMA)
            self.assertEqual(
                external["projection_policy_version"],
                EXTERNAL_VISUAL_PROJECTION_POLICY,
            )
            self.assertEqual(visual["observation"], "synthetic bounded observation")
            self.assertTrue(visual["caption_present"])
            self.assertEqual(store.public_metadata()["queued_summary_count"], 1)
            store.cancel_pending(auth, pending)

    def test_typed_hard_cap_backpressure_never_falls_through_to_legacy_context(self) -> None:
        selected = release_set()
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory, selected.release_set_id)
            for index in range(1, 8):
                _deliver(store, selected.release_set_id, index)
            auth = context(8)
            pending = store.begin_turn(
                auth,
                "synthetic hard-cap message",
                EgressSafetySignals(classifier_available=True),
            )
            with self.assertRaisesRegex(
                ExternalEpochV3Rejected,
                "external_summary_backpressure",
            ):
                store.context_payload(
                    auth,
                    pending,
                    visual_event=_visual_event(),
                )
            store.cancel_pending(auth, pending)


if __name__ == "__main__":
    unittest.main()
