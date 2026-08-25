from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _load_runtime():
    path = SCRIPTS / "telegram_owner_runtime_gateway.py"
    spec = importlib.util.spec_from_file_location(
        "telegram_recovery_notice_runtime_test",
        path,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


runtime = _load_runtime()


class Connection:
    def __init__(self) -> None:
        self.responses: list[bytes] = []

    def sendall(self, payload: bytes) -> None:
        self.responses.append(payload)

    def decoded(self) -> dict[str, object]:
        return json.loads(self.responses[0])


class AllowLimiter:
    def allow(self, _principal_id, _now) -> bool:
        return True


class RejectLimiter:
    def allow(self, _principal_id, _now) -> bool:
        return False


class SequenceCore:
    def __init__(self, outcomes: list[str]) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    def chat(self, _messages, *, decision, external_context=None):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if outcome == "failure":
            raise runtime.CoreUnavailable(
                runtime.deterministic_core_unreachable_projection(),
                projection_source="gateway",
            )
        return runtime.CoreReply(
            reply=f"synthetic-reply-{self.calls}",
            actual_route="deepseek_default",
        )


def decision(index: int = 1):
    now = datetime.now(timezone.utc)
    return runtime.RuntimeDecision(
        event_id=f"evt-synthetic-{index}",
        channel_kind="astrbot_telegram",
        channel_instance="synthetic-owner",
        conversation_id="conv-synthetic",
        occurred_at=now,
        nonce_fingerprint=f"{index:x}".rjust(64, "a")[-64:],
        payload_sha256=f"{index:x}".rjust(64, "b")[-64:],
        trace_id=f"trace-synthetic-{index}",
        account_fingerprint="c" * 64,
        message_text=f"synthetic request {index}",
    )


def run_connection(
    *,
    core,
    store,
    inbound_decision,
    claim: bool = True,
    owner: bool = True,
    limiter=None,
) -> Connection:
    connection = Connection()
    with (
        mock.patch.object(runtime, "_read_request", return_value={}),
        mock.patch.object(
            runtime,
            "evaluate_runtime_envelope",
            return_value=inbound_decision,
        ),
        mock.patch.object(runtime, "claim_inbound", return_value=claim),
        mock.patch.object(
            runtime,
            "resolve_verified_owner",
            return_value=owner,
        ),
        mock.patch.object(runtime, "record_outcome", return_value=True),
    ):
        runtime.process_connection(
            connection,
            config=SimpleNamespace(principal_id="principal-synthetic"),
            signing_secret=b"x" * 32,
            identity_pepper=b"y" * 32,
            core=core,
            limiter=limiter or AllowLimiter(),
            history=runtime.ConversationHistory(8, 8000),
            recovery_store=store,
        )
    return connection


class TelegramRecoveryNoticeTests(unittest.TestCase):
    def store(self, temp: str):
        return runtime.RecoveryEpisodeStore(
            Path(temp) / "recovery.db",
            "scope-synthetic-owner-private",
        )

    def test_core_failure_then_success_emits_one_fixed_notice(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = self.store(temp)
            core = SequenceCore(["failure", "success", "success"])
            failed = run_connection(
                core=core,
                store=store,
                inbound_decision=decision(1),
            )
            failed_payload = failed.decoded()
            self.assertEqual(
                failed_payload,
                {
                    "code": "owner-runtime-unavailable",
                    "status": "rejected",
                },
            )
            flattened_failure = repr(failed_payload)
            self.assertNotIn("category", flattened_failure)
            self.assertNotIn("fingerprint", flattened_failure)
            active = store.snapshot()
            self.assertIsNotNone(active)
            assert active is not None
            self.assertEqual(active.state, "active")
            self.assertEqual(active.category, "core_or_gateway_failure")
            self.assertFalse(active.notice_claimed)

            recovered = run_connection(
                core=core,
                store=store,
                inbound_decision=decision(2),
            ).decoded()
            self.assertEqual(recovered["kind"], "accepted_reply")
            self.assertEqual(
                recovered["recovery_notice"],
                runtime.RECOVERY_NOTICE_TEXT,
            )
            self.assertEqual(
                set(recovered),
                {"kind", "recovery_notice", "reply", "schema"},
            )
            snapshot = store.snapshot()
            assert snapshot is not None
            self.assertEqual(snapshot.state, "recovered")
            self.assertTrue(snapshot.notice_claimed)

            later = run_connection(
                core=core,
                store=store,
                inbound_decision=decision(3),
            ).decoded()
            self.assertEqual(later["code"], "owner-runtime-reply")
            self.assertNotIn("recovery_notice", later)
            self.assertEqual(core.calls, 3)

    def test_replay_never_calls_core_or_consumes_active_episode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = self.store(temp)
            store.mark_active(
                runtime._episode_projection(
                    runtime.deterministic_core_unreachable_projection()
                ),
                now=datetime.now(timezone.utc),
            )
            core = SequenceCore(["success"])
            replay = run_connection(
                core=core,
                store=store,
                inbound_decision=decision(4),
                claim=False,
            ).decoded()
            self.assertEqual(
                replay,
                {
                    "kind": "duplicate_suppressed",
                    "schema": "myuna.gateway-response.v3",
                },
            )
            self.assertEqual(core.calls, 0)
            snapshot = store.snapshot()
            assert snapshot is not None
            self.assertEqual(snapshot.state, "active")
            self.assertFalse(snapshot.notice_claimed)

    def test_identity_rejection_and_rate_limit_never_open_episode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            identity_store = self.store(temp)
            core = SequenceCore(["failure"])
            result = run_connection(
                core=core,
                store=identity_store,
                inbound_decision=decision(5),
                owner=False,
            ).decoded()
            self.assertEqual(result["code"], "owner-runtime-rejected")
            self.assertEqual(core.calls, 0)
            self.assertIsNone(identity_store.snapshot())

        with tempfile.TemporaryDirectory() as temp:
            rate_store = self.store(temp)
            core = SequenceCore(["failure"])
            result = run_connection(
                core=core,
                store=rate_store,
                inbound_decision=decision(6),
                limiter=RejectLimiter(),
            ).decoded()
            self.assertEqual(result["code"], "owner-runtime-unavailable")
            self.assertEqual(core.calls, 0)
            self.assertIsNone(rate_store.snapshot())

    def test_scope_key_is_derived_without_raw_account_or_message(self) -> None:
        config = runtime.RuntimeConfig(
            channel_kind="astrbot_telegram",
            binding_id="binding-owner",
            principal_id="principal-owner",
            namespace_id="namespace-owner",
            finalization_digest="a" * 64,
            evidence_sha256="b" * 64,
            channel_instance="telegram-owner",
            core_host="127.0.0.1",
            core_port=18081,
            max_requests_per_ten_minutes=12,
            max_history_messages=128,
            max_history_characters=131072,
        )
        scope = runtime._recovery_scope_key(config)
        self.assertRegex(scope, r"^scope-[0-9a-f]{64}$")
        self.assertNotIn(config.binding_id, scope)
        self.assertNotIn(config.principal_id, scope)
        self.assertNotIn(config.namespace_id, scope)


if __name__ == "__main__":
    unittest.main()
