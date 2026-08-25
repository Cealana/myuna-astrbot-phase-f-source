from __future__ import annotations

import ast
from pathlib import Path
import unittest

from myuna_core.episodic_memory.diary_generation import DiaryCapacityReceipt

import p07_owner_private_memory_runtime_v1 as runtime
import p07_reflective_diary_worker_v1 as worker
import telegram_owner_runtime_gateway as gateway


def capacity(*, fit: bool) -> DiaryCapacityReceipt:
    return DiaryCapacityReceipt(
        request_characters=100,
        projection_characters=90,
        serialized_bytes=200,
        input_tokens=50,
        request_headroom=199_900,
        projection_headroom=198_910,
        serialized_headroom=1_197_896,
        token_headroom=999_182,
        limiting_oracle=None if fit else "request_characters",
        fit=fit,
    )


class ReflectiveDiaryWorkerRetirementTests(unittest.TestCase):
    def test_inactive_provider_result_value_contract_is_preserved(self) -> None:
        coverage = worker.DiaryProviderResult(
            status="coverage_incomplete",
            job_digest="1" * 64,
            capacity=capacity(fit=False),
            provider_called=False,
            candidate=None,
        )
        self.assertFalse(coverage.provider_called)
        self.assertIsNone(coverage.candidate)
        with self.assertRaisesRegex(ValueError, "coverage result rejected"):
            worker.DiaryProviderResult(
                status="coverage_incomplete",
                job_digest="1" * 64,
                capacity=capacity(fit=True),
                provider_called=True,
                candidate=None,
            )
        with self.assertRaisesRegex(ValueError, "completed result rejected"):
            worker.DiaryProviderResult(
                status="completed",
                job_digest="1" * 64,
                capacity=capacity(fit=True),
                provider_called=False,
                candidate=None,
            )

    def test_worker_queue_retry_and_thread_surface_is_retired(self) -> None:
        self.assertFalse(worker.REFLECTIVE_DIARY_WORKER_ACTIVE)
        self.assertEqual(
            worker.__all__,
            ["DiaryProviderResult", "REFLECTIVE_DIARY_WORKER_ACTIVE"],
        )
        for name in (
            "BackgroundDiaryWorker",
            "DiaryWorkerCycle",
            "DiaryWorkerPort",
        ):
            self.assertFalse(hasattr(worker, name))
        for name in (
            "acquire_diary_job",
            "begin_diary_job_attempt",
            "commit_diary_job",
            "record_diary_job_gap",
        ):
            self.assertFalse(hasattr(runtime.OwnerPrivateMemoryRuntime, name))

    def test_active_modules_have_no_worker_queue_or_retry_execution(self) -> None:
        sources = {
            "runtime": Path(runtime.__file__).read_text(encoding="utf-8"),
            "worker": Path(worker.__file__).read_text(encoding="utf-8"),
            "gateway": Path(gateway.__file__).read_text(encoding="utf-8"),
        }
        forbidden = (
            "BackgroundDiaryWorker",
            "DiaryWorkerCycle",
            "diary_job_events",
            "acquire_diary_job",
            "begin_diary_job_attempt",
            "commit_diary_job",
            "record_diary_job_gap",
            "threading.Thread",
        )
        for label, source in sources.items():
            with self.subTest(module=label):
                for token in forbidden:
                    self.assertNotIn(token, source)

    def test_provider_facing_method_is_inactive_and_has_no_production_caller(self) -> None:
        source = Path(gateway.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        definitions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "generate_reflective_diary"
        ]
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "generate_reflective_diary"
        ]
        self.assertEqual(len(definitions), 1)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
