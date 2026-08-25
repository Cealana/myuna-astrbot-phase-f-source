from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myuna_core.evaluation.golden import (
    GoldenEvaluationError,
    assemble_system_prompt,
    capability_violations,
    evaluate_reply,
    load_approved_cases,
    parse_model_reply,
)


class GoldenEvaluationTests(unittest.TestCase):
    def test_approval_is_bound_to_the_exact_case_file(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases_path = root / "cases.jsonl"
            case = {
                "id": "identity_case",
                "prompt": {"messages": [{"role": "user", "content": "你是谁？"}]},
                "assertions": {"manual_review": ["truthful"]},
                "source_refs": ["SKILL.md"],
            }
            cases_path.write_text(json.dumps(case, ensure_ascii=False) + "\n", encoding="utf-8")
            digest = sha256(cases_path.read_bytes()).hexdigest().upper()
            approval_path = root / "approval.json"
            approval_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scope": "golden-test-contract-only",
                        "approved": True,
                        "cases_sha256": digest,
                        "approved_case_ids": ["identity_case"],
                        "release_activation_authorized": False,
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(len(load_approved_cases(cases_path, approval_path)), 1)
            cases_path.write_text(cases_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaises(GoldenEvaluationError):
                load_approved_cases(cases_path, approval_path)

    def test_context_loads_runtime_refs_but_rejects_raw_source(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            definition = root / "runtime-build/definition"
            (definition / "references").mkdir(parents=True)
            (definition / "SKILL.md").write_text("runtime core", encoding="utf-8")
            (definition / "references/00-overview.md").write_text("overview", encoding="utf-8")
            (definition / "references/02-voice.md").write_text("voice", encoding="utf-8")
            case = {
                "prompt": {"mode": "myuna"},
                "source_refs": ["references/02-voice.md#identity"],
            }
            prompt = assemble_system_prompt(root, case)
            self.assertIn("runtime core", prompt)
            self.assertIn("voice", prompt)
            self.assertIn("long-term memory is not active", prompt)
            self.assertIn("requested interface mode for this case is myuna", prompt)
            self.assertLess(prompt.index("voice"), prompt.index("End of Definition documents"))
            self.assertIn("Quoted dialogue and examples", prompt)

            case["source_refs"] = ["references/raw-source/private.txt"]
            with self.assertRaises(GoldenEvaluationError):
                assemble_system_prompt(root, case)

    def test_workbench_prompt_requires_targeted_precedence_confirmation(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            definition = root / "runtime-build/definition"
            (definition / "references").mkdir(parents=True)
            (definition / "SKILL.md").write_text("runtime core", encoding="utf-8")
            (definition / "references/00-overview.md").write_text(
                "overview", encoding="utf-8"
            )
            case = {"prompt": {"mode": "workbench"}, "source_refs": []}
            prompt = assemble_system_prompt(root, case)
            self.assertIn("ask exactly one targeted question", prompt)
            self.assertIn("old and new alone are not authorization", prompt)

    def test_category_controls_make_staging_judgments_explicit(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            definition = root / "runtime-build/definition"
            (definition / "references").mkdir(parents=True)
            (definition / "SKILL.md").write_text("runtime core", encoding="utf-8")
            (definition / "references/00-overview.md").write_text(
                "overview", encoding="utf-8"
            )
            checklist = {
                "category": "checklist",
                "prompt": {"mode": "checklist"},
                "source_refs": [],
            }
            memory = {
                "category": "memory_honesty",
                "prompt": {"mode": "myuna"},
                "source_refs": [],
            }
            relationship = {
                "category": "relationship_pacing",
                "prompt": {"mode": "myuna"},
                "source_refs": [],
            }
            self.assertIn(
                "exactly one smallest immediate physical action",
                assemble_system_prompt(root, checklist),
            )
            self.assertIn(
                "there is no available record",
                assemble_system_prompt(root, memory),
            )
            self.assertIn(
                "Do not repeat the requested pet name",
                assemble_system_prompt(root, relationship),
            )

    def test_reply_contract_and_automatic_assertions(self) -> None:
        reply = parse_model_reply('{"reply":"我是 Cealana 的助手，Myuna"}')
        case = {
            "assertions": {
                "must_include_any": ["Myuna", "助手"],
                "must_not_include": ["我能看到你的房间"],
                "max_chars": 80,
                "manual_review": ["brief identity"],
            }
        }
        result = evaluate_reply(case, reply)
        self.assertTrue(result["auto_pass"])
        self.assertEqual(result["manual_status"], "pending")
        with self.assertRaises(GoldenEvaluationError):
            parse_model_reply('{"reply":"ok","analysis":"hidden"}')

    def test_terminal_full_stop_assertion_is_deterministic(self) -> None:
        case = {
            "assertions": {
                "forbid_terminal_full_stop": True,
                "manual_review": ["chat-style final punctuation"],
            }
        }
        self.assertFalse(evaluate_reply(case, "通道正常。")["auto_pass"])
        self.assertFalse(evaluate_reply(case, "Channel ready.")["auto_pass"])
        self.assertTrue(evaluate_reply(case, "通道正常")["auto_pass"])
        self.assertTrue(evaluate_reply(case, "真的接通了吗？")["auto_pass"])
        self.assertTrue(evaluate_reply(case, "唔……")["auto_pass"])
        self.assertTrue(evaluate_reply(case, "hmm...")["auto_pass"])

    def test_capability_guard_distinguishes_claims_from_honest_absence(self) -> None:
        self.assertEqual(capability_violations("我可以记着，你以后再问我"), ["memory_write_claim"])
        self.assertEqual(capability_violations("平时可以帮他记住一些事情"), ["memory_write_claim"])
        self.assertEqual(capability_violations("你再说一次的话，我会好好记住的"), ["memory_write_claim"])
        self.assertEqual(capability_violations("不记得了，记忆系统还没启用"), [])
        self.assertEqual(capability_violations("我现在看不到你的房间"), [])


if __name__ == "__main__":
    unittest.main()
