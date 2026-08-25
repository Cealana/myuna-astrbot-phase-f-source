from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest

from myuna_core.owner_profile.contracts import OwnerProfileError
from myuna_core.owner_profile.write_candidate import (
    MAX_SOURCE_CHARACTERS as CANDIDATE_MAX_SOURCE_CHARACTERS,
    OwnerProfileCandidateError as CandidateExportedError,
)
from myuna_core.owner_profile.write_intent import (
    MAX_SOURCE_CHARACTERS,
    OwnerProfileCandidateError,
    benchmark_intent_grants_profile_consent,
    parse_benchmark_write_intent,
    parse_profile_v2_structural_request,
)


class BenchmarkWriteIntentTests(unittest.TestCase):
    def test_intent_seam_imports_without_candidate_or_provider_modules(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "src"
        program = (
            "import importlib.abc,sys\n"
            "class Block(importlib.abc.MetaPathFinder):\n"
            " def find_spec(self, fullname, path=None, target=None):\n"
            "  if fullname == 'myuna_core.owner_profile.write_candidate' or "
            "fullname == 'myuna_core.providers' or fullname.startswith('myuna_core.providers.'):\n"
            "   raise ImportError('blocked')\n"
            "  return None\n"
            "sys.meta_path.insert(0, Block())\n"
            "from myuna_core.owner_profile.write_intent import "
            "MAX_SOURCE_CHARACTERS,OwnerProfileCandidateError,"
            "parse_benchmark_write_intent,parse_profile_v2_structural_request\n"
            "assert MAX_SOURCE_CHARACTERS == 3500\n"
            "assert parse_benchmark_write_intent('/Benchmark synthetic').source_text == 'synthetic'\n"
            "assert parse_profile_v2_structural_request('冻结亲密度') == {'action':'freeze'}\n"
            "assert 'myuna_core.owner_profile.write_candidate' not in sys.modules\n"
            "assert not any(name == 'myuna_core.providers' or name.startswith('myuna_core.providers.') for name in sys.modules)\n"
        )
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONHASHSEED": os.environ.get("PYTHONHASHSEED", "0"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(source_root),
        }
        completed = subprocess.run(
            [sys.executable, "-B", "-c", program],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_candidate_reexports_exact_intent_objects(self) -> None:
        self.assertIs(CandidateExportedError, OwnerProfileCandidateError)
        self.assertIs(CANDIDATE_MAX_SOURCE_CHARACTERS, MAX_SOURCE_CHARACTERS)
        self.assertEqual(MAX_SOURCE_CHARACTERS, 3_500)

    def test_ordinary_chat_has_no_write_intent(self) -> None:
        self.assertIsNone(parse_benchmark_write_intent("hello"))
        self.assertFalse(benchmark_intent_grants_profile_consent("hello"))
        self.assertIsNone(parse_benchmark_write_intent("/Diary archived control"))

    def test_proposal_keeps_exact_supplied_text(self) -> None:
        intent = parse_benchmark_write_intent("/Benchmark 我长期喜欢研究合成电子设备。")
        assert intent is not None
        self.assertEqual(intent.action, "propose")
        self.assertEqual(intent.source_text, "我长期喜欢研究合成电子设备。")

    def test_confirm_and_cancel_codes_are_normalized(self) -> None:
        confirm = parse_benchmark_write_intent("/benchmark confirm abcdef123456")
        cancel = parse_benchmark_write_intent("/Benchmark cancel abcdef123456")
        assert confirm is not None and cancel is not None
        self.assertEqual(confirm.confirmation_code, "ABCDEF123456")
        self.assertEqual(cancel.confirmation_code, "ABCDEF123456")

    def test_malformed_control_intent_fails_closed(self) -> None:
        for text in (
            "/Benchmark",
            "/Benchmark confirm",
            "/Benchmark confirm not-a-code",
        ):
            with self.subTest(text=text):
                with self.assertRaisesRegex(
                    OwnerProfileCandidateError, "candidate_intent_rejected"
                ):
                    parse_benchmark_write_intent(text)
                self.assertFalse(benchmark_intent_grants_profile_consent(text))

    def test_profile_v2_structural_grammar_is_finite_and_scaled(self) -> None:
        self.assertEqual(
            parse_profile_v2_structural_request("将亲密度设为 12.5"),
            {"action": "propose_manifest", "requested_value": 125_000},
        )
        self.assertEqual(
            parse_profile_v2_structural_request("将亲密度修正为 12.5"),
            {"action": "correct", "requested_value": 125_000},
        )
        self.assertEqual(
            parse_profile_v2_structural_request("确认亲密度提案 proposal-1 v2"),
            {
                "action": "confirm_manifest",
                "proposal_id": "proposal-1",
                "proposal_version": 2,
            },
        )
        self.assertEqual(
            parse_profile_v2_structural_request("冻结亲密度"),
            {"action": "freeze"},
        )
        self.assertEqual(
            parse_profile_v2_structural_request("将亲密度回滚到 1.25"),
            {"action": "rollback", "requested_value": 12_500},
        )
        for ordinary in ("帮我决定晚饭", "亲密度是什么", "/Benchmark old route"):
            self.assertIsNone(parse_profile_v2_structural_request(ordinary))
        for malformed in (
            "确认亲密度提案 proposal-1",
            "确认亲密度提案 proposal-1 v0",
            "确认亲密度提案 proposal-1 v2 以及 proposal-2 v3",
            "取消亲密度提案 proposal-1",
            "冻结亲密度并清空历史",
            "将亲密度设为 151",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(
                OwnerProfileError
            ):
                parse_profile_v2_structural_request(malformed)


if __name__ == "__main__":
    unittest.main()
