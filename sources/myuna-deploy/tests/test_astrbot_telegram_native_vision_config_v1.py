from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import configure_astrbot_telegram_native_vision_v1 as configurator


def sample_config() -> dict[str, object]:
    return {
        "platform_settings": {
            "enable_id_white_list": True,
            "id_whitelist": [],
            "id_whitelist_log": True,
            "wl_ignore_admin_on_friend": True,
        },
        "provider_sources": [],
        "provider": [],
        "admins_id": [],
        "platform": [{"id": "telegram-only", "type": "telegram"}],
        "unrelated": {"preserve": [1, 2, 3]},
    }


def encode(document: dict[str, object]) -> bytes:
    return configurator.UTF8_BOM + json.dumps(
        document,
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8") + b"\n"


class AstrBotTelegramNativeVisionConfigTests(unittest.TestCase):
    def test_mutation_preserves_bom_and_changes_provider_and_source_only(self) -> None:
        before = sample_config()
        mutated = configurator.mutate_bytes(encode(before))
        self.assertTrue(mutated.startswith(configurator.UTF8_BOM))
        after = json.loads(mutated.decode("utf-8-sig"))
        expected = copy.deepcopy(before)
        expected["provider"].append(configurator.provider_entry())
        expected["provider_sources"].append(configurator.provider_source_entry())
        self.assertEqual(after, expected)
        self.assertEqual(
            after["provider_sources"][0]["key"],
            ["$MYUNA_TELEGRAM_GEMINI_API_KEY"],
        )
        self.assertEqual(after["provider"][0]["model"], "gemini-3.6-flash")
        self.assertEqual(
            after["provider_sources"][0]["gm_thinking_config"]["budget"], 0
        )
        self.assertEqual(
            after["provider_sources"][0]["gm_thinking_config"]["level"],
            "MINIMAL",
        )
        self.assertEqual(
            after["provider"][0]["provider_source_id"],
            configurator.PROVIDER_SOURCE_ID,
        )

    def test_missing_bom_duplicate_provider_and_env_reference_are_rejected(self) -> None:
        with self.assertRaises(configurator.NativeVisionConfigRejected):
            configurator.mutate_bytes(encode(sample_config())[3:])
        duplicate = sample_config()
        duplicate["provider"].append(configurator.provider_entry())
        with self.assertRaises(configurator.NativeVisionConfigRejected):
            configurator.mutate_bytes(encode(duplicate))
        duplicate_source = sample_config()
        duplicate_source["provider_sources"].append(
            configurator.provider_source_entry()
        )
        with self.assertRaises(configurator.NativeVisionConfigRejected):
            configurator.mutate_bytes(encode(duplicate_source))
        referenced = sample_config()
        referenced["unrelated"] = "$MYUNA_TELEGRAM_GEMINI_API_KEY"
        with self.assertRaises(configurator.NativeVisionConfigRejected):
            configurator.mutate_bytes(encode(referenced))

    def test_known_legacy_provider_pair_is_replaced_in_place(self) -> None:
        before = sample_config()
        before["provider"] = [
            {"id": "unrelated-provider"},
            configurator.legacy_provider_entry(),
        ]
        before["provider_sources"] = [
            {"id": "unrelated-source"},
            configurator.legacy_provider_source_entry(),
        ]
        after = configurator.decode_config(configurator.mutate_bytes(encode(before)))
        self.assertEqual(after["provider"][0], {"id": "unrelated-provider"})
        self.assertEqual(after["provider"][1], configurator.provider_entry())
        self.assertEqual(after["provider_sources"][0], {"id": "unrelated-source"})
        self.assertEqual(
            after["provider_sources"][1],
            configurator.provider_source_entry(),
        )

        drifted = copy.deepcopy(before)
        drifted["provider"][1]["model"] = "unexpected-model"
        with self.assertRaises(configurator.NativeVisionConfigRejected):
            configurator.mutate_bytes(encode(drifted))

    def test_exactly_one_telegram_platform_is_required(self) -> None:
        for platforms in ([], [{"type": "telegram"}, {"type": "telegram"}]):
            document = sample_config()
            document["platform"] = platforms
            with self.assertRaises(configurator.NativeVisionConfigRejected):
                configurator.mutate_bytes(encode(document))

    def test_atomic_configuration_preserves_metadata_and_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "cmd_config.json"
            config.write_bytes(encode(sample_config()))
            config.chmod(0o600)
            before = config.stat()
            result = configurator.configure(config)
            after = config.stat()
            self.assertEqual(
                result,
                {
                    "bom_preserved": True,
                    "provider_added": True,
                    "provider_source_added": True,
                    "semantic_diff_provider_and_source_only": True,
                },
            )
            self.assertEqual(after.st_mode & 0o777, 0o600)
            self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
            parsed = configurator.decode_config(config.read_bytes())
            self.assertEqual(parsed["provider"], [configurator.provider_entry()])
            self.assertEqual(
                parsed["provider_sources"],
                [configurator.provider_source_entry()],
            )

            target = root / "target.json"
            target.write_bytes(encode(sample_config()))
            target.chmod(0o600)
            link = root / "link.json"
            os.symlink(target, link)
            with self.assertRaises(configurator.NativeVisionConfigRejected):
                configurator.configure(link)


if __name__ == "__main__":
    unittest.main()
