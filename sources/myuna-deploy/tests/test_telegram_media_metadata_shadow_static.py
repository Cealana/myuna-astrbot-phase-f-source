from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "channels/astrbot-telegram/plugin/myuna_telegram_gateway/main.py"
COMPOSE = ROOT / "channels/astrbot-telegram/compose.dev.yml"
AUTH_GATEWAY = ROOT / "scripts/telegram_media_metadata_shadow_gateway.py"
WORKER = ROOT / "components/telegram-media-metadata-shadow/telegram_media_metadata_shadow/worker.py"
ADR = ROOT / "docs/ADR-049-telegram-media-metadata-shadow-v1.md"
UNITS = tuple(
    ROOT / "systemd" / name
    for name in (
        "myuna-telegram-media-auth-shadow-v1.socket",
        "myuna-telegram-media-auth-shadow-v1.service",
        "myuna-telegram-media-metadata-shadow-v1.socket",
        "myuna-telegram-media-metadata-shadow-v1.service",
    )
)


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


_RAW_MEDIA_FIELDS = frozenset({"file", "file_id", "path", "url"})


def _raw_media_field_accesses(node: ast.AST) -> set[str]:
    attributes = {
        candidate.attr
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Attribute)
    }
    dynamic_names = {
        candidate.value
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str)
    }
    return (attributes | dynamic_names) & _RAW_MEDIA_FIELDS


class TelegramMediaMetadataShadowStaticTests(unittest.TestCase):
    def test_media_shadow_branch_uses_astrimage_and_never_resolves_media(self) -> None:
        tree = ast.parse(MAIN.read_text(encoding="utf-8"))
        image_aliases = [
            alias
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            and node.module == "astrbot.api.message_components"
            for alias in node.names
            if alias.name == "Image"
        ]
        self.assertEqual(len(image_aliases), 1)
        self.assertEqual(image_aliases[0].asname, "AstrImage")

        intercept = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "intercept_telegram"
        )
        shadow_guards = [
            node
            for node in ast.walk(intercept)
            if isinstance(node, ast.If)
            and any(
                isinstance(candidate, ast.Call)
                and _call_name(candidate.func)
                == "should_observe_private_image_shape"
                for candidate in ast.walk(node.test)
            )
        ]
        self.assertEqual(len(shadow_guards), 1)
        shadow_branch = ast.Module(body=shadow_guards[0].body, type_ignores=[])

        calls = [node for node in ast.walk(shadow_branch) if isinstance(node, ast.Call)]
        call_names = [_call_name(node.func) for node in calls]
        self.assertEqual(call_names.count("build_signed_media_shadow_envelope"), 1)
        self.assertEqual(call_names.count("send_media_shadow_envelope"), 1)
        for forbidden in {
            "_bounded_google_genai_query",
            "_local_image_path",
            "_prepare_image_for_model",
            "convert_to_file_path",
            "convert_to_base64",
            "open",
            "read_bytes",
        }:
            self.assertNotIn(forbidden, call_names)

        self.assertEqual(_raw_media_field_accesses(shadow_branch), set())

        envelope_calls = [
            node
            for node in ast.walk(intercept)
            if isinstance(node, ast.Call)
            if _call_name(node.func) == "build_signed_media_shadow_envelope"
        ]
        self.assertEqual(len(envelope_calls), 2)
        for envelope_call in envelope_calls:
            self.assertEqual(
                {keyword.arg for keyword in envelope_call.keywords},
                {
                    "caption_present",
                    "channel_instance",
                    "image_count",
                    "message_id",
                    "raw_timestamp",
                    "sender_id",
                    "signing_secret",
                },
            )
            self.assertNotIn(
                "image",
                {node.id for node in ast.walk(envelope_call) if isinstance(node, ast.Name)},
            )

    def test_ast_oracle_distinguishes_fileno_from_raw_media_access(self) -> None:
        safe = ast.parse("stream.fileno()")
        unsafe = ast.parse(
            "image.file\n"
            "getattr(image, 'path', None)\n"
            "getattr(image, 'url', None)\n"
        )
        self.assertEqual(_raw_media_field_accesses(safe), set())
        self.assertEqual(
            _raw_media_field_accesses(unsafe),
            {"file", "path", "url"},
        )

    def test_compose_mounts_only_dedicated_auth_runtime(self) -> None:
        text = COMPOSE.read_text(encoding="utf-8")
        self.assertIn("MYUNA_MEDIA_SHADOW_SOCKET", text)
        self.assertIn("CHANNEL_MEDIA_AUTH_RUNTIME_ROOT", text)
        self.assertNotIn("telegram-media-metadata-shadow", text)

    def test_two_stage_units_are_marker_gated_and_inactive_templates(self) -> None:
        flattened = "\n".join(path.read_text(encoding="utf-8") for path in UNITS)
        self.assertIn("owner-media-metadata-shadow-v1-enabled", flattened)
        self.assertIn("telegram-media-metadata-shadow-v1-enabled", flattened)
        self.assertIn("User=myuna-gateway-telegram", flattened)
        self.assertIn("User=myuna-telegram-media-shadow", flattened)
        self.assertIn("SocketMode=0600", flattened)
        self.assertIn("SocketMode=0620", flattened)
        self.assertIn("IPAddressDeny=any", flattened)
        self.assertNotIn("WantedBy=multi-user.target", flattened)

    def test_worker_has_no_provider_memory_tool_or_decoder_dependency(self) -> None:
        flattened = (AUTH_GATEWAY.read_text(encoding="utf-8") + WORKER.read_text(encoding="utf-8")).casefold()
        for forbidden in (
            "deepseek",
            "openai",
            "pillow",
            "image.open",
            "memory_candidate",
            "tool_call",
            "httpconnection",
            "api.telegram.org",
        ):
            self.assertNotIn(forbidden, flattened)

    def test_adr_states_repository_only_and_all_forbidden_effects(self) -> None:
        text = " ".join(ADR.read_text(encoding="utf-8").split())
        for required in (
            "repository-only / inactive / not installed",
            "never receives Telegram User ID",
            "does not access `Image.file`",
            "already installed decoder remains disabled",
            "visible reply",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
