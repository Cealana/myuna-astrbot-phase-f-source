from __future__ import annotations

from pathlib import Path
import unittest

import render_telegram_media_metadata_shadow_units_v1 as renderer


ROOT = Path(__file__).resolve().parents[1]
CORE = "a" * 64
AUTH = "b" * 64
WORKER = "c" * 64


class TelegramMediaMetadataShadowUnitRendererTests(unittest.TestCase):
    def test_all_units_bind_only_exact_content_addressed_roots(self) -> None:
        units = renderer.render_repository_units(
            ROOT,
            core_digest=CORE,
            auth_digest=AUTH,
            worker_digest=WORKER,
        )
        self.assertEqual(len(units), 4)
        flattened = "\n".join(content.decode("utf-8") for content in units.values())
        self.assertIn(f"/core/{CORE}/src", flattened)
        self.assertIn(f"/telegram-media-auth/releases/{AUTH}", flattened)
        self.assertIn(f"/telegram-media-metadata-shadow/releases/{WORKER}", flattened)
        self.assertNotIn("/srv/myuna/repos/", flattened)
        self.assertIsNone(renderer._UNRESOLVED.search(flattened))

    def test_evidence_names_only_inactive_install_targets_and_hashes(self) -> None:
        evidence = renderer.build_evidence(
            ROOT,
            core_digest=CORE,
            auth_digest=AUTH,
            worker_digest=WORKER,
        )
        self.assertEqual(evidence["schema"], renderer.SCHEMA)
        for name, unit in evidence["units"].items():
            self.assertEqual(unit["inactive_install_target"], f"/etc/systemd/system/{name}")
            self.assertEqual(len(unit["rendered_sha256"]), 64)

    def test_invalid_digest_or_mutable_path_is_rejected(self) -> None:
        with self.assertRaises(renderer.TelegramMediaShadowUnitRejected):
            renderer.render_repository_units(
                ROOT,
                core_digest="short",
                auth_digest=AUTH,
                worker_digest=WORKER,
            )
        template = (ROOT / "systemd/myuna-telegram-media-auth-shadow-v1.service").read_bytes().replace(
            b"@AUTH_RELEASE_ROOT@", b"/opt/myuna/telegram-media-auth/current"
        )
        with self.assertRaises(renderer.TelegramMediaShadowUnitRejected):
            renderer.render_unit(
                template,
                kind="auth_service",
                core_digest=CORE,
                auth_digest=AUTH,
                worker_digest=WORKER,
            )


if __name__ == "__main__":
    unittest.main()
