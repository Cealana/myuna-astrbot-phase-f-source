from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import render_telegram_systemd_units_r4 as renderer


CORE_DIGEST = "c" * 64
GATEWAY_DIGEST = "d" * 64
CORE_ROOT = f"/srv/myuna/releases/core/{CORE_DIGEST}"
GATEWAY_ROOT = f"/opt/myuna/telegram-gateway/releases/{GATEWAY_DIGEST}"


class TelegramSystemdUnitsR4Tests(unittest.TestCase):
    def test_repository_templates_render_to_exact_release_roots(self) -> None:
        rendered = renderer.render_repository_units(
            ROOT,
            core_release_digest=CORE_DIGEST,
            gateway_release_digest=GATEWAY_DIGEST,
        )
        self.assertEqual(
            set(rendered),
            {
                "myuna-telegram-owner-runtime-dev.service",
                "myuna-telegram-owner-challenge-dev.service",
                "myuna-telegram-owner-runtime-dev.socket",
                "myuna-telegram-owner-challenge-dev.socket",
            },
        )
        for filename, payload in rendered.items():
            text = payload.decode("utf-8")
            self.assertNotIn("@CORE_RELEASE_ROOT@", text)
            self.assertNotIn("@GATEWAY_RELEASE_ROOT@", text)
            self.assertNotIn("/usr/local/libexec/myuna-telegram-gateway", text)
            self.assertNotIn("/usr/local/lib/myuna-telegram-gateway", text)
            self.assertNotIn("/srv/myuna/repos/", text)
            self.assertIn(f"Documentation=file:{GATEWAY_ROOT}/docs/", text)
            if filename.endswith(".service"):
                self.assertIn(
                    f"Environment=PYTHONPATH={CORE_ROOT}/src:",
                    text,
                )
            else:
                self.assertNotIn("Environment=PYTHONPATH=", text)

        runtime = rendered[
            "myuna-telegram-owner-runtime-dev.service"
        ].decode("utf-8")
        self.assertIn(
            f"ExecStart=/usr/bin/python3 {GATEWAY_ROOT}/scripts/"
            "telegram_owner_runtime_gateway.py",
            runtime,
        )
        challenge = rendered[
            "myuna-telegram-owner-challenge-dev.service"
        ].decode("utf-8")
        self.assertIn(
            f"ExecStart=/usr/bin/python3 {GATEWAY_ROOT}/scripts/"
            "telegram_owner_challenge_gateway.py",
            challenge,
        )
        runtime_socket = rendered[
            "myuna-telegram-owner-runtime-dev.socket"
        ].decode("utf-8")
        self.assertIn(
            "ListenStream=/run/myuna-telegram-gateway/owner.sock",
            runtime_socket,
        )
        self.assertNotIn("ExecStart=", runtime_socket)
        self.assertNotIn("Environment=PYTHONPATH=", runtime_socket)
        challenge_socket = rendered[
            "myuna-telegram-owner-challenge-dev.socket"
        ].decode("utf-8")
        self.assertIn(
            "ListenStream=/run/myuna-telegram-gateway/challenge.sock",
            challenge_socket,
        )

    def test_rendering_evidence_is_stable_and_install_bound(self) -> None:
        first = renderer.build_rendered_unit_evidence(
            ROOT,
            core_release_digest=CORE_DIGEST,
            gateway_release_digest=GATEWAY_DIGEST,
        )
        second = renderer.build_rendered_unit_evidence(
            ROOT,
            core_release_digest=CORE_DIGEST,
            gateway_release_digest=GATEWAY_DIGEST,
        )
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], renderer.SCHEMA)
        for filename, unit in first["units"].items():
            self.assertEqual(
                unit["inactive_install_target"],
                f"/etc/systemd/system/{filename}",
            )
            self.assertEqual(len(unit["template_sha256"]), 64)
            self.assertEqual(len(unit["rendered_sha256"]), 64)

    def test_invalid_digest_fails_closed(self) -> None:
        with self.assertRaises(renderer.TelegramUnitRenderRejected):
            renderer.render_repository_units(
                ROOT,
                core_release_digest="short",
                gateway_release_digest=GATEWAY_DIGEST,
            )

    def test_missing_or_duplicate_placeholders_fail_closed(self) -> None:
        template = (
            "[Unit]\n"
            "Documentation=file:@GATEWAY_RELEASE_ROOT@/docs/a.md\n"
            "[Service]\n"
            "ExecStart=/usr/bin/python3 "
            "@GATEWAY_RELEASE_ROOT@/scripts/telegram_owner_runtime_gateway.py\n"
            "Environment=PYTHONPATH=@CORE_RELEASE_ROOT@/src:"
            "@GATEWAY_RELEASE_ROOT@/scripts\n"
        ).encode("utf-8")
        with self.assertRaises(renderer.TelegramUnitRenderRejected):
            renderer.render_service_unit(
                template.replace(b"@CORE_RELEASE_ROOT@", b"/tmp/core"),
                kind="runtime",
                core_release_digest=CORE_DIGEST,
                gateway_release_digest=GATEWAY_DIGEST,
            )
        with self.assertRaises(renderer.TelegramUnitRenderRejected):
            renderer.render_service_unit(
                template
                + b"Environment=EXTRA=@GATEWAY_RELEASE_ROOT@\n",
                kind="runtime",
                core_release_digest=CORE_DIGEST,
                gateway_release_digest=GATEWAY_DIGEST,
            )

    def test_mutable_path_and_alias_fail_closed(self) -> None:
        template = (
            "[Unit]\n"
            "Documentation=file:@GATEWAY_RELEASE_ROOT@/docs/a.md\n"
            "[Service]\n"
            "ExecStart=/usr/bin/python3 "
            "@GATEWAY_RELEASE_ROOT@/scripts/telegram_owner_runtime_gateway.py\n"
            "Environment=PYTHONPATH=@CORE_RELEASE_ROOT@/src:"
            "@GATEWAY_RELEASE_ROOT@/scripts\n"
        ).encode("utf-8")
        for mutation in (
            b"ReadOnlyPaths=/srv/myuna/repos/deploy\n",
            b"ReadOnlyPaths=/opt/example/current/tree\n",
            b"ReadOnlyPaths=/opt/example/current\n",
            b"ReadOnlyPaths=/opt/example/latest/tree\n",
            b"ReadOnlyPaths=/opt/example/latest\n",
        ):
            with self.assertRaises(renderer.TelegramUnitRenderRejected):
                renderer.render_service_unit(
                    template + mutation,
                    kind="runtime",
                    core_release_digest=CORE_DIGEST,
                    gateway_release_digest=GATEWAY_DIGEST,
                )

    def test_extra_execstart_fails_closed(self) -> None:
        template = (
            "[Unit]\n"
            "Documentation=file:@GATEWAY_RELEASE_ROOT@/docs/a.md\n"
            "[Service]\n"
            "ExecStart=/usr/bin/python3 "
            "@GATEWAY_RELEASE_ROOT@/scripts/telegram_owner_runtime_gateway.py\n"
            "ExecStart=/bin/false\n"
            "Environment=PYTHONPATH=@CORE_RELEASE_ROOT@/src:"
            "@GATEWAY_RELEASE_ROOT@/scripts\n"
        ).encode("utf-8")
        with self.assertRaises(renderer.TelegramUnitRenderRejected):
            renderer.render_service_unit(
                template,
                kind="runtime",
                core_release_digest=CORE_DIGEST,
                gateway_release_digest=GATEWAY_DIGEST,
            )


if __name__ == "__main__":
    unittest.main()
