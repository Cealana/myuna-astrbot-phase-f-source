from __future__ import annotations

import unittest

from myuna_core.persona_modules import (
    DualReplyComposer,
    PersonaKind,
    PersonaOutputError,
    normalize_chryna_inner,
)


class PersonaModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.composer = DualReplyComposer()

    def test_direct_chryna_has_exactly_one_single_star_pair(self) -> None:
        reply = self.composer.compose_chryna("*Confirmed.*")
        self.assertEqual(reply.reply, "*Confirmed.*")
        self.assertEqual(reply.reply.count("*"), 2)
        self.assertEqual(reply.personas, (PersonaKind.CHRYNA,))

    def test_dual_reply_is_myuna_first_then_chryna_without_label(self) -> None:
        reply = self.composer.compose_dual("我觉得可以", "Confirmed")
        self.assertEqual(reply.reply, "我觉得可以\n*Confirmed*")
        self.assertEqual(
            reply.personas,
            (PersonaKind.MYUNA, PersonaKind.CHRYNA),
        )

    def test_chryna_rejects_double_stars_and_labels(self) -> None:
        for text in ("**Confirmed**", "Chryna: Confirmed"):
            with self.subTest(text=text):
                with self.assertRaises(PersonaOutputError):
                    normalize_chryna_inner(text)

    def test_chryna_structured_multiline_uses_one_outer_star_pair(self) -> None:
        reply = self.composer.compose_chryna("Status\n- Core: healthy\n- Memory: read-only")
        self.assertEqual(reply.reply.count("*"), 2)
        self.assertTrue(reply.reply.startswith("*Status\n"))
        self.assertTrue(reply.reply.endswith("read-only*"))

    def test_composer_does_not_fabricate_missing_persona(self) -> None:
        with self.assertRaises(PersonaOutputError):
            self.composer.compose_dual("Myuna answer", None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
