"""Offline tests: OCR lexical scoring, best-angle selection, error paths."""

import unittest
from unittest import mock

from eml_forensics import ocr_grid
from eml_forensics.errors import ForensicsError, OptionalDependencyError


class ScoringTest(unittest.TestCase):
    def test_clean_text_beats_gibberish(self):
        clean = ("This is a perfectly normal sentence with several "
                 "readable words inside it.")
        garbage = "zzx qw2 !! %% 12345 ~~~~ ~~~ 444 ###"
        self.assertGreater(ocr_grid.score_text(clean),
                           ocr_grid.score_text(garbage))

    def test_rotated_gibberish_loses_to_text(self):
        self.assertGreater(ocr_grid.score_text("The quick brown fox jumps"),
                           ocr_grid.score_text("x~! 9 8 7 @@@ ~~"))

    def test_empty_scores_zero(self):
        self.assertEqual(ocr_grid.score_text(""), 0.0)


class AngleSelectionTest(unittest.TestCase):
    def test_best_angle_selected(self):
        class _FakeImage:
            def __init__(self, angle):
                self.angle = angle

            def rotate(self, angle, expand=True):
                return _FakeImage(angle)

        def fake_ocr(image, lang):  # only the 90° orientation is readable
            if image.angle == 90:
                return "This is the correctly oriented sentence."
            return "~~~ xxxx 9999 ~~~"

        fake = _FakeImage(0)
        angle, text = ocr_grid.choose_best_angle(fake_ocr, fake, "eng")
        self.assertEqual(angle, 90)
        self.assertIn("correctly oriented", text)

    def test_tesseract_failure_wrapped(self):
        class _FakeImage:
            def rotate(self, angle, expand=True):
                return self

        def broken_ocr(image, lang):
            raise RuntimeError("tesseract exploded")

        with self.assertRaises(ForensicsError):
            ocr_grid.choose_best_angle(broken_ocr, _FakeImage(), "eng")


class DependencyTest(unittest.TestCase):
    def test_missing_ocr_extra_raises_actionable_error(self):
        with mock.patch.object(
                ocr_grid, "_ocr_modules",
                side_effect=OptionalDependencyError("needs [ocr] extra")):
            with self.assertRaises(OptionalDependencyError):
                ocr_grid.ocr_file(__import__("pathlib").Path("x.png"))


if __name__ == "__main__":
    unittest.main()
