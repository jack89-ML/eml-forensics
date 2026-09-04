"""Offline tests: built-in pattern scanning (CF/IBAN checksums, cadastral
and notarial references) plus watchlist keywords."""

import unittest

from eml_forensics import scanner


class FiscalCodeTest(unittest.TestCase):
    def test_valid_code_with_checksum(self):
        code15 = "RSSMRA85M01H501"
        code = code15 + scanner.control_char(code15)
        self.assertEqual(len(code), 16)
        self.assertTrue(scanner.cf_valid(code))
        broken = code[:15] + ("X" if code[15] != "X" else "Y")
        self.assertFalse(scanner.cf_valid(broken))

    def test_reference_fiscal_code_matches_ministerial_standard(self):
        # Widely used reference sample: RSSMRA80A01H501U
        self.assertTrue(scanner.cf_valid("RSSMRA80A01H501U"))
        self.assertEqual(scanner.control_char("RSSMRA80A01H501"), "U")
        self.assertFalse(scanner.cf_valid("RSSMRA80A01H501X"))

    def test_malformed_rejected(self):
        self.assertFalse(scanner.cf_valid("12345"))
        self.assertFalse(scanner.cf_valid("RSSMRA85M01H501"))


class IbanTest(unittest.TestCase):
    def test_known_valid(self):
        self.assertTrue(scanner.iban_valid("GB82WEST12345698765432"))
        self.assertTrue(scanner.iban_valid("IT60X0542811101000000123456"))

    def test_invalid_rejected(self):
        self.assertFalse(scanner.iban_valid("IT60X0542811101000000123457"))
        self.assertFalse(scanner.iban_valid("GB82WEST1234569876543"))
        self.assertFalse(scanner.iban_valid("notaniban"))


class PatternScanTest(unittest.TestCase):
    def setUp(self):
        code15 = "RSSMRA85M01H501"
        self.cf = code15 + scanner.control_char(code15)
        self.text = (
            f"Buongiorno, codice fiscale {self.cf}. "
            "IBAN GB82WEST12345698765432 per il bonifico. "
            "Immobile in Foglio 24, particella 941, subalterno 5; "
            "fabbricato storico rep. 12345 raccolta 678 del notaio. "
            "Confermo che la pratica è urgente."
        )

    def test_scan_finds_all_builtin_kinds(self):
        hits = scanner.scan_text(self.text)
        kinds = {h["kind"] for h in hits}
        self.assertIn("codice_fiscale", kinds)
        self.assertIn("iban", kinds)
        self.assertIn("catastale", kinds)
        self.assertIn("notarile", kinds)

    def test_watchlist_keyword(self):
        hits = scanner.scan_text(self.text, watchlist=["urgente"])
        watch = [h for h in hits if h["kind"] == "watchlist"]
        self.assertEqual(len(watch), 1)
        self.assertEqual(watch[0]["value"], "urgente")

    def test_snippet_has_context(self):
        hits = scanner.scan_text(self.text)
        cf_hit = next(h for h in hits if h["kind"] == "codice_fiscale")
        self.assertIn(self.cf, cf_hit["snippet"])


class WatchlistLoaderTest(unittest.TestCase):
    def test_comments_and_blanks_skipped(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "words.txt"
            path.write_text("# commento\n\nurgente\nconferma\n", encoding="utf-8")
            words = scanner.load_watchlist(path)
            self.assertEqual(words, ["urgente", "conferma"])


if __name__ == "__main__":
    unittest.main()
