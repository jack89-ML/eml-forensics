"""Offline tests: parsing, markdown/body extraction, PEC headers, charsets."""

import tempfile
import unittest
from pathlib import Path

from eml_forensics import parser

from fixtures.make_fixtures import build_corpus


def _read_corpus():
    tmp = tempfile.TemporaryDirectory()
    build_corpus(Path(tmp.name))
    return tmp


class ParserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        cls.files = build_corpus(cls.dir)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _parse(self, name: str):
        raw = (self.dir / name).read_bytes()
        return parser.parse_message(raw, str(self.dir / name))

    def test_plain_metadata(self):
        message = self._parse("01_kickoff.eml")
        self.assertEqual(message.subject, "Project kickoff")
        self.assertEqual(message.from_addr[0]["email"], "alice@example.com")
        self.assertEqual(message.from_addr[0]["name"], "Alice")
        self.assertEqual(message.to[0]["email"], "bob@example.org")
        self.assertEqual(message.message_id, "kickoff@example.com")
        self.assertEqual(message.date, "2026-01-10T09:00:00+00:00")
        self.assertIn("kick off the project", message.body_text)
        self.assertFalse(message.body_from_html)

    def test_reply_headers(self):
        message = self._parse("02_reply1.eml")
        self.assertEqual(message.in_reply_to, "kickoff@example.com")
        self.assertEqual(message.references, ["kickoff@example.com"])

    def test_html_cleaned_no_tracking(self):
        message = self._parse("05_html.eml")
        self.assertTrue(message.body_from_html)
        self.assertIn("Please review the draft before Monday.", message.body_text)
        self.assertNotIn("<script", message.body_text)
        self.assertNotIn("alert", message.body_text)
        self.assertNotIn("pixel.gif", message.body_text)
        self.assertNotIn("track.example.net", message.body_text)

    def test_latin1_body(self):
        message = self._parse("07_latin1.eml")
        self.assertIn("rendiconto", message.body_text.lower())
        self.assertIn("è", message.body_text)

    def test_pec_headers(self):
        message = self._parse("06_pec.eml")
        self.assertEqual(message.pec.get("X-Riferimento-Message-ID"),
                         "original@pec.example")
        self.assertEqual(message.pec.get("X-TipoRicevuta"), "accettazione")

    def test_iter_eml_files(self):
        files = parser.iter_eml_files(self.dir)
        self.assertEqual(len(files), 8)


if __name__ == "__main__":
    unittest.main()
