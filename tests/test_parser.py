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

    def test_attached_text_never_becomes_body(self):
        """A message whose only text/plain part is an attachment must not
        use the attachment text as its body."""
        import email.message
        message = email.message.EmailMessage()
        message["From"] = "Alice <alice@example.com>"
        message["To"] = "Bob <bob@example.org>"
        message["Subject"] = "Html body only"
        message["Message-ID"] = "<htmlbody@example.com>"
        message["Date"] = "Sat, 10 Jan 2026 09:00:00 +0000"
        message.set_content(
            "<html><body><p>The real body lives here.</p></body></html>",
            subtype="html")
        message.add_attachment(b"this is an attached document, not the body",
                               maintype="text", subtype="plain",
                               filename="notes.txt")
        parsed = parser.parse_message(message.as_bytes())
        self.assertTrue(parsed.body_from_html)
        self.assertIn("The real body lives here.", parsed.body_text)
        self.assertNotIn("attached document", parsed.body_text)

    def test_message_with_only_attached_text_has_empty_body(self):
        import email.message
        message = email.message.EmailMessage()
        message["From"] = "Alice <alice@example.com>"
        message["To"] = "Bob <bob@example.org>"
        message["Subject"] = "Only an attachment"
        message["Message-ID"] = "<onlyatt@example.com>"
        message["Date"] = "Sat, 10 Jan 2026 09:00:00 +0000"
        message.add_attachment(b"sole payload", maintype="text",
                               subtype="plain", filename="data.txt")
        parsed = parser.parse_message(message.as_bytes())
        self.assertEqual(parsed.body_text, "")


if __name__ == "__main__":
    unittest.main()


class AlternativeBodyTest(unittest.TestCase):
    """text/plain must win over text/html whatever the part order."""

    @staticmethod
    def _message(html_first: bool) -> bytes:
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = "alternative"
        msg["From"] = "alice@example.com"
        msg["To"] = "bob@example.org"
        if html_first:
            msg.set_content("<p>HTML BODY</p>", subtype="html")
            msg.add_alternative("PLAIN BODY", subtype="plain")
        else:
            msg.set_content("PLAIN BODY")
            msg.add_alternative("<p>HTML BODY</p>", subtype="html")
        return msg.as_bytes()

    def test_plain_wins_when_html_comes_first(self):
        parsed = parser.parse_message(self._message(html_first=True))
        self.assertIn("PLAIN BODY", parsed.body_text)
        self.assertNotIn("HTML BODY", parsed.body_text)
        self.assertFalse(parsed.body_from_html)

    def test_plain_wins_when_plain_comes_first(self):
        parsed = parser.parse_message(self._message(html_first=False))
        self.assertIn("PLAIN BODY", parsed.body_text)
        self.assertFalse(parsed.body_from_html)

    def test_html_is_used_when_there_is_no_plain_part(self):
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = "html only"
        msg["From"] = "alice@example.com"
        msg["To"] = "bob@example.org"
        msg.set_content("<p>ONLY HTML</p>", subtype="html")
        parsed = parser.parse_message(msg.as_bytes())
        self.assertIn("ONLY HTML", parsed.body_text)
        self.assertTrue(parsed.body_from_html)


class NestedMessageTest(unittest.TestCase):
    """Forwarded mail travels as an attached message/rfc822."""

    @staticmethod
    def _forwarded() -> bytes:
        from email.message import EmailMessage
        inner = EmailMessage()
        inner["Subject"] = "INNER SUBJECT"
        inner["From"] = "carol@example.com"
        inner["To"] = "dave@example.org"
        inner.set_content("inner body")
        outer = EmailMessage()
        outer["Subject"] = "OUTER"
        outer["From"] = "alice@example.com"
        outer["To"] = "bob@example.org"
        outer.set_content("outer body")
        outer.add_attachment(inner, filename="forwarded.eml")
        return outer.as_bytes()

    def test_nested_message_is_found(self):
        raw = self._forwarded()
        found = parser.nested_messages(parser.parse_bytes(raw))
        self.assertEqual(len(found), 1)
        label, nested_raw = found[0]
        self.assertIn("INNER SUBJECT", label)
        nested = parser.parse_message(nested_raw)
        self.assertIn("inner body", nested.body_text)

    def test_plain_message_has_no_nested_messages(self):
        raw = parser.parse_message.__doc__ is not None  # keep the import used
        self.assertEqual(parser.nested_messages(parser.parse_bytes(
            b"From: a@example.com\nTo: b@example.org\nSubject: s\n\nbody\n"
        )), [])
        self.assertTrue(raw)
