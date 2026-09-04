"""Offline tests: attachment extraction, SHA-256, path-traversal guard."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from eml_forensics import attachments, parser

from fixtures.make_fixtures import PNG_1PX, build_corpus


class AttachmentsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        build_corpus(cls.dir)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_extract_with_hashes(self):
        raw = (self.dir / "01_kickoff.eml").read_bytes()
        message = parser.parse_bytes(raw)
        with tempfile.TemporaryDirectory() as out:
            manifest = attachments.extract_attachments(message, Path(out))
            names = {item["name"] for item in manifest}
            self.assertEqual(names, {"notes.txt", "plan.png"})
            by_name = {item["name"]: item for item in manifest}
            self.assertEqual(by_name["notes.txt"]["sha256"],
                             hashlib.sha256(b"alpha bravo charlie delta\n").hexdigest())
            self.assertEqual(by_name["plan.png"]["sha256"],
                             hashlib.sha256(PNG_1PX).hexdigest())
            for item in manifest:
                target = Path(out) / item["name"]
                self.assertTrue(target.is_file())
                self.assertEqual(attachments.sha256_file(target),
                                 item["sha256"])

    def test_traversal_filename_sanitized(self):
        raw = (self.dir / "08_traversal.eml").read_bytes()
        message = parser.parse_bytes(raw)
        with tempfile.TemporaryDirectory() as out:
            root = Path(out)
            manifest = attachments.extract_attachments(message, root)
            self.assertEqual(len(manifest), 1)
            self.assertEqual(manifest[0]["name"], "evil.txt")
            # nothing escaped the destination directory
            self.assertEqual(list(root.rglob("*.txt")), [root / "evil.txt"])

    def test_safe_filename_edges(self):
        self.assertEqual(attachments.safe_filename("../../etc/passwd"), "passwd")
        self.assertEqual(attachments.safe_filename("a\\b\\c.txt"), "c.txt")
        self.assertEqual(attachments.safe_filename("...."), "attachment_0")
        self.assertNotIn("/", attachments.safe_filename("..\\..\\x.txt"))
        self.assertNotIn("..", attachments.safe_filename("..\\..\\x.txt"))


if __name__ == "__main__":
    unittest.main()
