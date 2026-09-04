"""Offline tests: thread reconstruction, latencies, blackouts."""

import tempfile
import unittest
from pathlib import Path

from eml_forensics.metrics import ThreadMessage, build_threads, normalize_subject
from eml_forensics import parser

from fixtures.make_fixtures import build_corpus


def _messages_from(dir_path: Path):
    messages = []
    for path in parser.iter_eml_files(dir_path):
        parsed = parser.parse_message(path.read_bytes(), str(path))
        messages.append(ThreadMessage(
            message_id=parsed.message_id,
            subject=parsed.subject,
            subject_norm=normalize_subject(parsed.subject),
            date=parsed.date,
            from_email=parsed.from_addr[0]["email"] if parsed.from_addr else "",
            to_emails=[a["email"] for a in parsed.to],
            in_reply_to=parsed.in_reply_to,
            references=parsed.references,
        ))
    return messages


class SubjectNormalizeTest(unittest.TestCase):
    def test_prefixes_stripped(self):
        self.assertEqual(normalize_subject("Re: Project kickoff"),
                         "project kickoff")
        self.assertEqual(normalize_subject("Fwd: Re: Project kickoff"),
                         "project kickoff")
        self.assertEqual(normalize_subject("R: Project kickoff"),
                         "project kickoff")
        self.assertEqual(normalize_subject("I: Project kickoff"),
                         "project kickoff")
        self.assertEqual(normalize_subject("Project kickoff"),
                         "project kickoff")


class ThreadMetricsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        build_corpus(cls.dir)
        cls.messages = _messages_from(cls.dir)
        cls.threads = build_threads(cls.messages, blackout_days=30)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_main_thread_found_with_four_members(self):
        kickoff = next(t for t in self.threads if "Project kickoff" in t.subject)
        self.assertEqual(len(kickoff.members), 4)

    def test_edge_latencies(self):
        kickoff = next(t for t in self.threads if "Project kickoff" in t.subject)
        delays = {e.child: e.delay_seconds for e in kickoff.edges}
        self.assertEqual(delays.get("reply1@example.org"), 178200)  # 49h30m
        self.assertIsNotNone(delays.get("reply2@example.net"))
        self.assertIsNotNone(delays.get("late@example.com"))

    def test_blackout_detected(self):
        kickoff = next(t for t in self.threads if "Project kickoff" in t.subject)
        gaps = [b.gap_days for b in kickoff.blackouts]
        self.assertTrue(any(gap > 70 for gap in gaps))

    def test_isolated_messages_are_singleton_threads(self):
        singletons = [t for t in self.threads if len(t.members) == 1]
        self.assertGreaterEqual(len(singletons), 4)

    def test_blackout_threshold_respected(self):
        threads = build_threads(self.messages, blackout_days=100)
        kickoff = next(t for t in threads if "Project kickoff" in t.subject)
        self.assertEqual(kickoff.blackouts, [])


if __name__ == "__main__":
    unittest.main()
