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

    def test_future_message_is_never_a_parent(self):
        """Without reference headers, replies chain to predecessors only —
        a later message can never parent an earlier one."""
        base = "2026-02-01T09:00:00+00:00"

        def msg(msg_id, day, subject="Status report"):
            return ThreadMessage(
                message_id=msg_id, subject=subject,
                subject_norm=normalize_subject(subject),
                date=f"2026-02-{day:02d}T09:00:00+00:00",
                from_email="alice@example.com")

        messages = [msg("a@example.com", 1), msg("b@example.com", 3),
                    msg("c@example.com", 5)]
        threads = build_threads(messages)
        self.assertEqual(len(threads), 1)
        edges = threads[0].edges
        parents = {e.child: e.parent for e in edges}
        self.assertEqual(parents.get("b@example.com"), "a@example.com")
        self.assertEqual(parents.get("c@example.com"), "b@example.com")
        self.assertNotIn("a@example.com", parents)  # root has no parent
        for edge in edges:
            child_time = next(m.when for m in messages
                              if m.message_id == edge.child)
            parent_time = next(m.when for m in messages
                               if m.message_id == edge.parent)
            self.assertGreater(child_time, parent_time)

    def test_iso_z_suffix_parses(self):
        from eml_forensics.metrics import _parse_utc
        parsed = _parse_utc("2026-01-10T09:00:00Z")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.hour, 9)


if __name__ == "__main__":
    unittest.main()
