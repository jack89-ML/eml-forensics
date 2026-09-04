"""Offline tests: participant collection and albo-search correlation bridge."""

import unittest
from unittest import mock

from eml_forensics import enrich


def _entry(sender_name, sender_email, recipients=None, cc=None):
    return {
        "message_id": "id@example.com", "subject": "t",
        "date_utc": "2026-01-10T09:00:00+00:00",
        "from": [{"name": sender_name, "email": sender_email}],
        "to": [{"name": r[0], "email": r[1]} for r in (recipients or [])],
        "cc": [{"name": r[0], "email": r[1]} for r in (cc or [])],
        "references": [],
    }


class CollectTest(unittest.TestCase):
    def test_unique_participants_and_counts(self):
        entries = [
            _entry("Alice", "alice@example.com",
                   [("Bob", "bob@example.org")]),
            _entry("Alice", "alice@example.com",
                   [("Bob", "bob@example.org")],
                   cc=[("Charlie", "charlie@example.net")]),
            _entry("Bob", "bob@example.org",
                   [("Alice", "alice@example.com")]),
        ]
        participants = enrich.collect_participants(entries)
        by_email = {p.email: p for p in participants}
        self.assertEqual(set(by_email), {
            "alice@example.com", "bob@example.org", "charlie@example.net"})
        self.assertEqual(by_email["alice@example.com"].count, 3)
        self.assertEqual(by_email["alice@example.com"].name, "Alice")

    def test_pec_detection(self):
        entries = [_entry("Pec", "giuridica@pec.example.com",
                          [("X", "x@example.org")])]
        participants = enrich.collect_participants(entries)
        self.assertTrue(participants[0].pecs)


class CorrelateTest(unittest.TestCase):
    def setUp(self):
        self.participants = enrich.collect_participants([
            _entry("Mario Rossi", "mario.rossi@example.com",
                   [("Luca Bianchi", "luca.bianchi@example.org")]),
        ])

    def test_skipped_without_foro(self):
        rows = enrich.correlate(self.participants, foro=None)
        self.assertEqual(rows[0]["status"], "skipped")

    def test_dry_run_never_calls_external(self):
        rows = enrich.correlate(self.participants, foro="MILANO",
                                dry_run=True)
        self.assertEqual(rows[0]["status"], "not_checked")
        self.assertEqual(rows[0]["detail"], "dry-run")

    def test_missing_binary_reported(self):
        with mock.patch.object(enrich, "_find_binary", return_value=None):
            rows = enrich.correlate(self.participants, foro="MILANO")
        self.assertEqual(rows[0]["status"], "not_checked")
        self.assertIn("not installed", rows[0]["detail"])

    def test_verified_flow_with_fake_binary(self):
        with mock.patch.object(enrich, "_find_binary",
                               return_value="/usr/bin/albo-search"):
            with mock.patch.object(enrich, "_query_albo",
                                   return_value={"status": "verified",
                                                 "matches": 2}):
                rows = enrich.correlate(self.participants, foro="MILANO")
        self.assertEqual(rows[0]["status"], "verified")
        self.assertEqual(rows[0]["matches"], 2)

    def test_render_table(self):
        rows = enrich.correlate(self.participants, foro="MILANO",
                                dry_run=True)
        table = enrich.render_table(rows)
        self.assertIn("mario.rossi@example.com", table)
        self.assertIn("email", table)


if __name__ == "__main__":
    unittest.main()
