"""Offline tests: interaction graph and DOT/JSON rendering."""

import json
import unittest

from eml_forensics import graph


def _entry(sender, recipients, cc=None, subject="t"):
    return {
        "message_id": "id@example.com", "subject": subject,
        "date_utc": "2026-01-10T09:00:00+00:00",
        "from": [{"name": sender.split("@")[0].title(), "email": sender}],
        "to": [{"name": r.split("@")[0].title(), "email": r}
               for r in recipients],
        "cc": [{"name": r.split("@")[0].title(), "email": r}
               for r in (cc or [])],
        "references": [],
    }


class GraphTest(unittest.TestCase):
    def setUp(self):
        self.entries = [
            _entry("alice@example.com", ["bob@example.org"],
                   cc=["charlie@example.net"], subject="a"),
            _entry("alice@example.com", ["bob@example.org"], subject="b"),
            _entry("charlie@example.net", ["alice@example.com"], subject="c"),
        ]

    def test_edges_and_weights(self):
        nodes, edges = graph.interactions(self.entries)
        self.assertEqual(len(nodes), 3)
        by_pair = {(e["from"], e["to"]): e for e in edges}
        self.assertEqual(by_pair[("alice@example.com",
                                  "bob@example.org")]["weight"], 2)
        self.assertFalse(by_pair[("alice@example.com",
                                  "bob@example.org")]["cc"])
        cc_edge = by_pair[("alice@example.com", "charlie@example.net")]
        self.assertTrue(cc_edge["cc"])
        self.assertEqual(by_pair[("charlie@example.net",
                                  "alice@example.com")]["weight"], 1)

    def test_names_attached_to_nodes(self):
        nodes, _ = graph.interactions(self.entries)
        self.assertEqual(nodes["alice@example.com"]["name"], "Alice")

    def test_dot_output(self):
        nodes, edges = graph.interactions(self.entries)
        dot = graph.to_dot(nodes, edges)
        self.assertTrue(dot.startswith("digraph corpus {"))
        self.assertIn('"alice@example.com" -> "bob@example.org"', dot)
        self.assertIn("style=dashed", dot)   # cc edge
        self.assertIn('label="2"', dot)

    def test_json_output(self):
        nodes, edges = graph.interactions(self.entries)
        payload = json.loads(graph.to_json(nodes, edges))
        self.assertEqual(len(payload["nodes"]), 3)
        self.assertEqual(len(payload["edges"]), 3)


if __name__ == "__main__":
    unittest.main()
