"""Offline tests: CLI behaviour, exit codes, stdout purity."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from eml_forensics import cli
from eml_forensics.errors import EXIT_EMPTY, EXIT_ERROR

from fixtures.make_fixtures import PNG_1PX, build_corpus


class CliTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.corpus = self.root / "in"
        build_corpus(self.corpus)

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.run(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_process_full_pipeline(self):
        out = self.root / "out"
        code, stdout, _ = self._run(["process", str(self.corpus), "--out", str(out)])
        self.assertEqual(code, 0)
        corpus = json.loads((out / "corpus.json").read_text())
        self.assertEqual(corpus["count"], 8)
        self.assertTrue((out / "timeline.csv").is_file())
        md_files = list((out / "messages").glob("*.md"))
        self.assertGreaterEqual(len(md_files), 8)
        att_files = [p for p in (out / "attachments").rglob("*") if p.is_file()]
        self.assertEqual(len(att_files), 3)  # notes.txt, plan.png, evil.txt
        # per-message folders: attachments live in 01_*/ and 08_*/ subdirs
        self.assertTrue(any("01_" in p.parent.name for p in att_files))
        self.assertTrue(any("08_" in p.parent.name for p in att_files))
        for message in corpus["messages"]:
            for attachment in message["attachments"]:
                self.assertTrue(
                    attachment["file"].startswith("attachments/0"))
        hashes = {a["sha256"] for m in corpus["messages"]
                  for a in m["attachments"]}
        self.assertEqual(len(hashes), 3)

    def test_process_empty_dir_exits_one(self):
        empty = self.root / "empty"
        empty.mkdir()
        code, _, stderr = self._run(
            ["process", str(empty), "--out", str(self.root / "o2")])
        self.assertEqual(code, EXIT_EMPTY)
        self.assertIn("no .eml", stderr)

    def test_timeline_json_is_pure(self):
        code, stdout, _ = self._run(
            ["timeline", str(self.corpus), "--format", "json"])
        self.assertEqual(code, 0)
        rows = json.loads(stdout)
        self.assertEqual(len(rows), 8)

    def test_timeline_csv_is_pure(self):
        code, stdout, _ = self._run(
            ["timeline", str(self.corpus), "--format", "csv"])
        self.assertEqual(code, 0)
        header, *lines = stdout.splitlines()
        self.assertTrue(header.startswith("date_utc,from,to"))
        self.assertEqual(len(lines), 8)

    def test_metrics_json_has_threads(self):
        code, stdout, _ = self._run(
            ["metrics", str(self.corpus), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertGreaterEqual(payload["count"], 5)
        kickoff = next(t for t in payload["threads"]
                       if "Project kickoff" in t["subject"])
        self.assertEqual(len(kickoff["members"]), 4)
        self.assertTrue(any(b["gap_days"] > 70 for b in kickoff["blackouts"]))

    def test_metrics_on_corpus_json(self):
        out = self.root / "out2"
        self._run(["process", str(self.corpus), "--out", str(out)])
        code, stdout, _ = self._run(
            ["metrics", str(out / "corpus.json"), "--json"])
        self.assertEqual(code, 0)
        json.loads(stdout)

    def test_metrics_accepts_directory_containing_corpus(self):
        out = self.root / "out3"
        self._run(["process", str(self.corpus), "--out", str(out)])
        code, stdout, _ = self._run(["metrics", str(out), "--json"])
        self.assertEqual(code, 0)
        json.loads(stdout)

    def test_markdown_body_has_clean_addresses(self):
        out = self.root / "out4"
        code, _, _ = self._run(["process", str(self.corpus), "--out", str(out)])
        self.assertEqual(code, 0)
        md_files = list((out / "messages").glob("0001_*.md"))
        self.assertEqual(len(md_files), 1)
        md = md_files[0].read_text()
        self.assertIn("From: Alice <alice@example.com>", md)
        self.assertIn("To: Bob <bob@example.org>", md)
        self.assertNotIn("[{", md)

    def test_corpus_entries_carry_auth_digest(self):
        out = self.root / "out_auth"
        self._run(["process", str(self.corpus), "--out", str(out)])
        corpus = json.loads((out / "corpus.json").read_text())
        for entry in corpus["messages"]:
            self.assertIn("auth", entry)
            self.assertEqual(entry["auth"]["hop_count"], 0)
            self.assertIn("p7m", entry)

    def test_graph_dot_and_json(self):
        code, stdout, _ = self._run(
            ["graph", str(self.corpus), "--format", "dot"])
        self.assertEqual(code, 0)
        self.assertTrue(stdout.startswith("digraph corpus {"))
        code, stdout, _ = self._run(
            ["graph", str(self.corpus), "--format", "json"])
        payload = json.loads(stdout)
        self.assertGreaterEqual(len(payload["nodes"]), 3)
        self.assertGreaterEqual(len(payload["edges"]), 3)

    def test_scan_detects_patterns_and_watchlist(self):
        import email.message
        from eml_forensics.scanner import control_char
        target = self.root / "hits"
        target.mkdir()
        code15 = "RSSMRA85M01H501"
        cf = code15 + control_char(code15)
        message = email.message.EmailMessage()
        message["From"] = "Alice <alice@example.com>"
        message["To"] = "Bob <bob@example.org>"
        message["Subject"] = "Pratica urgente"
        message["Message-ID"] = "<scan@example.com>"
        message["Date"] = "Sat, 10 Jan 2026 09:00:00 +0000"
        message.set_content(
            f"Codice fiscale {cf} e IBAN GB82WEST12345698765432. "
            "Foglio 24, particella 941. La pratica è urgente e riservata.")
        (target / "scan.eml").write_bytes(message.as_bytes())
        watch = self.root / "watch.txt"
        watch.write_text("# keywords\nurgente\nriservata\n")
        code, stdout, _ = self._run(
            ["scan", str(target), "--watchlist", str(watch), "--json"])
        self.assertEqual(code, 0)
        hits = json.loads(stdout)["hits"]
        kinds = {h["kind"] for h in hits}
        self.assertIn("codice_fiscale", kinds)
        self.assertIn("iban", kinds)
        self.assertIn("catastale", kinds)
        self.assertIn("watchlist", kinds)
        self.assertTrue(all(h["message_id"] == "scan@example.com"
                            for h in hits))

    def test_scan_empty_exits_one(self):
        empty = self.root / "empty_scan"
        empty.mkdir()
        code, stdout, _ = self._run(["scan", str(empty), "--json"])
        self.assertEqual(code, EXIT_EMPTY)
        self.assertEqual(json.loads(stdout), {"hits": []})

    def test_enrich_dry_run(self):
        code, stdout, _ = self._run(
            ["enrich", str(self.corpus), "--dry-run", "--json"])
        self.assertEqual(code, 0)
        rows = json.loads(stdout)["participants"]
        self.assertGreaterEqual(len(rows), 4)
        self.assertTrue(all(row["status"] in ("skipped", "not_checked")
                            for row in rows))

    def test_enrich_table_default(self):
        code, stdout, _ = self._run(
            ["enrich", str(self.corpus), "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("alice@example.com", stdout)
        self.assertIn("email", stdout)

    def test_ocr_without_extra_exits_two(self):
        try:
            import pytesseract  # noqa: F401
            self.skipTest("ocr extra installed")
        except ImportError:
            pass
        target = self.root / "img.png"
        target.write_bytes(PNG_1PX)
        code, stdout, stderr = self._run(["ocr", str(target)])
        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(stdout, "")
        self.assertIn("ocr", stderr.lower())

    def test_missing_input_exits_two(self):
        code, _, stderr = self._run(
            ["process", str(self.root / "missing"), "--out", str(self.root / "o")])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not found", stderr)

    def test_help_and_version_exit_zero(self):
        """`--help`/`--version` are successful invocations: returning the
        documented operational-error code (2) for them breaks shell checks."""
        for argv in (["--help"], ["-h"], ["--version"]):
            code = self._run(argv)[0]
            self.assertEqual(code, 0, f"{argv} returned {code}")

    def test_unknown_subcommand_exits_two(self):
        code = self._run(["not-a-command"])[0]
        self.assertEqual(code, 2)

    def test_missing_args_exit_two(self):
        code, _, _ = self._run(["process"])
        self.assertEqual(code, EXIT_ERROR)

    def test_keyboard_interrupt_returns_130(self):
        with mock.patch.object(cli, "parse_message",
                               side_effect=KeyboardInterrupt):
            code, stdout, stderr = self._run(
                ["process", str(self.corpus), "--out", str(self.root / "o3")])
        self.assertEqual(code, 130)
        self.assertEqual(stdout, "")
        self.assertIn("interrupted", stderr)


class ScanFullBodyTest(unittest.TestCase):
    """Scan coverage beyond body_preview: corpus body_file resolution and
    markdown targets in directory scans."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.run(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_corpus_scan_resolves_full_body_file(self):
        from eml_forensics.scanner import control_char
        cf = "RSSMRA80A01H501" + control_char("RSSMRA80A01H501")
        corpus_dir = self.root / "corpus"
        messages = corpus_dir / "messages"
        messages.mkdir(parents=True)
        # fiscal code only appears AFTER the preview window (400 chars)
        body = "contestualizzazione riservata\n" + ("x" * 450) + \
            f"\nCodice fiscale {cf} in coda.\n"
        (messages / "0001_deep.md").write_text(body, encoding="utf-8")
        corpus = {
            "count": 1,
            "messages": [{
                "message_id": "<deep@example.com>",
                "date_utc": "2026-01-10T09:00:00+00:00",
                "subject": "Deep body",
                "body_file": "messages/0001_deep.md",
                "body_preview": body[:200],  # no fiscal code in preview
                "from": [{"name": "Alice", "email": "alice@example.com"}],
                "to": [{"name": "Bob", "email": "bob@example.org"}],
            }],
        }
        (corpus_dir / "corpus.json").write_text(
            json.dumps(corpus), encoding="utf-8")
        code, stdout, _ = self._run(
            ["scan", str(corpus_dir / "corpus.json"), "--json"])
        self.assertEqual(code, 0)
        hits = json.loads(stdout)["hits"]
        self.assertTrue(any(h["kind"] == "codice_fiscale" for h in hits))

    def test_directory_scan_includes_markdown(self):
        from eml_forensics.scanner import control_char
        cf = "RSSMRA80A01H501" + control_char("RSSMRA80A01H501")
        target = self.root / "tree"
        target.mkdir()
        (target / "note.md").write_text(
            f"Nota riservata con codice {cf}.\n", encoding="utf-8")
        (target / "empty.txt").write_text("nessun dato qui\n",
                                          encoding="utf-8")
        code, stdout, _ = self._run(["scan", str(target), "--json"])
        self.assertEqual(code, 0)
        hits = json.loads(stdout)["hits"]
        self.assertTrue(any(h["kind"] == "codice_fiscale" for h in hits))
        self.assertTrue(any(h["message_id"] == "note.md" for h in hits))

    def test_directory_scan_markdown_empty_verified(self):
        target = self.root / "tree_clean"
        target.mkdir()
        (target / "note.md").write_text("solo testo innocuo\n",
                                        encoding="utf-8")
        code, stdout, _ = self._run(["scan", str(target), "--json"])
        self.assertEqual(code, EXIT_EMPTY)
        self.assertEqual(json.loads(stdout), {"hits": []})


if __name__ == "__main__":
    unittest.main()


class NestedAndLimitsCliTest(unittest.TestCase):
    """End-to-end: nested messages land in the corpus, attachment caps warn."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.corpus = self.root / "in"
        self.corpus.mkdir(parents=True)
        self.out = self.root / "out"

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = cli.run(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def _write_forward(self, attachment_bytes: int = 10) -> None:
        from email.message import EmailMessage
        inner = EmailMessage()
        inner["Subject"] = "INNER SUBJECT"
        inner["From"] = "carol@example.com"
        inner["To"] = "dave@example.org"
        inner.set_content("inner body")
        outer = EmailMessage()
        outer["Subject"] = "OUTER SUBJECT"
        outer["From"] = "alice@example.com"
        outer["To"] = "bob@example.org"
        outer.set_content("outer body")
        outer.add_attachment(inner, filename="forwarded.eml")
        outer.add_attachment(b"x" * attachment_bytes,
                             maintype="application", subtype="octet-stream",
                             filename="payload.bin")
        (self.corpus / "outer.eml").write_bytes(outer.as_bytes())

    def test_nested_message_becomes_a_corpus_entry(self):
        self._write_forward()
        code, _, _ = self._run(["process", str(self.corpus),
                                "--out", str(self.out)])
        self.assertEqual(code, 0)
        corpus = json.loads((self.out / "corpus.json").read_text("utf-8"))
        self.assertEqual(corpus["count"], 2)
        subjects = [m["subject"] for m in corpus["messages"]]
        self.assertIn("INNER SUBJECT", subjects)
        nested = [m for m in corpus["messages"] if m.get("nested_of")]
        self.assertEqual(len(nested), 1)
        self.assertEqual(nested[0]["subject"], "INNER SUBJECT")
        bodies = list((self.out / "messages").glob("*.md"))
        self.assertEqual(len(bodies), 2)
        nested_body = [p for p in bodies if "INNER" in p.read_text("utf-8")]
        self.assertEqual(len(nested_body), 1)
        self.assertIn("Nested in:", nested_body[0].read_text("utf-8"))

    def test_attachment_cap_is_reported_on_stderr(self):
        self._write_forward(attachment_bytes=1000)
        code, _, err = self._run(["process", str(self.corpus),
                                  "--out", str(self.out),
                                  "--max-attachment-size", "100"])
        self.assertEqual(code, 0)
        self.assertIn("attachment(s) not written", err)
        written = list((self.out / "attachments").rglob("*.bin"))
        self.assertEqual(written, [])
        corpus = json.loads((self.out / "corpus.json").read_text("utf-8"))
        outer = next(m for m in corpus["messages"]
                     if m.get("subject") == "OUTER SUBJECT")
        capped = [a for a in outer["attachments"] if a.get("skipped")]
        self.assertEqual(len(capped), 1)
        self.assertEqual(len(capped[0]["sha256"]), 64)

    def test_max_nested_zero_disables_nested_parsing(self):
        self._write_forward()
        code, _, _ = self._run(["process", str(self.corpus),
                                "--out", str(self.out), "--max-nested", "0"])
        self.assertEqual(code, 0)
        corpus = json.loads((self.out / "corpus.json").read_text("utf-8"))
        self.assertEqual(corpus["count"], 1)
