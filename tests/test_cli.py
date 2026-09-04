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
        att = list((out / "attachments").iterdir())
        self.assertEqual(len(att), 3)  # notes.txt, plan.png, evil.txt
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


if __name__ == "__main__":
    unittest.main()
