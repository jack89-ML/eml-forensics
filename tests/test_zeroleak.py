"""Zero-leak guard: no case-related tokens anywhere in the repository.

Tokens are rot13-encoded here so the literal names never appear in the tree.
"""

import codecs
import pathlib
import unittest

_ENCODED = [
    # case entities and places
    "pebgbar", "pngnamneb", "fniryyv", "fpnyvfr", "snovnab", "crenppuvb",
    "pnynoevn", "fpnaqvppv", "pbframn", "pnfgebivyynev", "iremvab", "fvyn",
    "cbagvrev", "znasreqv", "sebagren",
]
FORBIDDEN = tuple(codecs.encode(token, "rot13") for token in _ENCODED)
SKIPPED = {".git", ".venv", "venv", "__pycache__", ".pytest_cache",
           "generated", "out"}
SKIPPED_FILES = {"test_zeroleak.py"}


class ZeroLeakTest(unittest.TestCase):
    def test_tree_is_free_of_case_tokens(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        offenders = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIPPED for part in path.parts):
                continue
            if path.name in SKIPPED_FILES:
                continue
            if path.suffix.lower() in {".png", ".jpg", ".pyc", ".pdf"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            for token in FORBIDDEN:
                if token in text:
                    offenders.append((str(path.relative_to(root)), token))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
