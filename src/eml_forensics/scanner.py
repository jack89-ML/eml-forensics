"""Pattern and watchlist scanner over corpus bodies.

Built-in rules cover Italian sensitive references: fiscal codes with control
character validation, IBAN with ISO 7064 mod-97 validation, cadastral
references (foglio/particella/subalterno/mappale) and notarial register
references. A watchlist file adds plain keyword searches over email bodies
and ``.ocr.txt`` transcriptions.
"""

from __future__ import annotations

import re
from pathlib import Path

CF_RE = re.compile(r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
CADASTRE_RE = re.compile(
    r"(?:\b(?:foglio|fg)\.?\s*\d+|\b(?:particella|part\.?|mappale)\.?\s*\d+"
    r"|\bsub(?:alterno)?\.?\s*\d+)",
    re.I,
)
NOTARY_RE = re.compile(
    r"(?:\b(?:repertorio|rep\.?|raccolta|rg\.?)\s*(?:n\.?|nr\.?)?\s*\d+)",
    re.I,
)

_ODD_TABLE = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3,
              6, 8, 12, 14, 16, 10, 22, 25, 24, 23]


def control_char(code15: str) -> str:
    """Italian fiscal-code control character (weights over the first 15)."""
    total = 0
    for index, char in enumerate(code15):
        position = index + 1
        if char.isdigit():
            value = int(char)
        elif position % 2 == 1:
            value = _ODD_TABLE[ord(char) - ord("A")]
        else:
            value = ord(char) - ord("A")
        total += value
    return chr(ord("A") + total % 26)


def cf_valid(code: str) -> bool:
    code = (code or "").upper()
    if not CF_RE.fullmatch(code):
        return False
    return control_char(code[:15]) == code[15]


def iban_valid(code: str) -> bool:
    """ISO 7064 MOD-97-10 check for IBANs."""
    normalized = (code or "").upper().replace(" ", "")
    if len(normalized) < 15 or not IBAN_RE.fullmatch(normalized):
        return False
    reordered = normalized[4:] + normalized[:4]
    digits = "".join(str(ord(char) - ord("A") + 10) if char.isalpha()
                     else char for char in reordered)
    return int(digits) % 97 == 1


def _norm_catastre(text: str) -> str:
    text = text.replace("particella", "part.").replace("mappale", "part.")
    return re.sub(r"\s+", " ", text).strip()


def scan_text(text: str, watchlist: list[str] | None = None) -> list[dict]:
    """Built-in pattern scan + optional keyword hits.

    Each hit: {kind, value, snippet}.
    """
    hits: list[dict] = []
    seen: set[tuple] = set()

    def push(kind: str, value: str, snippet: str) -> None:
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        hits.append({"kind": kind, "value": value, "snippet": snippet})

    for match in CF_RE.finditer(text):
        if cf_valid(match.group(0)):
            push("codice_fiscale", match.group(0),
                 snippet(text, match.start()))
    for match in IBAN_RE.finditer(text):
        if iban_valid(match.group(0)):
            push("iban", match.group(0), snippet(text, match.start()))
    for match in CADASTRE_RE.finditer(text):
        push("catastale", _norm_catastre(match.group(0)),
             snippet(text, match.start()))
    for match in NOTARY_RE.finditer(text):
        push("notarile", match.group(0).strip(), snippet(text, match.start()))

    lowered = text.lower()
    for keyword in watchlist or []:
        keyword = keyword.strip()
        if not keyword:
            continue
        position = lowered.find(keyword.lower())
        if position >= 0:
            push("watchlist", keyword, snippet(text, position))
    return hits


def snippet(text: str, start: int, radius: int = 80) -> str:
    left = max(0, start - radius)
    right = min(len(text), start + radius)
    prefix = "…" if left > 0 else ""
    suffix = "…" if right < len(text) else ""
    return (prefix + text[left:right].replace("\n", " ") + suffix).strip()


def load_watchlist(path: Path | None) -> list[str]:
    if path is None:
        return []
    return [line for line in
            path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
