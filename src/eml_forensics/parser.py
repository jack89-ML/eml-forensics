"""RFC 822/5322 parsing: recursive MIME decode, charset handling,
HTML-to-text conversion and metadata extraction.

Standard library only. Charsets are decoded with a fallback chain that never
crashes on malformed payloads.
"""

from __future__ import annotations

import datetime as _dt
import email
import email.header
import email.utils
import html.parser
import re
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ForensicsError

_DECODE_CHAIN = ("utf-8", "iso-8859-1", "windows-1252")
_BLOCK_TAGS = {
    "p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6",
    "table", "blockquote", "pre", "section", "article",
}
_SKIP_TAGS = {"script", "style", "head", "title", "noscript", "svg"}
_TRACKING_RE = re.compile(
    r"<img[^>]*(?:width|height)=[\"']?1[\"']?[^>]*>", re.I
)


def parse_bytes(raw: bytes):
    """Parse raw .eml bytes into an :class:`email.message.EmailMessage`."""
    try:
        return email.message_from_bytes(raw)
    except Exception as exc:  # malformed MIME must never crash the pipeline
        raise ForensicsError(f"unparseable message: {exc}") from exc


def _decode_bytes(payload: bytes, charset: str | None) -> str:
    if charset:
        try:
            return payload.decode(charset)
        except (LookupError, UnicodeDecodeError):
            pass
    for candidate in _DECODE_CHAIN:
        try:
            return payload.decode(candidate)
        except UnicodeDecodeError:
            continue
    return payload.decode("utf-8", errors="replace")


def part_text(part) -> str | None:
    """Decoded text of a MIME part (text/*), or None for binary parts."""
    payload = part.get_payload(decode=True)
    if payload is None:
        return None
    if not part.get_content_type().startswith("text/"):
        return None
    return _decode_bytes(payload, part.get_content_charset())


class _TextExtractor(html.parser.HTMLParser):
    """HTML -> plain text: drops scripts/styles/markup, keeps paragraphs."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._skip = 0
        self._chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _SKIP_TAGS:
            self._skip += 1
        elif self._skip == 0 and tag in _BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in _SKIP_TAGS and self._skip > 0:
            self._skip -= 1
        elif self._skip == 0 and tag in _BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_data(self, data):
        if self._skip == 0:
            self._chunks.append(data)


def html_to_text(html_text: str) -> str:
    """Convert HTML to clean compact text, dropping tracking pixels."""
    cleaned = _TRACKING_RE.sub("", html_text)
    extractor = _TextExtractor()
    try:
        extractor.feed(cleaned)
    except Exception:  # pragma: no cover - defensive
        pass
    lines = [re.sub(r"[ \t]+", " ", line).strip()
             for line in "".join(extractor._chunks).splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(line for line in lines if line)).strip()


def _display(value: str) -> str:
    """Decode RFC 2047 encoded words in a single header value."""
    if not value:
        return ""
    parts = []
    for text, charset in email.header.decode_header(value):
        if isinstance(text, bytes):
            parts.append(_decode_bytes(text, charset))
        else:
            parts.append(text)
    return "".join(parts).strip()


def address_list(header_value: str) -> list[dict]:
    """Parse an address header into [{name, email}] keeping display names."""
    result = []
    for raw_name, raw_addr in email.utils.getaddresses([header_value or ""]):
        result.append({
            "name": _display(raw_name),
            "email": raw_addr,
        })
    return result


def _header_addresses(message, name: str) -> list[dict]:
    values = message.get_all(name, [])
    out: list[dict] = []
    for value in values:
        out.extend(address_list(value))
    return out


def normalize_date(value: str | None) -> str:
    """RFC date -> UTC ISO-8601 string; empty when unparseable."""
    if not value:
        return ""
    try:
        parsed = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc).isoformat()


@dataclass
class ParsedMessage:
    """Canonical representation of one message."""

    path: str = ""
    message_id: str = ""
    date: str = ""                  # UTC ISO-8601
    from_addr: list[dict] = field(default_factory=list)
    to: list[dict] = field(default_factory=list)
    cc: list[dict] = field(default_factory=list)
    subject: str = ""
    in_reply_to: str = ""
    references: list[str] = field(default_factory=list)
    pec: dict = field(default_factory=dict)
    body_text: str = ""
    body_from_html: bool = False
    attachments: list[dict] = field(default_factory=list)
    extra_headers: dict = field(default_factory=dict)


def _first_text_body(message) -> tuple[str | None, bool]:
    """Preferred body: text/plain; falls back to text/html converted.

    Parts carrying a ``filename`` or a ``Content-Disposition: attachment``
    are never treated as the message body — an attached .txt or .html file
    is an attachment, not the email text.
    """
    plain: str | None = None
    for part in message.walk():
        if part.get_filename():
            continue
        disposition = str(part.get("Content-Disposition", "")).lower()
        if "attachment" in disposition:
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain" and plain is None:
            plain = part_text(part)
        elif ctype == "text/html":
            html_text = part_text(part)
            if html_text:
                converted = html_to_text(html_text)
                if plain is None and converted:
                    return converted, True
    return plain, False


def parse_message(raw: bytes, path: str = "") -> ParsedMessage:
    """Full pipeline over one .eml file."""
    message = parse_bytes(raw)
    result = ParsedMessage(path=path)
    result.message_id = _display(message.get("Message-ID", "")).strip("<>")
    result.date = normalize_date(message.get("Date"))
    result.from_addr = _header_addresses(message, "From")
    result.to = _header_addresses(message, "To")
    result.cc = _header_addresses(message, "Cc")
    result.subject = _display(message.get("Subject", ""))
    result.in_reply_to = _display(message.get("In-Reply-To", "")).strip("<>")
    refs = _display(message.get("References", ""))
    result.references = [r.strip("<>") for r in re.split(r"[\s,]+", refs) if r.strip("<>")]

    for key in ("X-Riferimento-Message-ID", "X-TipoRicevuta",
                "X-Coda-Ricevuta", "Return-Path", "X-Mailer"):
        value = message.get(key)
        if value:
            cleaned = _display(value)
            if key == "X-Riferimento-Message-ID":
                cleaned = cleaned.strip("<>")
            result.pec[key] = cleaned
    result.extra_headers = {
        key: _display(value) for key, value in message.items()
        if key.lower().startswith("x-") and key not in result.pec
    }

    body, from_html = _first_text_body(message)
    result.body_text = (body or "").strip()
    result.body_from_html = from_html
    return result


def iter_eml_files(root: Path) -> list[Path]:
    """All *.eml files under a directory (recursive, case-insensitive)."""
    if root.is_file():
        return [root] if root.suffix.lower() == ".eml" else []
    return sorted(p for p in root.rglob("*") if p.suffix.lower() == ".eml")
