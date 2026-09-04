"""Attachment extraction with path-traversal protection and SHA-256 chain
of custody."""

from __future__ import annotations

import email.header
import hashlib
import os
import re
from pathlib import Path

_SAFE_RE = re.compile(r"[^\w. -]+")
_DECODE_CHAIN = ("utf-8", "iso-8859-1", "windows-1252")


def _decode_rfc2047(value: str) -> str:
    """Decode encoded words (RFC 2047) in a MIME filename."""
    if "=?" not in value:
        return value
    parts = []
    for text, charset in email.header.decode_header(value):
        if isinstance(text, bytes):
            if charset:
                try:
                    parts.append(text.decode(charset))
                    continue
                except (LookupError, UnicodeDecodeError):
                    pass
            for candidate in _DECODE_CHAIN:
                try:
                    parts.append(text.decode(candidate))
                    break
                except UnicodeDecodeError:
                    continue
            else:
                parts.append(text.decode("utf-8", errors="replace"))
        else:
            parts.append(text)
    return "".join(parts)


def safe_filename(raw_name: str, fallback_index: int = 0) -> str:
    """Neutralize a MIME filename: RFC 2047-decode, keep only the basename,
    strip traversal and odd characters. Never returns an absolute or
    parent-relative path."""
    name = _decode_rfc2047(raw_name)
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = name.strip(" .")
    name = _SAFE_RE.sub("_", name)
    if not name:
        name = f"attachment_{fallback_index}"
    return name


def iter_attachments(message, min_size: int = 0):
    """Yield (part, filename, disposition) for file-bearing MIME parts."""
    index = 0
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename:
            continue
        index += 1
        disposition = str(part.get("Content-Disposition", "")).lower()
        yield part, safe_filename(filename, index), disposition


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_attachments(message, dest_dir: Path) -> list[dict]:
    """Write every attachment under ``dest_dir`` and return its manifest.

    Manifest item: {name, file, sha256, size, content_type, disposition}.
    Colliding names inside one message get a numeric suffix.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    seen: dict[str, int] = {}
    for part, filename, disposition in iter_attachments(message):
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        stem, ext = os.path.splitext(filename)
        candidate = filename
        counter = seen.get(filename, 0) + 1
        seen[filename] = counter
        if counter > 1:
            candidate = f"{stem}_{counter}{ext or ''}"
        target = dest_dir / candidate
        target.write_bytes(payload)
        manifest.append({
            "name": candidate,
            "file": str(target.relative_to(dest_dir.parent)),
            "sha256": sha256_bytes(payload),
            "size": len(payload),
            "content_type": part.get_content_type(),
            "disposition": "attachment" if "attachment" in disposition else "inline",
        })
    return manifest
