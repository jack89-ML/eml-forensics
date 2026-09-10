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
# Most filesystems reject a component longer than 255 bytes; leaving the
# extension visible keeps the artefact recognisable in a report.
MAX_NAME_LENGTH = 120


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


def safe_filename(raw_name: str, fallback_index: int = 0,
                  max_length: int = MAX_NAME_LENGTH) -> str:
    """Neutralize a MIME filename: RFC 2047-decode, keep only the basename,
    strip traversal and odd characters, cap the length (keeping the
    extension). Never returns an absolute or parent-relative path."""
    name = _decode_rfc2047(raw_name)
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = name.strip(" .")
    name = _SAFE_RE.sub("_", name)
    if not name:
        name = f"attachment_{fallback_index}"
    if len(name) > max_length:
        stem, ext = os.path.splitext(name)
        name = f"{stem[:max(1, max_length - len(ext))]}{ext[:32]}"
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


def extract_attachments(message, dest_dir: Path, max_size: int | None = None,
                        budget: int | None = None) -> list[dict]:
    """Write every attachment under ``dest_dir`` and return its manifest.

    Manifest item: {name, file, sha256, size, content_type, disposition};
    skipped payloads keep their name, size and hash plus a ``skipped`` reason,
    so an omission is auditable instead of invisible.

    ``max_size`` drops a single oversized attachment, ``budget`` caps the total
    bytes written for one message (the corpus is untrusted input: without caps
    a single hostile or careless email fills the disk). Colliding names inside
    one message get a numeric suffix.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    seen: dict[str, int] = {}
    written = 0
    for part, filename, disposition in iter_attachments(message):
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        item = {
            "name": filename,
            "file": "",
            "sha256": sha256_bytes(payload),
            "size": len(payload),
            "content_type": part.get_content_type(),
            "disposition": "attachment" if "attachment" in disposition else "inline",
        }
        if max_size is not None and len(payload) > max_size:
            item["skipped"] = f"larger than the {max_size} byte limit"
            manifest.append(item)
            continue
        if budget is not None and written + len(payload) > budget:
            item["skipped"] = f"message budget of {budget} bytes exhausted"
            manifest.append(item)
            continue
        stem, ext = os.path.splitext(filename)
        candidate = filename
        counter = seen.get(filename, 0) + 1
        seen[filename] = counter
        if counter > 1:
            candidate = f"{stem}_{counter}{ext or ''}"
        target = dest_dir / candidate
        try:
            target.write_bytes(payload)
        except OSError as exc:
            # one unreadable/unwritable attachment must not abort the corpus
            item["skipped"] = f"not written: {exc}"
            manifest.append(item)
            continue
        item["file"] = str(target.relative_to(dest_dir.parent))
        manifest.append(item)
        written += len(payload)
    return manifest
