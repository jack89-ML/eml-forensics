"""Attachment extraction with path-traversal protection and SHA-256 chain
of custody."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

_SAFE_RE = re.compile(r"[^A-Za-z0-9._ -]+")


def safe_filename(raw_name: str, fallback_index: int = 0) -> str:
    """Neutralize a MIME filename: keep only the basename, strip traversal
    and odd characters. Never returns an absolute or parent-relative path."""
    name = raw_name.replace("\\", "/").rsplit("/", 1)[-1]
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
