"""Machine-readable outputs: corpus index and linear timeline."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from .parser import ParsedMessage


def entry_to_dict(parsed: ParsedMessage, body_file: str = "") -> dict:
    return {
        "path": parsed.path,
        "message_id": parsed.message_id,
        "date_utc": parsed.date,
        "from": parsed.from_addr,
        "to": parsed.to,
        "cc": parsed.cc,
        "subject": parsed.subject,
        "in_reply_to": parsed.in_reply_to,
        "references": parsed.references,
        "pec": parsed.pec,
        "body_file": body_file,
        "body_preview": parsed.body_text[:400],
        "body_from_html": parsed.body_from_html,
        "attachments": parsed.attachments,
    }


def write_corpus(entries: list[dict], out_dir: Path) -> Path:
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "count": len(entries),
        "messages": entries,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "corpus.json"
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    return target


def load_corpus(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("messages", [])


def timeline_rows(entries: list[dict]) -> list[dict]:
    rows = []
    for entry in entries:
        sender = ""
        if entry.get("from"):
            sender = entry["from"][0].get("email") or entry["from"][0].get("name", "")
        recipients = ", ".join(
            a.get("email") or a.get("name", "")
            for a in entry.get("to", []))
        rows.append({
            "date_utc": entry.get("date_utc", ""),
            "from": sender,
            "to": recipients,
            "subject": entry.get("subject", ""),
            "message_id": entry.get("message_id", ""),
            "in_reply_to": entry.get("in_reply_to", ""),
        })
    rows.sort(key=lambda r: r["date_utc"])
    return rows


def timeline_csv(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=["date_utc", "from", "to", "subject",
                            "message_id", "in_reply_to"])
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


def timeline_table(rows: list[dict]) -> str:
    if not rows:
        return "No messages (verified empty)."
    headers = ["date_utc", "from", "to", "subject", "message_id"]
    lines = ["  ".join(h.ljust(0) for h in headers)]
    widths = {h: max(len(h), *(len(str(r[h])) for r in rows)) for h in headers}
    lines[0] = "  ".join(h.ljust(widths[h]) for h in headers)
    lines.append("-" * (sum(widths.values()) + 2 * (len(headers) - 1)))
    for row in rows:
        cells = [str(row[h])[:80].ljust(widths[h]) for h in headers]
        lines.append("  ".join(cells))
    return "\n".join(lines)
