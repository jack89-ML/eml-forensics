"""Command-line interface for eml-forensics.

Exit codes: 0 success, 1 verified empty, 2 operational error,
130 interrupted. With --json/--csv the payload is the ONLY thing on
stdout; diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from . import __version__
from .attachments import extract_attachments
from .errors import (EXIT_EMPTY, EXIT_ERROR, EXIT_INTERRUPTED, ForensicsError)
from .metrics import ThreadMessage, build_threads
from .ocr_grid import iter_ocr_targets, ocr_file
from .output import (entry_to_dict, load_corpus, timeline_csv, timeline_rows,
                     timeline_table, write_corpus)
from .parser import ParsedMessage, iter_eml_files, parse_bytes, parse_message

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(value: str, fallback: str) -> str:
    slug = _SLUG_RE.sub("_", value).strip("_")[:80]
    return slug or fallback


def _parse_corpus_input(input_arg: str) -> tuple[list[dict], str]:
    """Accept a directory of .eml files or an existing corpus.json."""
    path = Path(input_arg)
    if path.is_file() and path.name == "corpus.json":
        return load_corpus(path), "corpus"
    files = iter_eml_files(path)
    entries = []
    for file_path in files:
        parsed = parse_message(file_path.read_bytes(), str(file_path))
        entries.append(entry_to_dict(parsed))
    return entries, "parsed"


def _cmd_process(args) -> int:
    root = Path(args.input)
    if not root.exists():
        raise ForensicsError(f"input not found: {args.input}")
    out_dir = Path(args.out)
    files = iter_eml_files(root)
    if not files:
        print("no .eml files found (verified empty)", file=sys.stderr)
        return EXIT_EMPTY

    messages_dir = out_dir / "messages"
    attachments_dir = out_dir / "attachments"
    messages_dir.mkdir(parents=True, exist_ok=True)
    attachments_dir.mkdir(parents=True, exist_ok=True)

    entries = []
    for index, file_path in enumerate(files, start=1):
        raw = file_path.read_bytes()
        parsed: ParsedMessage = parse_message(raw, str(file_path))
        parsed.attachments = extract_attachments(parse_bytes(raw),
                                                 attachments_dir)
        base = f"{index:04d}_{_slug(parsed.subject, parsed.message_id or 'msg')}"
        body_file = f"{base}.md"
        (messages_dir / body_file).write_text(
            f"# {parsed.subject}\n\n"
            f"- Date: {parsed.date}\n- From: {parsed.from_addr}\n"
            f"- To: {parsed.to}\n- Message-ID: {parsed.message_id}\n\n"
            f"{parsed.body_text}\n",
            encoding="utf-8")
        entries.append(entry_to_dict(parsed, body_file))

    corpus = write_corpus(entries, out_dir)
    timeline = timeline_rows(entries)
    (out_dir / "timeline.csv").write_text(timeline_csv(timeline),
                                          encoding="utf-8")
    print(f"processed {len(files)} messages -> {corpus}")
    return 0


def _cmd_ocr(args) -> int:
    root = Path(args.input)
    if not root.exists():
        raise ForensicsError(f"input not found: {args.input}")
    targets = iter_ocr_targets(root)
    if not targets:
        print("no image/PDF files found (verified empty)", file=sys.stderr)
        return EXIT_EMPTY
    out_dir = Path(args.out) if args.out else None
    processed = 0
    for target in targets:
        try:
            out_path, angle, text = ocr_file(target, lang=args.lang,
                                             out_dir=out_dir)
        except ForensicsError as exc:
            print(f"error: {target.name}: {exc}", file=sys.stderr)
            continue
        processed += 1
        print(f"{out_path}  angle={angle}°  chars={len(text)}")
    return 0 if processed else EXIT_ERROR


def _cmd_metrics(args) -> int:
    entries, source = _parse_corpus_input(args.input)
    if not entries:
        if args.json:
            print(json.dumps({"threads": [], "count": 0}))
        else:
            print("no messages (verified empty)", file=sys.stderr)
        return EXIT_EMPTY
    messages = []
    for entry in entries:
        messages.append(ThreadMessage(
            message_id=entry.get("message_id", ""),
            subject=entry.get("subject", ""),
            subject_norm=entry.get("subject", ""),
            date=entry.get("date_utc", ""),
            from_email=(entry.get("from") or [{}])[0].get("email", ""),
            to_emails=[a.get("email", "") for a in entry.get("to", [])],
            in_reply_to=entry.get("in_reply_to", ""),
            references=entry.get("references", [])))
    from .metrics import normalize_subject
    for message in messages:
        message.subject_norm = normalize_subject(message.subject)
    results = build_threads(messages, blackout_days=args.max_gap)
    if args.json:
        payload = []
        for thread in results:
            payload.append({
                "thread_id": thread.thread_id,
                "subject": thread.subject,
                "members": thread.members,
                "edges": [
                    {"parent": e.parent, "child": e.child,
                     "delay_seconds": e.delay_seconds}
                    for e in thread.edges
                ],
                "blackouts": [
                    {"start": b.start, "end": b.end, "gap_days": b.gap_days}
                    for b in thread.blackouts
                ],
            })
        print(json.dumps({"threads": payload, "count": len(payload)},
                         ensure_ascii=False, indent=2))
        return 0
    for thread in results:
        print(f"{thread.thread_id}  '{thread.subject}'  "
              f"members={len(thread.members)}  "
              f"edges={len(thread.edges)}  blackouts={len(thread.blackouts)}")
        for edge in thread.edges:
            if edge.delay_seconds is not None:
                print(f"    {edge.parent} -> {edge.child}  "
                      f"+{edge.delay_seconds}s")
        for blackout in thread.blackouts:
            print(f"    BLACKOUT {blackout.start} -> {blackout.end} "
                  f"({blackout.gap_days} days)")
    return 0


def _cmd_timeline(args) -> int:
    entries, _ = _parse_corpus_input(args.input)
    rows = timeline_rows(entries)
    if not rows:
        if args.format in ("json", "csv"):
            payload = "[]" if args.format == "json" else \
                "date_utc,from,to,subject,message_id,in_reply_to\n"
            print(payload)
        else:
            print("No messages (verified empty).", file=sys.stderr)
        return EXIT_EMPTY
    if args.format == "json":
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    elif args.format == "csv":
        print(timeline_csv(rows), end="")
    else:
        print(timeline_table(rows))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eml-forensics",
        description="Offline e-discovery for .eml corpora.",
    )
    parser.add_argument("--version", action="version",
                        version=f"eml-forensics {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_proc = sub.add_parser("process", help="parse a corpus to markdown + hashes")
    p_proc.add_argument("input", help="input directory (or a single .eml file)")
    p_proc.add_argument("--out", required=True, help="output directory")

    p_ocr = sub.add_parser("ocr", help="OCR images/PDFs with rotation grid")
    p_ocr.add_argument("input", help="file or directory")
    p_ocr.add_argument("--lang", default="ita+eng", help="tesseract languages")
    p_ocr.add_argument("--out", default=None, help="output directory for text")

    p_met = sub.add_parser("metrics", help="thread latency and blackout metrics")
    p_met.add_argument("input", help="directory of .eml files or corpus.json")
    p_met.add_argument("--max-gap", type=int, default=30,
                       help="blackout threshold in days (default 30)")
    p_met.add_argument("--json", action="store_true", help="pure JSON on stdout")

    p_tim = sub.add_parser("timeline", help="linear chronological table")
    p_tim.add_argument("input", help="directory of .eml files or corpus.json")
    p_tim.add_argument("--format", choices=["table", "csv", "json"],
                       default="table")
    return parser


def run(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit:
        return EXIT_ERROR
    try:
        if args.command == "process":
            return _cmd_process(args)
        if args.command == "ocr":
            return _cmd_ocr(args)
        if args.command == "metrics":
            return _cmd_metrics(args)
        if args.command == "timeline":
            return _cmd_timeline(args)
    except KeyboardInterrupt:
        print("interrupted by user", file=sys.stderr)
        return EXIT_INTERRUPTED
    except ForensicsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # unexpected failure -> still exit 2, no traceback
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR  # pragma: no cover


def main() -> None:
    try:
        sys.exit(run())
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted by user", file=sys.stderr)
        sys.exit(EXIT_INTERRUPTED)


if __name__ == "__main__":
    main()
