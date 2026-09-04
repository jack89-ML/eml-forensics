# eml-forensics

Offline e-discovery and digital-forensics toolkit for `.eml` corpora
(mailbox dumps, client exports, certified PEC mail). Parses MIME messages to
clean Markdown, extracts attachments with a SHA-256 chain of custody,
transcribes rotated scans through an OCR rotation grid, and reconstructs
conversation latency and silence metrics.

Everything runs locally: the core is Python 3.10+ standard library only;
OCR is an optional extra.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Optional OCR support (rotation grid over images/PDFs):

```bash
pip install -e ".[ocr]"        # pytesseract, pdf2image, Pillow
# + a tesseract binary and poppler-utils on the system
```

## Usage

```
eml-forensics process <input_dir> --out <output_dir>   # parse + markdown + hashes
eml-forensics ocr <file_or_dir> [--lang ita+eng]       # OCR with rotation grid
eml-forensics metrics <dir|corpus.json> [--json]       # threads, latency, blackouts
eml-forensics timeline <dir|corpus.json> [--format table|csv|json]
```

`emlf` is registered as a shorthand alias.

### process

Scans the input recursively for `*.eml`, writes per message a Markdown file
(metadata + cleaned body), extracts every attachment into `attachments/`,
computes SHA-256 for each file, and emits:

- `corpus.json` — machine-readable index (jq/database friendly)
- `timeline.csv` — linear chronological view

Bodies are decoded with a charset fallback chain (UTF-8 → ISO-8859-1 →
Windows-1252) and never crash the pipeline. HTML bodies are converted to
plain text with scripts, styles, comments and 1x1 tracking pixels removed.

### ocr

Runs a 4-way rotation grid (0°/90°/180°/270°) on each image or PDF, scores
each orientation by lexical quality and saves the best transcription next to
the source as `<name>.ocr.txt`. Useful for scans that were saved rotated.

### metrics

Reconstructs threads through `References` / `In-Reply-To` (falling back to
normalized subjects, stripping `Re:`/`Fwd:`/`R:`/`I:` prefixes) and reports:

- thread membership and reply edges with per-edge latency (`delay_seconds`)
- blackouts: intra-thread gaps beyond `--max-gap` days (default 30)

### timeline

Linear table of the whole corpus sorted by date; `--format csv|json` emits
pure data on stdout.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Success, records produced |
| 1    | Verified empty (no .eml / no OCR targets / no messages) |
| 2    | Operational error (missing input, missing OCR extra, tool failure) |
| 130  | Interrupted by user (SIGINT, no traceback) |

With `--json`/`--csv` the payload is the only thing written to stdout;
diagnostics go to stderr.

## Notes

- Attachment filenames are sanitized against path traversal; extraction
  never writes outside the destination directory.
- Dates are normalized to UTC ISO-8601 regardless of the original timezone.
- PEC headers (`X-Riferimento-Message-ID`, `X-TipoRicevuta`) are kept in a
  dedicated `pec` block of the corpus entry.
- The tool is read-only with respect to the input corpus and stores no data
  outside the output directory you choose.

## Development

```bash
pip install -e .
python -m unittest discover -s tests -v
```

The suite is fully offline: synthetic fixtures are generated at test time
(entities are RFC 2606 placeholders only) and OCR behaviour is tested
through injected callables, not a live tesseract.

## License

MIT
