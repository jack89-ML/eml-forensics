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
eml-forensics process <input_dir> --out <out> --p7m     # also unwrap .p7m envelopes
eml-forensics ocr <file_or_dir> [--lang ita+eng]       # OCR with rotation grid
eml-forensics metrics <dir|corpus.json> [--json]       # threads, latency, blackouts
eml-forensics timeline <dir|corpus.json> [--format table|csv|json]
eml-forensics graph <dir|corpus.json> [--format dot|json] [--out file]
eml-forensics scan <dir|corpus.json> [--watchlist file] [--json]
eml-forensics enrich <dir|corpus.json> [--foro MILANO] [--dry-run] [--json]
```

`emlf` is registered as a shorthand alias.

### process

Scans the input recursively for `*.eml`, writes per message a Markdown file
(metadata + cleaned body), extracts every attachment into
`attachments/<message>/`, computes SHA-256 for each file, and emits:

- `corpus.json` — machine-readable index (jq/database friendly)
- `timeline.csv` — linear chronological view

Each corpus entry also carries an `auth` digest (Received hop chain with
per-hop delays, DKIM/SPF summaries and Authentication-Results) computed by
the authenticity module. With `--p7m`, CAdES envelopes (`.p7m` or
`application/pkcs7-mime`) are unwrapped via OpenSSL into
`attachments/<message>/unpacked/`, recording SHA-256 of both envelope and
payload plus signer/issuer certificates.

Bodies are decoded with a charset fallback chain (UTF-8 → ISO-8859-1 →
Windows-1252) and never crash the pipeline. HTML bodies are converted to
plain text with scripts, styles, comments and 1x1 tracking pixels removed;
parts carrying a filename or `Content-Disposition: attachment` are never
mistaken for the body.

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

### graph

Relational graph of the corpus: nodes are participant addresses, directed
edges are communications From→To (solid, weight = message count) and
From→Cc (dashed). Emits Graphviz DOT (render with
`dot -Tpng network.dot -o network.png`) or JSON. Useful for network /
SNA pipelines.

### scan

Pattern scanner over full email bodies (directory input) or corpus previews
(corpus.json input), plus any `*.ocr.txt` transcriptions found under the
input directory. Built-in rules validate:

- Italian fiscal codes (control character check)
- IBANs (ISO 7064 mod-97 check)
- cadastral references (foglio / particella / mappale / subalterno)
- notarial register references (repertorio / raccolta)

`--watchlist file.txt` adds plain keywords (lines, `#` comments allowed).
Every hit reports kind, value, message_id, UTC date and a context snippet.

### enrich

Lists the unique participants of a corpus (with PEC-domain flagging) and,
when the `albo-search` CLI (`albo` alias) is installed, correlates each
surname against the chosen bar council, annotating verified professional
qualifications. `--dry-run` skips external calls; a missing binary never
fails the pipeline — rows report `not_checked`.

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
- `.p7m` unwrapping requires the OpenSSL binary (`openssl`); everything else
  in the package works without third-party executables.
- `enrich` correlation requires the separate `albo-search` CLI to be on the
  PATH; every other command is self-contained.
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
