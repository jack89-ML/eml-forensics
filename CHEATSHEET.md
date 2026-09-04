# eml-forensics — Operations Cheatsheet

Offline e-discovery CLI for `.eml` corpora. Entry points: `eml-forensics` / `emlf`.
Exit codes: `0` ok · `1` verified empty · `2` operational error · `130` interrupted.

## Ingestion (process)

```bash
# full pipeline: markdown + attachment SHA-256 + corpus.json + timeline.csv
emlf process ./evidence/raw_eml --out ./evidence/processed

# also unwrap CAdES .p7m envelopes (signer, CA, timestamps, payload hash)
emlf process ./evidence/raw_eml --out ./evidence/processed --p7m
```

Artefacts:

```text
messages/0001_Subject.md            cleaned markdown body + metadata
attachments/0001_Subject/           raw attachments (path-traversal safe)
attachments/0001_Subject/unpacked/  p7m payload + signer/CA details
corpus.json                         machine index (auth digest included)
timeline.csv                        chronological event table
```

## OCR on attachments (rotation grid)

```bash
# 4-way orientation grid over every attachment in a processed corpus
emlf ocr ./evidence/processed/attachments --lang ita+eng

# one problematic scan, explicit output dir
emlf ocr ./evidence/scans/deed.pdf --out ./evidence/ocr_transcripts

# Italian legal documents: ita first
emlf ocr ./evidence/processed/attachments --lang ita
```

Each image/pdf is tested at 0°/90°/180°/270°, scored by lexical density and
written next to the source as `<name>.ocr.txt`. Re-run OCR-only passes on the
already-processed corpus without touching the chain of custody.

## Threads, latency and blackouts (metrics)

```bash
emlf metrics ./evidence/processed/corpus.json
emlf metrics ./evidence/processed/corpus.json --max-gap 14 --json
```

jq filters:

```bash
# threads with at least one blackout (gap > threshold)
emlf metrics ./evidence/processed/corpus.json --max-gap 14 --json \
  | jq -c '.threads[] | select((.blackouts // []) | length > 0)'

# worst latency edges per thread
emlf metrics ./evidence/processed/corpus.json --json \
  | jq -r '.threads[] | .messages as $m | $m[:($m|length-1)] | to_entries[]
      | select(.value.delay_s != null)
      | "\(.key): \(.value.delay_s)s"' | sort -t: -k2 -n | tail -5

# every delay > 48h (weekend/negotiation stalls)
emlf metrics ./evidence/processed/corpus.json --json \
  | jq -r '.. | objects | .delay_s? // empty | select(. > 172800)'
```

## Relational graph (graph)

```bash
# DOT file, then render with Graphviz
emlf graph ./evidence/processed/corpus.json --format dot --out network.dot
dot -Tpng network.dot -o network.png

# JSON matrix for Gephi / NetworkX
emlf graph ./evidence/processed/corpus.json --format json > interactions.json
```

jq filters:

```bash
# top communicators by out-degree (weight)
emlf graph ./evidence/processed/corpus.json --format json \
  | jq -r '.edges | group_by(.from)[] | "\(.[0].from): \([.[].weight] | add)"' \
  | sort -t: -k2 -rn | head

# cc-only observers (passive participants)
emlf graph ./evidence/processed/corpus.json --format json \
  | jq -r '.edges[] | select(.cc == true) | "\(.from) -> \(.to)"'
```

## Pattern & watchlist scanning (scan)

```bash
# built-in: fiscal codes (checksum), IBAN (mod-97), cadastral refs, notary refs
emlf scan ./evidence/processed/corpus.json

# watchlist over bodies + .ocr.txt transcripts
emlf scan ./evidence/processed --watchlist ./rules/keywords.txt --json
```

jq filters:

```bash
# hits grouped by kind
emlf scan ./evidence/processed/corpus.json --json \
  | jq -r '.hits | group_by(.kind)[] | "\(.[0].kind): \(length)"'

# hits referencing a cadastral sheet, with context
emlf scan ./evidence/processed/corpus.json --json \
  | jq -r '.hits[] | select(.kind=="cadastral") | "\(.message_id) \(.snippet)"'
```

## Registry enrichment (enrich)

```bash
# list participants + PEC flags, no external queries
emlf enrich ./evidence/processed/corpus.json --dry-run

# cross-check surnames against a bar council (requires albo-search in PATH)
emlf enrich ./evidence/processed/corpus.json --foro MILANO
```

## One-shot report

```bash
emlf process ./evidence/raw_eml --out ./processed
emlf metrics ./processed/corpus.json --json > metrics.json
emlf graph ./processed/corpus.json --format dot --out network.dot
dot -Tpng network.dot -o network.png
emlf scan ./processed --json > scan.json
```

## Notes

- P7M unwrapping needs the `openssl` binary; everything else is stdlib.
- OCR needs the `[ocr]` extra plus system `tesseract` + `poppler-utils`.
- Input corpora are read-only; every artefact lands under `--out`.
- `--json`/`--csv` print payload only on stdout; logs go to stderr.
