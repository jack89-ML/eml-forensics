# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-10

### Added

- Attached messages (`message/rfc822`) are parsed as their own corpus entries
  with a `nested_of` link: forwarded mail used to be invisible to the corpus,
  bodies and attachments included. `--max-nested` bounds the recursion.
- Attachment limits: `--max-attachment-size` (default 100 MiB per attachment)
  and `--attachment-budget` (default 500 MiB per message). A skipped payload
  keeps its name, size and SHA-256 in the manifest plus the reason, so the
  omission stays auditable; oversized or unwritable attachments no longer abort
  the corpus.
- Signature metadata per signer certificate: validity window
  (`not_before`/`not_after`) and SHA-256 fingerprint, next to the CN and issuer.
- Explicit `signature_verified: false` in the unpacking result: the envelope is
  unwrapped with `smime -verify -noverify`, i.e. not cryptographically
  validated. A forensic report must not imply a check it did not perform.
- Lint (ruff) and coverage (86.5% measured, fails under 80%) gates in CI.

### Fixed

- **`text/plain` wins over `text/html` regardless of MIME part order.** An
  alternative part carrying HTML before the plain text made the converted HTML
  win, losing the most faithful representation of the message.
- Filenames longer than 120 characters are truncated keeping the extension: a
  hostile or careless MIME filename used to raise `OSError` and abort the run.
- `EXIT_OK` was referenced in `cli.run` without being imported (latent
  `NameError` on the argparse path).


## [0.1.0] - 2026-09-04

### Added

- `process`: recursive `.eml` ingestion, MIME de-obfuscation, normalized
  Markdown bodies, per-attachment SHA-256 chain of custody, and CAdES `.p7m`
  unwrapping through `openssl`.
- `ocr`: 4-way orientation grid (0°/90°/180°/270°) with lexical confidence
  scoring, for rotated scans and PDFs.
- `metrics`: conversation DAG reconstruction with per-edge latency and
  blackout detection.
- `graph`: relational export (From→To, From→Cc weights) to Graphviz DOT and to
  node/edge matrices for Gephi or NetworkX.
- `scan`: pattern and checksum validation (fiscal code, IBAN, cadastral
  references, notarial references) plus watchlist search over corpus bodies.
- `enrich`: cross-correlation of extracted participants with official
  professional registers, delegating to `albo-search` when available.
- `timeline`: linear chronological serialization as table, CSV or JSON.
- Offline test suite with dynamically generated fixtures on RFC 2606 reserved
  domains, including a zero-leak guard over the whole repository tree.
- Case studies over the Enron corpus and Italian public-administration CAdES
  signatures, with the interaction graph shipped as an asset.

### Changed

- Attachment handling separated from body handling; integrity checks hardened.
- `scan` resolves `body_file` in corpus mode and accepts full Markdown bodies
  in directory mode.
- Cadastral rules require explicit `foglio` context for short `part.`
  references, removing false positives.

### Fixed

- Fiscal-code checksum on odd-position digits.
- Folded `Received` headers are reconstructed correctly; node handling made
  robust against malformed messages.
- Enron graph regenerated with a force-directed layout, dynamic degree sizing
  and contrast edges for readability.

[Unreleased]: https://github.com/jack89-ML/eml-forensics/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jack89-ML/eml-forensics/releases/tag/v0.1.0
