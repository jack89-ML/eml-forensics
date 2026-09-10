# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
