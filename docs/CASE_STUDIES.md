# Case Studies — Real-World Validation

Both studies ran entirely offline against public, open datasets inside isolated
benchmark directories (`/tmp/bench_*`), exercising `process`, `metrics`,
`graph`, `scan`, and the CAdES `.p7m` unpacker on heterogeneous real data.

---

## Case Study 1: Enron Corpus (SNA & E-Discovery Benchmark)

**Dataset.** Public sample of real Enron employee email (Hugging Face
`Hellisotherpeople/enron_emails_parsed`, derived from the CMU Enron corpus).
100 messages were reconstructed as minimal RFC 822 files (real From/To/Date/
Subject/body fields) and processed by the full pipeline.

**Pipeline results**

| Metric | Value |
| :--- | :--- |
| Messages processed | 100 / 100 (0 parse errors) |
| Graph nodes | 460 |
| Graph edges | 497 |
| Edge density | 0.0024 (sparse, typical for email) |
| Threads detected | 92 (8 linked by subject fallback) |
| Blackouts | 2 — max gap 255 days |
| Main hubs | `veronica.espinoza@enron.com` (deg 190), `lisa.jacobson@enron.com` (73), `kathie.grabstald@enron.com` (62) |

**Caveat.** The parsed dataset does not preserve `In-Reply-To`/`References`,
so conversational threading falls back to normalized subjects; latency edges
are therefore a lower bound.

**Visual.** High-resolution relational rendering (300 DPI, dark theme):
`../assets/enron_graph.png`

![Enron relational graph](../assets/enron_graph.png)

---

## Case Study 2: Italian Public Administration (CAdES P7M & Cadastral Scan)

**Dataset.** Two publicly signed acts from the Comune di Lecce open download
directory (Progetto "Passerelle nelle Marine"): *Doc 00 – Elenco degli
elaborati* and *Doc 11 – Titolarità delle aree*, both `.pdf.p7m`.

**Cryptographic results (CAdES unwrap)**

| Property | Value |
| :--- | :--- |
| Unwrap status | ok on both envelopes |
| Signature algorithm | `sha256WithRSAEncryption` (1.2.840.113549.1.1.11) |
| Signers | Enrico Ghezzi — CA `ArubaPEC S.p.A. NG CA 3`; Giovanni Puce — CA `INFOCERT SPA` |
| Signing time | present (`signingTime` signed attribute) on both |
| Hashing | distinct SHA-256 per envelope and per payload |

**Scanner results.** The updated cadastral rules (short `part. N` accepted
only when the same line carries `foglio`/`fg.`) reported **6 cadastral hits**
on the land-ownership document (`Doc 11`): `foglio 20/21/44` and
`part. 6/1/182` — with zero false positives and zero hits on the document
list (`Doc 00`). No fiscal codes or IBANs appear in either act's text layer.

**Rules change validated.** Pre-refinement the same scan reported a bare
`part. 20` style reference that the new context rule correctly suppresses as
ambiguous; the explicit forms (`particella`, `mappale`, `subalterno`, 3+
digit `part.`) keep full recall (unit-tested).
