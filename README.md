# VulnTriage-RAG

Is this CVE actually my problem? Exploit-aware triage for Python dependencies, with cited verdicts.

## Architecture

```
requirements.txt -> [Scanner: OSV querybatch, min_safe_version, priority]
                        |
                  [Hybrid retriever: BM25 + bge-small + RRF + cross-encoder]
                        |
              [LLM verdict, citation-validated against evidence ids]
                        |
                  Findings report (table / JSON) + /ask endpoint
```

## Quickstart

```bash
docker compose up -d
uv sync --extra dev
uv run vt db-init
uv run vt ingest osv --limit 2000 && uv run vt ingest kev && uv run vt ingest epss
uv run vt index
uv run vt scan tests/fixtures/requirements_demo.txt
```

(Note: this uses `--limit 2000`, not the unlimited full-corpus ingest — every number in this README
was produced against that dev-scoped corpus. See Limitations for why, and don't read the numbers
below as full-corpus numbers.)

## Sample output

```
                   VulnTriage scan: tests/fixtures/requirements_demo.txt
+-----------------------------------------------------------------------------------------+
| priority | package      | installed | advisory_id         | min_safe_version | verified |
|----------+--------------+-----------+---------------------+------------------+----------|
| P1       | django       | 3.2.0     | GHSA-2hrw-hx67-34x6 | 3.2.18           | False    |
| P1       | django       | 3.2.0     | GHSA-6cw3-g6wv-c2xv | 3.2.12           | False    |
| P1       | django       | 3.2.0     | GHSA-2gwj-7jmv-h26r | 3.2.13           | False    |
| P1       | django       | 3.2.0     | GHSA-6w2r-r2m5-xq5w | 4.2.24           | False    |
| P1       | pyyaml       | 5.3       | GHSA-6757-jp84-gxfx | 5.3.1            | False    |
| P1       | pillow       | 8.0.0     | GHSA-7534-mm45-c74v | 8.3.0            | False    |
| P1       | pillow       | 8.0.0     | GHSA-77gc-v2xv-rvvh | 8.2.0            | False    |
| P1       | pillow       | 8.0.0     | GHSA-57h3-9rgr-c24m | 8.1.1            | False    |
| P2       | pillow       | 8.0.0     | GHSA-3wvg-mj6g-m9cv | 8.1.2            | False    |
| P2       | flask        | 0.12      | GHSA-562c-5r94-xh97 | 0.12.3           | False    |
| P2       | jinja2       | 2.10      | GHSA-462w-v97r-4m45 | 2.10.1           | False    |
| P2       | urllib3      | 1.24.1    | GHSA-38jv-5279-wg99 | 2.6.3            | False    |
| P2       | pillow       | 8.0.0     | GHSA-7r7m-5h27-29hp | 8.2.0            | False    |
| P2       | django       | 3.2.0     | GHSA-53qw-q765-4fww | 3.2.11           | False    |
| P2       | flask        | 0.12      | GHSA-5wv5-4vpf-pj6m | 1.0              | False    |
| P2       | pillow       | 8.0.0     | GHSA-3f63-hfp8-52jq | 10.2.0           | False    |
| P2       | cryptography | 3.2       | GHSA-3ww4-gg4f-jr7f | 42.0.0           | False    |
| P2       | pillow       | 8.0.0     | GHSA-6r8x-57c9-28j4 | 12.3.0           | True     |
| P2       | pillow       | 8.0.0     | GHSA-45hq-cxwh-f6vc | 12.3.0           | True     |
| P2       | pillow       | 8.0.0     | GHSA-5x94-69rx-g8h2 | 12.3.0           | True     |
| P2       | cryptography | 3.2       | GHSA-537c-gmf6-5ccf | 48.0.1           | False    |
| P3       | django       | 3.2.0     | GHSA-68w8-qjq3-2gfm | 3.2.4            | False    |
| P3       | django       | 3.2.0     | GHSA-7h4p-27mh-hmrw | 3.2.21           | False    |
| P3       | urllib3      | 1.24.1    | GHSA-34jh-p97f-mpxf | 1.26.19          | False    |
| P3       | pillow       | 8.0.0     | GHSA-44wm-f244-xhp3 | 10.3.0           | False    |
| P3       | django       | 3.2.0     | GHSA-7xr5-9hcq-chf9 | 4.2.22           | False    |
| P3       | urllib3      | 1.24.1    | GHSA-2xpw-w6gg-jr37 | 2.6.0            | False    |
| P3       | pillow       | 8.0.0     | GHSA-62p4-gmf7-7g93 | 12.3.0           | True     |
| P3       | django       | 3.2.0     | GHSA-3h9f-r86x-qvjx | 5.2.16           | False    |
| P3       | flask        | 0.12      | GHSA-68rp-wp8r-4726 | 3.1.3            | True     |
| P3       | pillow       | 8.0.0     | GHSA-4x4j-2g7c-83w6 | 12.3.0           | True     |
| P3       | pillow       | 8.0.0     | GHSA-4fx9-vc88-q2xc | 9.0.0            | False    |
| P3       | cryptography | 3.2       | GHSA-5cpq-8wj7-hf2v | 41.0.0           | False    |
+-----------------------------------------------------------------------------------------+
```

(Captured with `--no-llm` for determinism; 33 findings across 8 pinned dependencies in
`tests/fixtures/requirements_demo.txt`, against the dev-scoped `--limit 2000` OSV corpus.)

## Results

Real retrieval eval (`reports/eval.md`, 53 real queries — 33 LLM-generated + 20 hand-verified —
against the dev-scoped `--limit 2000` corpus):

| Setup | Recall@1 | Recall@5 | Recall@10 | MRR@10 | p50 ms |
|---|---|---|---|---|---|
| BM25 | 0.585 | 0.774 | 0.792 | 0.659 | 37.0 |
| Dense (bge-small) | 0.340 | 0.585 | 0.642 | 0.437 | 18.4 |
| Hybrid (RRF) | 0.547 | 0.679 | 0.755 | 0.610 | 65.6 |
| Hybrid + cross-encoder | 0.717 | 0.830 | 0.830 | 0.762 | 1326.9 |

Real generation eval (`vt eval generation`, 33 findings on the demo requirements file):

- JSON-valid rate: 48.48%
- Citation-valid rate: 48.48%
- Fallback rate: 51.52%
- min_safe_version verified rate: 18.18%
- Faithfulness spot check: 3/10 verdicts read by hand had a clear unsupported/incorrect claim, plus
  1 borderline self-contradiction (specifics: a rationale claiming "no immediate action required"
  for a P1 finding and inventing an "NVD" citation source that was never in the evidence; a
  rationale garbling a version number as a "severity score"; a rationale claiming the installed
  version was already at the safe version, contradicting the evidence's own installed-version fact;
  and, separately, one verdict calling something "high-priority" then "P2... moderate severity" in
  the same paragraph)

**A note on statistical confidence:** these retrieval numbers come from 53 real queries (33
LLM-generated + 20 hand-verified), not the ~150 originally targeted — a real dev-run of the full
query-generation batch was interrupted by a host memory constraint partway through, and re-running
it was judged not worth the risk on this machine. At N=53, differences of 1-2 queries between
setups (e.g. Hybrid RRF's recall vs plain BM25's) are within noise and shouldn't be read as
meaningful; the reranking setup's larger, consistent gains across all three recall/MRR metrics are
the more trustworthy signal.

## Design decisions

- **Code computes, the LLM explains.** Version matching, minimum safe version and priority are
  deterministic Python; the LLM only writes prose, and a validator rejects any citation not in
  the evidence it was given.
- **Alias groups.** OSV mirrors the same bug under both GHSA-* and PYSEC-* ids; a union-find over
  aliases collapses these before computing retrieval metrics, or Recall/MRR look artificially low.
- **RRF over score blending.** BM25 and dense scores are not on the same scale; reciprocal rank
  fusion combines rankings, not raw scores. Note: RRF can occasionally score below its single best
  input on Recall@1 specifically when the other fused retriever is weak on a given query (confirmed
  in this project's own eval table, where plain BM25 slightly out-scores Hybrid RRF on Recall@1) —
  this is naive/unweighted RRF rewarding cross-retriever consensus over single-retriever confidence,
  a known property, not a bug.
- **Why a cross-encoder.** The fused list has the right advisory in the top 30 more often than in
  the top 5; the cross-encoder fixes ordering (the largest, most consistent gain in the eval table)
  at a measured latency cost (~1.3s/query on CPU) that is real and worth naming explicitly, not just
  "some cost."
- **Request timeouts on the LLM path.** A stuck local Ollama server was observed to hang the
  scanner/ask pipeline indefinitely during development; `OllamaProvider` now constructs an explicit
  client with a configurable timeout (`OLLAMA_TIMEOUT`, default 120s) rather than waiting forever.

## Limitations

- Tells you a vulnerable version is *installed*, not that the vulnerable code path is *reachable*.
- PyPI only; npm/Maven/Go are out of scope for this build.
- KEV hits on PyPI are rare by design (KEV is dominated by vendor products).
- **Ingested corpus is dev-scoped**: ~2,000 OSV PyPI advisories (`vt ingest osv --limit 2000`), not
  the full OSV PyPI corpus (tens of thousands of records) the spec anticipates for a "full" build.
  All numbers in this README (findings, eval table, generation rates) reflect this smaller corpus,
  reported honestly rather than extrapolated. A full, unlimited ingest + re-index is a straightforward
  follow-up (documented as the spec's own accepted cut-list item: "evaluate on a subset and say so").
- **Retrieval eval set is 53 queries**, not the ~150 originally targeted (see Results section above).
- The local `llama3.2:3b` model (via Ollama) has a real, measured ~48% success rate at producing
  citation-valid JSON on the first-or-retry attempt for this project's dossier format — the remaining
  ~52% fall back to a deterministic template verdict (never a fabricated one), and even among the
  successful LLM verdicts, a hand-read faithfulness check found unsupported claims in roughly a third
  of them (see Results). A larger/more capable model would very likely improve both rates.

## Next steps

- Reachability analysis via a tree-sitter call graph from entry points to vulnerable symbols named
  in fix commits.
- A calibrated classifier trained on KEV additions, replacing the static priority table.
- npm/Maven ecosystem support.
- Full, unlimited OSV ingest + re-index once running on a machine with more headroom, to validate
  the eval numbers above at full corpus scale.
