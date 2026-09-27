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

(Note: this uses `--limit 2000`, not the unlimited full-corpus ingest. The retrieval and generation
numbers in this README were produced against that dev-scoped corpus; see Limitations for why, and
don't read them as full-corpus numbers. `vt ingest osv` reuses a cached `all.zip` for 24 hours;
`--force-download` fetches a fresh copy.)

## Sample output

```
                   VulnTriage scan: tests/fixtures/requirements_demo.txt
+-----------------------------------------------------------------------------------------+
| priority | package      | installed | advisory_id         | min_safe_version | verified |
|----------+--------------+-----------+---------------------+------------------+----------|
| P0       | pillow       | 8.0.0     | GHSA-j7hp-h8jx-5ppr | 10.0.1           | True     |
| P1       | django       | 3.2.0     | GHSA-p64x-8rxx-wf6q | 3.2.14           | True     |
| P1       | django       | 3.2.0     | GHSA-2hrw-hx67-34x6 | 3.2.18           | True     |
| P1       | cryptography | 3.2       | GHSA-x4qr-2fvf-3mr5 | 39.0.1           | True     |
| P1       | django       | 3.2.0     | GHSA-qmf9-6jqf-j8fq | 3.2.23           | True     |
| P1       | django       | 3.2.0     | GHSA-6cw3-g6wv-c2xv | 3.2.12           | True     |
| P1       | django       | 3.2.0     | GHSA-q2jf-h9jm-m7p4 | 3.2.17           | True     |
| P1       | django       | 3.2.0     | GHSA-xpfp-f569-q3p2 | 3.2.5            | True     |
| P1       | django       | 3.2.0     | GHSA-frmv-pr5f-9mcr | 4.2.26           | True     |
| P1       | django       | 3.2.0     | GHSA-2gwj-7jmv-h26r | 3.2.13           | True     |
| P1       | django       | 3.2.0     | GHSA-6w2r-r2m5-xq5w | 4.2.24           | True     |
| P1       | cryptography | 3.2       | GHSA-rhm9-p9w5-fwm7 | 3.3.2            | True     |
| P1       | pyyaml       | 5.3       | GHSA-8q59-q68h-6hv4 | 5.4              | True     |
| P1       | pyyaml       | 5.3       | GHSA-6757-jp84-gxfx | 5.3.1            | True     |
| P1       | pillow       | 8.0.0     | GHSA-8vj2-vxx3-667w | 9.0.1            | True     |
| P1       | pillow       | 8.0.0     | GHSA-7534-mm45-c74v | 8.3.0            | True     |
| P1       | django       | 3.2.0     | GHSA-w24h-v9qh-8gxj | 3.2.13           | True     |
| P1       | pillow       | 8.0.0     | GHSA-77gc-v2xv-rvvh | 8.2.0            | True     |
| P1       | pillow       | 8.0.0     | GHSA-9j59-75qj-795w | 9.0.1            | True     |
| P1       | pillow       | 8.0.0     | GHSA-rwv7-3v45-hg29 | 8.2.0            | True     |
| P1       | pillow       | 8.0.0     | GHSA-57h3-9rgr-c24m | 8.1.1            | True     |
| P1       | django       | 3.2.0     | GHSA-r3xc-prgr-mg9p | 3.2.19           | True     |
| P2       | requests     | 2.19.0    | GHSA-x84v-xcm2-53pg | 2.20.0           | True     |
| P2       | django       | 3.2.0     | GHSA-rxjp-mfm9-w4wr | 3.2.1            | True     |
| P2       | django       | 3.2.0     | GHSA-p99v-5w3c-jqq9 | 3.2.4            | True     |
| P2       | pillow       | 8.0.0     | GHSA-3wvg-mj6g-m9cv | 8.1.2            | True     |
| P2       | flask        | 0.12      | GHSA-562c-5r94-xh97 | 0.12.3           | True     |
| P2       | jinja2       | 2.10      | GHSA-462w-v97r-4m45 | 2.10.1           | True     |
| P2       | pillow       | 8.0.0     | GHSA-98vv-pw6r-q6q4 | 8.3.2            | True     |
| P2       | pillow       | 8.0.0     | GHSA-f4w8-cv6p-x6r5 | 8.1.2            | True     |
| ...      |              |           |                     |                  |          |
+-----------------------------------------------------------------------------------------+
```

(Captured with `--no-llm` for determinism; first 30 of **127 findings** across the 8 pinned
dependencies in `tests/fixtures/requirements_demo.txt`: 1 P0, 21 P1, 50 P2, 55 P3, all 127 with a
verified minimum safe version. Findings don't depend on the dev-scoped corpus: OSV `querybatch`
decides which advisories affect each pin, and any advisory the local corpus lacks is fetched from
OSV on demand and cached, so `vt index` can chunk it for verdict evidence.)

## Results

Retrieval eval (`vt eval retrieval` → `reports/eval.md`; 53 real queries, 33 LLM-generated + 20
hand-verified, against the dev-scoped `--limit 2000` corpus). All 53 were evaluated, 0 skipped. Recall@k
and MRR@10 are over the top-k distinct advisory alias groups, from 50 retrieved chunks per query; p50
includes retrieving those 50 chunks (and reranking them, for the cross-encoder row):

| Setup | Recall@1 | Recall@5 | Recall@10 | MRR@10 | p50 ms |
|---|---|---|---|---|---|
| BM25 | 0.585 | 0.755 | 0.811 | 0.661 | 41.4 |
| Dense (bge-small) | 0.377 | 0.604 | 0.698 | 0.478 | 48.3 |
| Hybrid (RRF) | 0.566 | 0.698 | 0.849 | 0.634 | 145.1 |
| Hybrid + cross-encoder | 0.660 | 0.830 | 0.849 | 0.736 | 3282.2 |

Generation eval (`vt eval generation --limit 40`, llama3.2:3b via Ollama on CPU). The demo scan has
127 findings; LLM verdicts are generated for a fixed-seed sample of 40 of them (~10-20 s each), and
all 40 reached the model:

- JSON-valid rate: 92.5% (schema-valid JSON object on the final response)
- Citation-valid rate: 85.0% (also every citation in the evidence set; these are the LLM verdicts kept)
- Fallback rate: 15.0% (deterministic template verdict instead)
- Provider-error rate: 0.0%
- min_safe_version verified rate: 100% (127/127, over all findings; no LLM involved)
- Faithfulness spot check: 4 of the first 10 kept LLM verdicts, read by hand against their FACT lines
  and cited evidence, have a clear unsupported or incorrect claim. One says the fixed version (8.3.2)
  is affected. One says to upgrade to "3.2 or later" when 3.2 is installed and 49.0.0 is the safe
  version. One says the fix is "already installed (3.2)" and calls a P3 finding high-priority. One
  more calls a P3 finding "high priority". Three others inflate a P1/P2 finding to "critical"/"High"
  (borderline).

Citation-valid counts evidence ids with or without the square brackets they're printed in (models
often copy `[GHSA-…]` verbatim); any id outside the evidence set is still rejected.

**A note on statistical confidence:** the retrieval numbers come from 53 real queries, not the ~150
originally targeted: a dev-run of the full query-generation batch was interrupted by a host memory
constraint partway through, and re-running it was judged not worth the risk on this machine. At
N=53 one query is ~0.019, so differences of 1-2 queries between setups (e.g. BM25 vs Hybrid RRF on
Recall@1) are within noise; the cross-encoder's gains on Recall@1, Recall@5 and MRR@10 are the more
trustworthy signal.

### Methodology corrections

An earlier version of this README reported numbers produced by code with measurement bugs, found in
a whole-repo review and fixed before the numbers above were re-measured:

- **Recall@k counted chunks, not advisories.** Each advisory has several chunks, so a 10-chunk cutoff
  covered only ~3 advisories. The eval now retrieves 50 chunks and scores the top-k distinct alias
  groups, with gold labels resolved from each query's advisory id at eval time.
- **The dense retriever was silently capped at 40 results** (pgvector's default `hnsw.ef_search`),
  whatever `k` was asked for, and advisory-filtered dense search could return no rows at all.
- **JSON-valid always equaled citation-valid**, by construction. They are now counted separately on
  each finding's final LLM response.
- **`verified` required zero known vulnerabilities of any kind** at the suggested version, not this
  advisory being fixed, and the scan silently dropped every advisory missing from the local corpus
  (33 findings then vs 127 now on the same file).

## Design decisions

- **Code computes, the LLM explains.** Version matching, minimum safe version and priority are
  deterministic Python; the LLM only writes prose, and a validator rejects any citation not in
  the evidence it was given.
- **Alias groups.** OSV mirrors the same bug under both GHSA-* and PYSEC-* ids. A union-find over
  aliases collapses them; the group id is the group's lexicographically smallest member, so it
  doesn't depend on ingest order or on which mirrors happen to be ingested. The scanner merges
  mirrors into one finding, retrieval dedupes hits per group, and the eval scores groups, not ids.
- **Missing advisories are fetched live.** OSV `querybatch` answers for all of OSV, but the local
  corpus may be a subset. Advisories it reports that aren't stored locally are fetched from
  `api.osv.dev` and upserted, instead of the package silently looking clean; EPSS scores for their
  CVEs are fetched lazily the same way.
- **Verified means OSV no longer lists *this* advisory.** The suggested version is re-queried in one
  batch; a fix is verified when OSV doesn't report this advisory, under any of its alias ids, at that
  version. Unrelated advisories still open there don't count against it. When mirrors disagree on
  the fixing version (e.g. GHSA says 8.1.2, its PYSEC mirror says 8.1.1), the suggestion is the
  version every mirror with fix data considers fixed.
- **RRF over score blending.** BM25 and dense scores are not on the same scale; reciprocal rank
  fusion combines rankings, not raw scores. Unweighted RRF rewards cross-retriever consensus, so it
  can rank below its best single input at rank 1 when the other retriever is weak on a query; here
  plain BM25 edges Hybrid RRF on Recall@1 (0.585 vs 0.566, one query), while RRF is ahead at
  Recall@10 (0.849 vs 0.811).
- **Why a cross-encoder.** The fused list often has the right advisory in its top 10 but not at
  rank 1; reranking the 50 fused chunks with a cross-encoder fixes ordering (Recall@1 0.566 → 0.660,
  MRR@10 0.634 → 0.736) at a measured cost of ~3.3 s/query on CPU.
- **LLM failures degrade, they don't crash.** `OllamaProvider` has a request timeout
  (`OLLAMA_TIMEOUT`, default 120s). Any provider failure (unreachable server, timeout, empty
  response) gives that finding the template verdict and switches the rest of the scan to templates,
  so a dead model costs one timeout rather than one per finding; `/ask` answers that the model is
  unavailable instead of returning a 500.

## Limitations

- Tells you a vulnerable version is *installed*, not that the vulnerable code path is *reachable*.
- PyPI only; npm/Maven/Go are out of scope for this build.
- KEV hits on PyPI are rare by design (KEV is dominated by vendor products).
- **Indexed corpus is dev-scoped and not a random sample**: `vt ingest osv --limit 2000` takes the
  first 2,000 entries of OSV's `all.zip` in its alphabetical order, i.e. roughly GHSA-2… through
  GHSA-8… (1,929 after dropping 71 withdrawn records), plus the 198 advisories the demo scan fetched
  live. The full OSV PyPI corpus is ~25,700 records. The retrieval and generation numbers reflect
  this smaller corpus and aren't extrapolated; scan findings don't depend on it (see Sample output).
  A full ingest + re-index is a straightforward follow-up (the spec's own accepted cut-list item:
  "evaluate on a subset and say so").
- **Retrieval eval set is 53 queries** (all 53 evaluated, 0 skipped), not the ~150 originally
  targeted (see Results).
- **Citation-valid is not the same as faithful.** The local `llama3.2:3b` produces citation-valid
  JSON for 85% of sampled findings (the other 15% get the template verdict, never a fabricated one),
  but citations only prove the model pointed at real evidence. In the hand check, 4 of 10 kept
  verdicts still misstated a version or the priority. The deterministic fields (priority,
  min_safe_version, verified) are always shown alongside the prose and are the ones to act on; a
  larger model, or a check that versions and priorities in the prose match the FACT lines, would be
  the next improvement.

## Next steps

- Reachability analysis via a tree-sitter call graph from entry points to vulnerable symbols named
  in fix commits.
- A calibrated classifier trained on KEV additions, replacing the static priority table.
- A post-generation check that any version or priority the verdict prose mentions matches the FACT
  lines (the failure mode the faithfulness check found), falling back to the template otherwise.
- npm/Maven ecosystem support.
- Full, unlimited OSV ingest + re-index once running on a machine with more headroom, to validate
  the eval numbers above at full corpus scale.
