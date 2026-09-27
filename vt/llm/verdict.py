from vt.models import Advisory, Chunk, Finding, KevEntry
from vt.llm.dossier import build_dossier
from vt.llm.prompts import SYSTEM_PROMPT, build_user_prompt
from vt.llm.validate import validate_verdict

# Module-level counters for the eval report (Task 18)
# NOTE: process-lifetime cumulative — never reset except at module import.
# Safe for one-shot CLI runs (fresh process each time); if this is ever read
# from a long-running server process (e.g. vt/api.py's uvicorn process) for
# a "this request's stats" signal, it will silently blend counts across
# unrelated requests/scans unless explicitly reset or scoped per-request.
counters = {"json_valid": 0, "citation_valid": 0, "fallback": 0, "total": 0}


def _template_fallback(finding: Finding, advisory: Advisory) -> tuple[str, str, list[str]]:
    cve_str = ", ".join(advisory.cve_ids) or "no known CVE"
    summary = f"{finding.package} {finding.installed} is affected by {advisory.id} ({cve_str})."
    upgrade = f"Upgrade to {finding.min_safe_version}." if finding.min_safe_version else "No fix is available yet."
    rationale = f"Priority {finding.priority}. {upgrade}"
    return summary, rationale, ["FACT:pkg", "FACT:prio", advisory.id]


def generate_verdict(
    finding: Finding,
    advisory: Advisory,
    kev_entry: KevEntry | None,
    epss_percentile: float | None,
    chunks: list[Chunk],
    provider,
) -> Finding:
    counters["total"] += 1
    dossier = build_dossier(finding, advisory, kev_entry, epss_percentile, chunks)
    evidence_ids = {"FACT:pkg", "FACT:prio", advisory.id}
    if kev_entry is not None:
        evidence_ids.add(f"KEV:{kev_entry.cve_id}")
    if finding.epss is not None and advisory.cve_ids:
        evidence_ids.add(f"EPSS:{advisory.cve_ids[0]}")
    evidence_ids.update(c.id for c in chunks)

    user_prompt = build_user_prompt(dossier)

    raw = provider.complete_json(SYSTEM_PROMPT, user_prompt)
    result = validate_verdict(raw, evidence_ids)
    if not result.ok:
        retry_prompt = f"{user_prompt}\n\nPrevious attempt failed validation: {result.error}. Try again."
        raw = provider.complete_json(SYSTEM_PROMPT, retry_prompt)
        result = validate_verdict(raw, evidence_ids)

    if result.ok:
        counters["json_valid"] += 1
        counters["citation_valid"] += 1
        finding.summary = result.verdict.summary
        finding.rationale = result.verdict.rationale
        finding.citations = result.verdict.citations
        finding.generated_by = "llm"
    else:
        counters["fallback"] += 1
        summary, rationale, citations = _template_fallback(finding, advisory)
        finding.summary = summary
        finding.rationale = rationale
        finding.citations = citations
        finding.generated_by = "template"

    return finding


def fill_verdicts(findings: list[Finding]) -> list[Finding]:
    """Load each finding's advisory/kev/epss/top-5 chunks and generate a verdict for it."""
    from vt.bm25_index import load_bm25
    from vt.db import get_conn
    from vt.llm.provider import get_provider
    from vt.retrieval.bm25 import BM25Retriever
    from vt.retrieval.dense import DenseRetriever
    from vt.retrieval.hybrid import HybridRetriever
    from vt.retrieval.rerank import RerankedRetriever
    from vt.models import Advisory, KevEntry
    from pathlib import Path

    provider = get_provider()
    bm25_path = Path("data/bm25.pkl")
    bm25, chunk_ids = load_bm25(bm25_path) if bm25_path.exists() else (None, [])

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, advisory_id, content FROM chunks WHERE id = ANY(%s)", (chunk_ids,))
            chunk_rows = {r[0]: r for r in cur.fetchall()}
        advisory_ids = {cid: chunk_rows[cid][1] for cid in chunk_ids if cid in chunk_rows}
        texts = {cid: chunk_rows[cid][2] for cid in chunk_ids if cid in chunk_rows}

        bm25_retriever = BM25Retriever(bm25=bm25, chunk_ids=chunk_ids, advisory_ids=advisory_ids, texts=texts) if bm25 else None
        dense_retriever = DenseRetriever(get_conn=lambda: conn)
        reranked = RerankedRetriever(hybrid=HybridRetriever(bm25_retriever=bm25_retriever, dense_retriever=dense_retriever)) if bm25_retriever else None

        for finding in findings:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, package, cve_ids, summary, details FROM advisories WHERE id = %s",
                    (finding.advisory_id,),
                )
                row = cur.fetchone()
            advisory = Advisory(id=row[0], package=row[1], cve_ids=row[2], summary=row[3], details=row[4])

            kev_entry = None
            if finding.kev and advisory.cve_ids:
                with conn.cursor() as cur:
                    cur.execute("SELECT cve_id, vendor, product, date_added, due_date, ransomware FROM kev WHERE cve_id = ANY(%s)", (advisory.cve_ids,))
                    kr = cur.fetchone()
                if kr:
                    kev_entry = KevEntry(cve_id=kr[0], vendor=kr[1], product=kr[2], date_added=kr[3], due_date=kr[4], ransomware=kr[5])

            epss_percentile = None
            if finding.epss is not None and advisory.cve_ids:
                with conn.cursor() as cur:
                    cur.execute("SELECT percentile FROM epss WHERE cve_id = %s", (advisory.cve_ids[0],))
                    pr = cur.fetchone()
                epss_percentile = pr[0] if pr else None

            chunks = []
            if reranked:
                query = f"{finding.package} {advisory.summary}"
                hits = reranked.search(query, k=5, advisory_filter={advisory.id})
                chunks = [Chunk(id=h.chunk_id, advisory_id=h.advisory_id, kind="", header="", content=h.text) for h in hits]

            generate_verdict(finding, advisory, kev_entry, epss_percentile, chunks, provider)

    return findings
