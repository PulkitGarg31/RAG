from dataclasses import asdict

from fastapi import FastAPI
from pydantic import BaseModel

from vt.db import get_conn
from vt.scanner.scan import scan_requirements_text
from vt.store import default_store

app = FastAPI(title="VulnTriage-RAG")


class ScanRequest(BaseModel):
    requirements: str


class AskRequest(BaseModel):
    scan_id: str
    question: str


@app.post("/scan")
def scan(req: ScanRequest, use_llm: bool = True):
    findings, skipped = scan_requirements_text(req.requirements)
    if use_llm:
        from vt.llm.verdict import fill_verdicts

        findings = fill_verdicts(findings)
    scan_id = default_store().save(findings, skipped)
    return {"scan_id": scan_id, "findings": [asdict(f) for f in findings], "skipped": skipped}


@app.post("/ask")
def ask(req: AskRequest):
    from vt.ask import ask_scan
    from vt.llm.provider import get_provider

    return ask_scan(req.scan_id, req.question, default_store(), get_provider())


@app.get("/advisory/{advisory_id}")
def get_advisory(advisory_id: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, package, cve_ids, summary, cvss_score FROM advisories WHERE id = %s",
                (advisory_id,),
            )
            row = cur.fetchone()
        if row is None:
            return {"error": "not found"}

        advisory_id_, package, cve_ids, summary, cvss_score = row
        cve_ids = cve_ids or []

        kev_date_added = None
        epss = None
        epss_percentile = None
        if cve_ids:
            with conn.cursor() as cur:
                cur.execute("SELECT date_added FROM kev WHERE cve_id = ANY(%s)", (cve_ids,))
                kev_rows = cur.fetchall()
            if kev_rows:
                kev_date_added = kev_rows[0][0]

            with conn.cursor() as cur:
                cur.execute("SELECT epss, percentile FROM epss WHERE cve_id = ANY(%s)", (cve_ids,))
                epss_rows = cur.fetchall()
            if epss_rows:
                epss = max(r[0] for r in epss_rows)
                epss_percentile = max(r[1] for r in epss_rows)

    return {
        "id": advisory_id_, "package": package, "cve_ids": cve_ids, "summary": summary,
        "cvss_score": cvss_score, "kev_date_added": kev_date_added,
        "epss": epss, "epss_percentile": epss_percentile,
    }


@app.get("/health")
def health():
    db_ok = True
    try:
        from vt.db import get_conn

        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
    except Exception:
        db_ok = False

    index_loaded = False
    try:
        from pathlib import Path

        index_loaded = Path("data/bm25.pkl").exists()
    except Exception:
        index_loaded = False

    return {"db": db_ok, "index_loaded": index_loaded}
