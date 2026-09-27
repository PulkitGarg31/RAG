from dataclasses import asdict

from fastapi import FastAPI
from pydantic import BaseModel

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
    from vt.db import get_conn

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT a.id, a.package, a.cve_ids, a.summary, a.cvss_score, "
            "k.date_added, e.epss, e.percentile "
            "FROM advisories a "
            "LEFT JOIN kev k ON k.cve_id = ANY(a.cve_ids) "
            "LEFT JOIN epss e ON e.cve_id = ANY(a.cve_ids) "
            "WHERE a.id = %s",
            (advisory_id,),
        )
        row = cur.fetchone()
    if row is None:
        return {"error": "not found"}
    return {
        "id": row[0], "package": row[1], "cve_ids": row[2], "summary": row[3],
        "cvss_score": row[4], "kev_date_added": row[5], "epss": row[6], "epss_percentile": row[7],
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
