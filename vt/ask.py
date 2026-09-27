import json
import re

from vt.llm.prompts import build_user_prompt
from vt.models import Finding

ASK_SYSTEM_PROMPT = (
    "You are a security triage assistant answering questions about one dependency scan. "
    "Use ONLY the evidence provided (a findings table and retrieved advisory text). "
    "Answer arithmetic questions (counts, 'most') by reading the [FACT:findings] table. "
    'Return JSON only: {"answer": str, "citations": [evidence ids]}'
)

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def build_ask_dossier(findings: list[Finding], retrieved_chunks: list) -> str:
    lines = ["[FACT:findings] package | advisory | priority | min_safe_version"]
    for f in findings:
        lines.append(f"  {f.package} | {f.advisory_id} | {f.priority} | {f.min_safe_version}")
    for chunk in retrieved_chunks:
        lines.append(f"[{chunk.chunk_id}] {chunk.text}")
    return "\n".join(lines)


def _extract_json(raw: str) -> dict | None:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = _JSON_OBJECT_RE.search(raw)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None


def _validate_answer(raw: str, evidence_ids: set[str]) -> tuple[bool, dict | None, str | None]:
    """Validate an /ask response: must be JSON with an 'answer' string and a non-empty
    'citations' list that is a subset of the known evidence ids."""
    data = _extract_json(raw)
    if data is None:
        return False, None, "response was not valid JSON"

    if not isinstance(data.get("answer"), str) or not data["answer"]:
        return False, None, "missing or empty 'answer' field"

    citations = data.get("citations")
    if not isinstance(citations, list) or not citations:
        return False, None, "citations must be a non-empty list"

    unknown = [c for c in citations if c not in evidence_ids]
    if unknown:
        return False, None, f"citations not in evidence: {unknown}"

    return True, data, None


def answer_question(question: str, findings: list[Finding], retrieved_chunks: list, provider) -> dict:
    dossier = build_ask_dossier(findings, retrieved_chunks)
    evidence_ids = {"FACT:findings", *(c.chunk_id for c in retrieved_chunks)}
    user_prompt = f"{build_user_prompt(dossier)}\n\nQuestion: {question}"

    raw = provider.complete_json(ASK_SYSTEM_PROMPT, user_prompt)
    ok, data, error = _validate_answer(raw, evidence_ids)
    if not ok:
        retry_prompt = f"{user_prompt}\n\nPrevious attempt failed validation: {error}. Try again."
        raw = provider.complete_json(ASK_SYSTEM_PROMPT, retry_prompt)
        ok, data, error = _validate_answer(raw, evidence_ids)

    if ok:
        return {"answer": data.get("answer", ""), "citations": data.get("citations", [])}

    return {"answer": "Insufficient validated evidence to answer.", "citations": []}


def ask_scan(scan_id: str, question: str, store, provider) -> dict:
    from vt.retrieval.dedupe import dedupe_to_advisory

    record = store.get(scan_id)
    if record is None:
        return {"answer": "Unknown scan_id.", "citations": []}

    findings = [Finding(**f) for f in record["findings"]]
    advisory_filter = {f.advisory_id for f in findings}

    chunks = []
    try:
        from pathlib import Path

        from vt.bm25_index import load_bm25
        from vt.db import get_conn
        from vt.retrieval.bm25 import BM25Retriever
        from vt.retrieval.dense import DenseRetriever
        from vt.retrieval.hybrid import HybridRetriever
        from vt.retrieval.rerank import RerankedRetriever

        bm25_path = Path("data/bm25.pkl")
        if bm25_path.exists():
            bm25, chunk_ids = load_bm25(bm25_path)
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, advisory_id, content FROM chunks WHERE id = ANY(%s)", (chunk_ids,))
                    rows = {r[0]: r for r in cur.fetchall()}
                advisory_ids = {cid: rows[cid][1] for cid in chunk_ids if cid in rows}
                texts = {cid: rows[cid][2] for cid in chunk_ids if cid in rows}
                bm25_retriever = BM25Retriever(bm25=bm25, chunk_ids=chunk_ids, advisory_ids=advisory_ids, texts=texts)
                dense_retriever = DenseRetriever(get_conn=lambda: conn)
                reranked = RerankedRetriever(hybrid=HybridRetriever(bm25_retriever=bm25_retriever, dense_retriever=dense_retriever))
                hits = dedupe_to_advisory(reranked.search(question, k=8, advisory_filter=advisory_filter))
                chunks = hits
    except Exception:
        chunks = []

    return answer_question(question, findings, chunks, provider)
