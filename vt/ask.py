import logging

from vt.llm.prompts import build_user_prompt
from vt.llm.provider import ProviderError, complete_json_checked
from vt.llm.validate import extract_json
from vt.models import Finding

logger = logging.getLogger(__name__)

ASK_SYSTEM_PROMPT = (
    "You are a security triage assistant answering questions about one dependency scan. "
    "Use ONLY the evidence provided (a findings table and retrieved advisory text). "
    "Answer arithmetic questions (counts, 'most') by reading the [FACT:findings] table. "
    'Return JSON only: {"answer": str, "citations": [evidence ids]}'
)


def build_ask_dossier(findings: list[Finding], retrieved_chunks: list) -> str:
    lines = ["[FACT:findings] package | advisory | priority | min_safe_version"]
    for f in findings:
        lines.append(f"  {f.package} | {f.advisory_id} | {f.priority} | {f.min_safe_version}")
    for chunk in retrieved_chunks:
        lines.append(f"[{chunk.chunk_id}] {chunk.text}")
    return "\n".join(lines)


def _validate_answer(raw: str | None, evidence_ids: set[str]) -> tuple[bool, dict | None, str | None]:
    """Validate an /ask response: must be JSON with an 'answer' string and a non-empty
    'citations' list that is a subset of the known evidence ids."""
    data = extract_json(raw)
    if not isinstance(data, dict):
        return False, None, "response was not a JSON object"

    if not isinstance(data.get("answer"), str) or not data["answer"]:
        return False, None, "missing or empty 'answer' field"

    citations = data.get("citations")
    if not isinstance(citations, list) or not citations:
        return False, None, "citations must be a non-empty list"

    if not all(isinstance(c, str) for c in citations):
        return False, None, "citations must be strings"

    unknown = [c for c in citations if c not in evidence_ids]
    if unknown:
        return False, None, f"citations not in evidence: {unknown}"

    return True, data, None


def answer_question(question: str, findings: list[Finding], retrieved_chunks: list, provider) -> dict:
    dossier = build_ask_dossier(findings, retrieved_chunks)
    evidence_ids = {"FACT:findings", *(c.chunk_id for c in retrieved_chunks)}
    user_prompt = f"{build_user_prompt(dossier)}\n\nQuestion: {question}"

    try:
        raw = complete_json_checked(provider, ASK_SYSTEM_PROMPT, user_prompt)
        ok, data, error = _validate_answer(raw, evidence_ids)
        if not ok:
            retry_prompt = f"{user_prompt}\n\nPrevious attempt failed validation: {error}. Try again."
            raw = complete_json_checked(provider, ASK_SYSTEM_PROMPT, retry_prompt)
            ok, data, error = _validate_answer(raw, evidence_ids)
    except ProviderError:
        logger.warning("LLM provider failed while answering", exc_info=True)
        return {"answer": "The language model is unavailable right now; no answer was generated.", "citations": []}

    if ok:
        return {"answer": data.get("answer", ""), "citations": data.get("citations", [])}

    return {"answer": "Insufficient validated evidence to answer.", "citations": []}


def ask_scan(scan_id: str, question: str, store, provider) -> dict:
    from vt.retrieval.dedupe import dedupe_to_advisory

    record = store.get(scan_id)
    if record is None:
        return {"answer": "Unknown scan_id.", "citations": []}

    findings = [Finding(**f) for f in record["findings"]]
    advisory_filter = {x for f in findings for x in (f.advisory_id, *f.aliases)}

    chunks = []
    try:
        from vt.db import get_conn
        from vt.retrieval.factory import build_retrievers

        with get_conn() as conn:
            retrievers = build_retrievers(conn)
            if retrievers is not None:
                hits = retrievers.reranked.search(question, k=8, advisory_filter=advisory_filter)
                chunks = dedupe_to_advisory(hits, retrievers.group_of)
    except Exception:
        logger.warning("ask_scan retrieval failed; answering from the findings table only", exc_info=True)
        chunks = []

    return answer_question(question, findings, chunks, provider)
