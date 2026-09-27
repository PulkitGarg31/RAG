import logging

from vt.models import Advisory, Chunk, Finding, KevEntry
from vt.llm.dossier import build_dossier, evidence_ids
from vt.llm.prompts import SYSTEM_PROMPT, build_user_prompt
from vt.llm.provider import ProviderError, complete_json_checked
from vt.llm.validate import validate_verdict

logger = logging.getLogger(__name__)

# Module-level counters for the eval report (Task 18)
# NOTE: process-lifetime cumulative — never reset except at module import.
# Safe for one-shot CLI runs (fresh process each time); if this is ever read
# from a long-running server process (e.g. vt/api.py's uvicorn process) for
# a "this request's stats" signal, it will silently blend counts across
# unrelated requests/scans unless explicitly reset or scoped per-request.
# json_valid/citation_valid are judged on each finding's final LLM response.
# not_attempted counts findings that never reached the LLM (no provider, or it failed earlier in
# the batch); LLM rates exclude them.
counters = {
    "json_valid": 0, "citation_valid": 0, "fallback": 0, "provider_error": 0, "total": 0,
    "not_attempted": 0,
}


def _template_fallback(finding: Finding, advisory: Advisory) -> tuple[str, str, list[str]]:
    cve_str = ", ".join(advisory.cve_ids) or "no known CVE"
    summary = f"{finding.package} {finding.installed} is affected by {advisory.id} ({cve_str})."
    upgrade = f"Upgrade to {finding.min_safe_version}." if finding.min_safe_version else "No fix is available yet."
    rationale = f"Priority {finding.priority}. {upgrade}"
    return summary, rationale, ["FACT:pkg", "FACT:prio", advisory.id]


def _apply_template(finding: Finding, advisory: Advisory) -> None:
    finding.summary, finding.rationale, finding.citations = _template_fallback(finding, advisory)
    finding.generated_by = "template"


def generate_verdict(finding: Finding, advisory: Advisory, kev_entry: KevEntry | None,
                     chunks: list[Chunk], provider) -> Finding:
    """Fill the finding's summary/rationale/citations from the LLM, validated against its evidence.
    Falls back to a deterministic template when validation fails twice or provider is None.
    If the provider itself fails, the template is applied and ProviderError is re-raised."""
    counters["total"] += 1
    if provider is None:
        counters["fallback"] += 1
        counters["not_attempted"] += 1
        _apply_template(finding, advisory)
        return finding

    dossier = build_dossier(finding, advisory, kev_entry, chunks)
    allowed = evidence_ids(finding, advisory, kev_entry, chunks)
    user_prompt = build_user_prompt(dossier)
    try:
        result = validate_verdict(complete_json_checked(provider, SYSTEM_PROMPT, user_prompt), allowed)
        if not result.ok:
            retry_prompt = f"{user_prompt}\n\nPrevious attempt failed validation: {result.error}. Try again."
            result = validate_verdict(complete_json_checked(provider, SYSTEM_PROMPT, retry_prompt), allowed)
    except ProviderError:
        counters["provider_error"] += 1
        counters["fallback"] += 1
        _apply_template(finding, advisory)
        raise

    if result.stage in ("citations", "ok"):
        counters["json_valid"] += 1
    if result.ok:
        counters["citation_valid"] += 1
        finding.summary = result.verdict.summary
        finding.rationale = result.verdict.rationale
        finding.citations = result.verdict.citations
        finding.generated_by = "llm"
    else:
        counters["fallback"] += 1
        _apply_template(finding, advisory)
    return finding


def fill_verdicts(findings: list[Finding]) -> list[Finding]:
    """Load each finding's advisory/kev/top-5 chunks and generate a verdict for it."""
    from vt.db import get_conn
    from vt.llm.provider import get_provider
    from vt.retrieval.factory import build_retrievers

    provider = get_provider()

    with get_conn() as conn:
        retrievers = build_retrievers(conn)
        reranked = retrievers.reranked if retrievers else None

        for finding in findings:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, package, cve_ids, summary, details FROM advisories WHERE id = %s",
                    (finding.advisory_id,),
                )
                row = cur.fetchone()
            advisory = (
                Advisory(id=row[0], package=row[1], cve_ids=row[2], summary=row[3], details=row[4])
                if row else Advisory(id=finding.advisory_id, package=finding.package, cve_ids=finding.cve_ids)
            )

            kev_entry = None
            if finding.kev and advisory.cve_ids:
                with conn.cursor() as cur:
                    cur.execute("SELECT cve_id, vendor, product, date_added, due_date, ransomware FROM kev WHERE cve_id = ANY(%s)", (advisory.cve_ids,))
                    kr = cur.fetchone()
                if kr:
                    kev_entry = KevEntry(cve_id=kr[0], vendor=kr[1], product=kr[2], date_added=kr[3], due_date=kr[4], ransomware=kr[5])

            chunks = []
            if reranked is not None and provider is not None:
                query = f"{finding.package} {advisory.summary or ''}"
                hits = reranked.search(query, k=5, advisory_filter={advisory.id, *finding.aliases})
                chunks = [Chunk(id=h.chunk_id, advisory_id=h.advisory_id, kind="", header="", content=h.text) for h in hits]

            try:
                generate_verdict(finding, advisory, kev_entry, chunks, provider)
            except ProviderError as e:
                logger.warning("LLM provider failed (%s); using template verdicts for the rest of this scan", e)
                provider = None

    return findings
