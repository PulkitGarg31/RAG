from vt.llm import verdict as verdict_module


def summarize_counters(verified_count: int, total_findings: int) -> dict:
    c = verdict_module.counters
    total = c["total"] or 1
    return {
        "json_valid_rate": c["json_valid"] / total,
        "citation_valid_rate": c["citation_valid"] / total,
        "fallback_rate": c["fallback"] / total,
        "min_safe_version_verified_rate": (verified_count / total_findings) if total_findings else 0.0,
    }


def run_generation_checks(requirements_files: list[str]) -> dict:
    """Run vt scan (with LLM) on each file, tally counters. Dev-run only (needs Ollama + Postgres)."""
    from pathlib import Path

    from vt.llm.verdict import fill_verdicts
    from vt.scanner.scan import scan_requirements_text

    all_findings = []
    for path in requirements_files:
        findings, _ = scan_requirements_text(Path(path).read_text(encoding="utf-8-sig"))
        all_findings.extend(fill_verdicts(findings))

    verified_count = sum(1 for f in all_findings if f.verified)
    return summarize_counters(verified_count, len(all_findings))
