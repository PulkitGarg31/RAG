import json
import random
from dataclasses import asdict
from pathlib import Path

from vt.llm import verdict as verdict_module


def summarize_counters(verified_count: int, total_findings: int) -> dict:
    """LLM rates are over findings that reached the LLM; the verified rate is over all findings."""
    c = verdict_module.counters
    attempted = c["total"] - c.get("not_attempted", 0)
    denom = attempted or 1
    return {
        "json_valid_rate": c["json_valid"] / denom,
        "citation_valid_rate": c["citation_valid"] / denom,
        "fallback_rate": (c["fallback"] - c.get("not_attempted", 0)) / denom,
        "provider_error_rate": c["provider_error"] / denom,
        "min_safe_version_verified_rate": (verified_count / total_findings) if total_findings else 0.0,
    }


def sample_findings(findings: list, limit: int | None, seed: int = 42) -> list:
    """Fixed-seed sample, taken from a stable (package, installed, advisory_id) order so that
    re-scoring (e.g. an EPSS refresh reordering the scan) doesn't change which findings are picked."""
    ordered = sorted(findings, key=lambda f: (f.package, f.installed, f.advisory_id))
    if limit is None or len(ordered) <= limit:
        return ordered
    return random.Random(seed).sample(ordered, limit)


def run_generation_checks(
    requirements_files: list[str],
    limit: int | None = 40,
    seed: int = 42,
    out_path: Path = Path("reports/generation_findings.json"),
) -> tuple[dict, dict]:
    """Scan each file, verify-rate over all findings, LLM verdicts on a fixed-seed sample.
    Returns (rates, counts). Dev-run only (needs Ollama + Postgres)."""
    from vt.llm.verdict import fill_verdicts
    from vt.scanner.scan import scan_requirements_text

    all_findings = []
    for path in requirements_files:
        findings, _ = scan_requirements_text(Path(path).read_text(encoding="utf-8-sig"))
        all_findings.extend(findings)
    verified_count = sum(1 for f in all_findings if f.verified)

    sample = sample_findings(all_findings, limit, seed)
    fill_verdicts(sample)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps([asdict(f) for f in sample], indent=2, default=str), encoding="utf-8")

    not_attempted = verdict_module.counters.get("not_attempted", 0)
    counts = {
        "findings": len(all_findings),
        "llm_sample": len(sample),
        "llm_attempted": len(sample) - not_attempted,
        "not_attempted": not_attempted,
    }
    return summarize_counters(verified_count, len(all_findings)), counts
