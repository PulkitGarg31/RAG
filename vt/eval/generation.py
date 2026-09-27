import json
import random
from dataclasses import asdict
from pathlib import Path

from vt.llm import verdict as verdict_module


def summarize_counters(verified_count: int, total_findings: int) -> dict:
    c = verdict_module.counters
    total = c["total"] or 1
    return {
        "json_valid_rate": c["json_valid"] / total,
        "citation_valid_rate": c["citation_valid"] / total,
        "fallback_rate": c["fallback"] / total,
        "provider_error_rate": c["provider_error"] / total,
        "min_safe_version_verified_rate": (verified_count / total_findings) if total_findings else 0.0,
    }


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

    sample = list(all_findings)
    if limit is not None and len(sample) > limit:
        sample = random.Random(seed).sample(sample, limit)
    fill_verdicts(sample)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps([asdict(f) for f in sample], indent=2, default=str), encoding="utf-8")

    counts = {"findings": len(all_findings), "llm_sample": len(sample)}
    return summarize_counters(verified_count, len(all_findings)), counts
