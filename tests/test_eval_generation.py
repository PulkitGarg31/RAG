from vt.eval.generation import sample_findings, summarize_counters
from vt.llm import verdict as verdict_module
from vt.models import Finding


def test_summarize_counters_computes_rates():
    verdict_module.counters.update({"json_valid": 8, "citation_valid": 7, "fallback": 2, "total": 10})
    result = summarize_counters(verified_count=6, total_findings=10)
    assert result["json_valid_rate"] == 0.8
    assert result["citation_valid_rate"] == 0.7
    assert result["fallback_rate"] == 0.2
    assert result["min_safe_version_verified_rate"] == 0.6


def test_summarize_counters_handles_zero_total():
    verdict_module.counters.update({"json_valid": 0, "citation_valid": 0, "fallback": 0, "total": 0})
    result = summarize_counters(verified_count=0, total_findings=0)
    assert result["json_valid_rate"] == 0.0
    assert result["min_safe_version_verified_rate"] == 0.0


def test_summarize_counters_reports_provider_errors_separately():
    verdict_module.counters.update({"json_valid": 5, "citation_valid": 4, "fallback": 6, "provider_error": 2, "total": 10})
    result = summarize_counters(verified_count=0, total_findings=10)
    assert result["json_valid_rate"] == 0.5
    assert result["citation_valid_rate"] == 0.4
    assert result["provider_error_rate"] == 0.2


def test_llm_rates_exclude_findings_that_never_reached_the_llm():
    verdict_module.counters.update({"total": 40, "json_valid": 2, "citation_valid": 2, "fallback": 38,
                                    "provider_error": 1, "not_attempted": 37})
    result = summarize_counters(verified_count=40, total_findings=40)
    assert result["json_valid_rate"] == 2 / 3
    assert result["citation_valid_rate"] == 2 / 3
    assert result["fallback_rate"] == 1 / 3
    assert result["provider_error_rate"] == 1 / 3
    verdict_module.counters.update({"not_attempted": 0, "provider_error": 0})


def _finding(package: str, installed: str, advisory_id: str) -> Finding:
    return Finding(package=package, installed=installed, advisory_id=advisory_id, cve_ids=[],
                   priority="P2", min_safe_version=None, verified=False, kev=False, epss=None)


def test_sample_findings_is_reproducible_regardless_of_input_order():
    findings = [
        _finding(f"pkg{i}", "1.0", f"GHSA-{i}")
        for i in range(10)
    ]

    a = sample_findings(findings, 4)
    b = sample_findings(list(reversed(findings)), 4)

    assert {f.advisory_id for f in a} == {f.advisory_id for f in b}
