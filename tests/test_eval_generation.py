from vt.eval.generation import summarize_counters
from vt.llm import verdict as verdict_module


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
