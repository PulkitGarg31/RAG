from unittest.mock import MagicMock

import pytest

from vt.llm import verdict as verdict_module
from vt.llm.provider import ProviderError
from vt.llm.verdict import generate_verdict
from vt.models import Advisory, Finding


def _finding() -> Finding:
    return Finding(package="jinja2", installed="2.10", advisory_id="GHSA-1", cve_ids=["CVE-1"],
                   priority="P2", min_safe_version="2.11.3", verified=True, kev=False, epss=None)


def _advisory() -> Advisory:
    return Advisory(id="GHSA-1", package="jinja2", cve_ids=["CVE-1"])


@pytest.fixture(autouse=True)
def fresh_counters(monkeypatch):
    monkeypatch.setattr(verdict_module, "counters", {
        "total": 0, "json_valid": 0, "citation_valid": 0, "fallback": 0, "provider_error": 0,
    })


def test_provider_failure_applies_template_then_raises():
    provider = MagicMock()
    provider.complete_json.side_effect = TimeoutError("read timeout")
    finding = _finding()

    with pytest.raises(ProviderError):
        generate_verdict(finding, _advisory(), None, [], provider)

    assert finding.generated_by == "template"
    assert finding.citations == ["FACT:pkg", "FACT:prio", "GHSA-1"]
    assert verdict_module.counters["provider_error"] == 1
    assert verdict_module.counters["fallback"] == 1


def test_none_text_from_provider_is_a_provider_error():
    provider = MagicMock()
    provider.complete_json.return_value = None  # e.g. Gemini response.text is None
    with pytest.raises(ProviderError):
        generate_verdict(_finding(), _advisory(), None, [], provider)


def test_valid_json_with_bad_citations_counts_as_json_valid_only():
    provider = MagicMock()
    provider.complete_json.return_value = '{"summary": "s", "rationale": "r", "citations": ["NVD"]}'
    finding = _finding()

    generate_verdict(finding, _advisory(), None, [], provider)

    c = verdict_module.counters
    assert (c["total"], c["json_valid"], c["citation_valid"], c["fallback"]) == (1, 1, 0, 1)
    assert finding.generated_by == "template"


def test_no_provider_goes_straight_to_template():
    finding = _finding()
    generate_verdict(finding, _advisory(), None, [], None)
    assert finding.generated_by == "template"
    assert verdict_module.counters["fallback"] == 1
