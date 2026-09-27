from unittest.mock import MagicMock

import pytest

from vt.llm import verdict as verdict_module
from vt.llm.provider import ProviderError
from vt.llm.verdict import fill_verdicts, generate_verdict
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
        "not_attempted": 0,
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
    assert verdict_module.counters["not_attempted"] == 1


class _FakeCursor:
    def execute(self, sql, params=None):
        pass

    def fetchone(self):
        return None  # no local advisory row; fill_verdicts falls back to a bare Advisory

    def fetchall(self):
        return []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def cursor(self):
        return _FakeCursor()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fill_verdicts_disables_provider_after_first_failure(monkeypatch):
    """A provider failure partway through a batch (I1) must not be counted as if every
    remaining finding reached the LLM, and retrieval (M2) must filter on alias ids too."""
    provider = MagicMock()
    provider.complete_json.side_effect = TimeoutError("read timeout")
    retrievers = MagicMock()
    retrievers.reranked.search.return_value = []

    monkeypatch.setattr("vt.llm.provider.get_provider", lambda: provider)
    monkeypatch.setattr("vt.db.get_conn", lambda: _FakeConn())
    monkeypatch.setattr("vt.retrieval.factory.build_retrievers", lambda conn: retrievers)

    findings = [
        Finding(package="jinja2", installed="2.10", advisory_id="GHSA-1", cve_ids=["CVE-1"],
                priority="P2", min_safe_version="2.11.3", verified=True, kev=False, epss=None,
                aliases=["PYSEC-9", "CVE-9"]),
        Finding(package="pyyaml", installed="5.3", advisory_id="GHSA-2", cve_ids=["CVE-2"],
                priority="P2", min_safe_version="5.4", verified=True, kev=False, epss=None),
        Finding(package="requests", installed="2.19.0", advisory_id="GHSA-3", cve_ids=["CVE-3"],
                priority="P2", min_safe_version="2.20.0", verified=True, kev=False, epss=None),
    ]

    result = fill_verdicts(findings)

    assert result is findings
    assert all(f.generated_by == "template" for f in findings)
    assert provider.complete_json.call_count == 1

    c = verdict_module.counters
    assert c["provider_error"] == 1
    assert c["not_attempted"] == 2
    assert c["total"] == 3

    assert retrievers.reranked.search.call_count == 1
    _, kwargs = retrievers.reranked.search.call_args_list[0]
    assert kwargs["advisory_filter"] == {"GHSA-1", "PYSEC-9", "CVE-9"}
