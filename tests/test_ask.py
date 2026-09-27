from unittest.mock import MagicMock

from vt.ask import build_ask_dossier, answer_question
from vt.models import Finding


def test_build_ask_dossier_includes_findings_table():
    findings = [
        Finding(package="jinja2", installed="2.10", advisory_id="GHSA-1", cve_ids=["CVE-1"],
                priority="P1", min_safe_version="3.1.4", verified=True, kev=False, epss=0.5),
    ]
    dossier = build_ask_dossier(findings, retrieved_chunks=[])
    assert "jinja2" in dossier
    assert "P1" in dossier
    assert "[FACT:findings]" in dossier


def test_answer_question_validates_citations(monkeypatch):
    findings = [
        Finding(package="jinja2", installed="2.10", advisory_id="GHSA-1", cve_ids=["CVE-1"],
                priority="P1", min_safe_version="3.1.4", verified=True, kev=False, epss=0.5),
    ]
    fake_provider = MagicMock()
    fake_provider.complete_json.return_value = '{"answer": "jinja2 is high priority.", "citations": ["FACT:findings"]}'

    result = answer_question("Which deps are risky?", findings, retrieved_chunks=[], provider=fake_provider)
    assert result["citations"] == ["FACT:findings"]
    assert "jinja2" in result["answer"]


def test_answer_question_rejects_non_object_json_without_crashing():
    findings = [
        Finding(package="jinja2", installed="2.10", advisory_id="GHSA-1", cve_ids=["CVE-1"],
                priority="P1", min_safe_version="3.1.4", verified=True, kev=False, epss=0.5),
    ]
    provider = MagicMock()
    provider.complete_json.return_value = '["not", "an", "object"]'

    result = answer_question("Which deps are risky?", findings, retrieved_chunks=[], provider=provider)

    assert result == {"answer": "Insufficient validated evidence to answer.", "citations": []}
    assert provider.complete_json.call_count == 2
