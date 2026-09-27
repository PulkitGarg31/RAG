import json
from pathlib import Path

from vt.ingest.osv import parse_osv_record

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_parse_osv_record_basic_fields():
    adv = parse_osv_record(_load("osv_jinja2.json"))
    assert adv.id == "GHSA-462w-v97r-4m45"
    assert adv.package == "jinja2"  # normalized
    assert adv.cve_ids == ["CVE-2019-10906"]
    assert adv.fixed_versions == ["2.11.3"]
    assert adv.cwe_ids == ["CWE-94"]


def test_parse_osv_record_cvss_score_computed():
    adv = parse_osv_record(_load("osv_jinja2.json"))
    assert adv.cvss_score is not None
    assert 9.0 <= adv.cvss_score <= 10.0


def test_parse_osv_record_missing_cvss_is_none():
    rec = _load("osv_jinja2_pysec.json")
    adv = parse_osv_record(rec)
    assert adv.cvss_score is None


def test_parse_osv_record_skips_non_pypi():
    rec = _load("osv_jinja2.json")
    rec["affected"][0]["package"]["ecosystem"] = "npm"
    assert parse_osv_record(rec) is None


def test_parse_osv_record_refs_split_by_type():
    adv = parse_osv_record(_load("osv_jinja2.json"))
    fix_refs = [r for r in adv.refs if r["type"] == "FIX"]
    assert len(fix_refs) == 1


def test_parse_osv_record_logs_when_multiple_pypi_packages(caplog):
    import logging

    rec = _load("osv_jinja2.json")
    rec["affected"].append(
        {
            "package": {"name": "Flask", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
        }
    )
    with caplog.at_level(logging.WARNING):
        adv = parse_osv_record(rec)
    assert adv is not None
    assert any("lists 2 PyPI-affected packages" in r.message for r in caplog.records)
