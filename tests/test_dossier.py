from vt.llm.dossier import build_dossier
from vt.models import Advisory, Finding


def test_dossier_includes_fact_lines():
    finding = Finding(
        package="jinja2", installed="2.10", advisory_id="GHSA-1", cve_ids=["CVE-2019-10906"],
        priority="P2", min_safe_version="3.1.4", verified=True, kev=False, epss=0.0123,
    )
    adv = Advisory(id="GHSA-1", package="jinja2", cve_ids=["CVE-2019-10906"], summary="sandbox escape")
    dossier = build_dossier(finding, adv, kev_entry=None, epss_percentile=0.71, chunks=[])

    assert "[FACT:pkg] package=jinja2 installed=2.10 min_safe_version=3.1.4 (verified=true)" in dossier
    assert "[FACT:prio] priority=P2" in dossier
    assert "[GHSA-1]" in dossier
    assert "CVE-2019-10906" in dossier


def test_dossier_includes_kev_line_only_when_present():
    finding = Finding(
        package="jinja2", installed="2.10", advisory_id="GHSA-1", cve_ids=["CVE-1"],
        priority="P0", min_safe_version="3.1.4", verified=True, kev=True, epss=None,
    )
    adv = Advisory(id="GHSA-1", package="jinja2", cve_ids=["CVE-1"])
    from vt.models import KevEntry

    kev = KevEntry(cve_id="CVE-1", vendor="Pallets", product="Jinja2", date_added="2024-01-15", due_date=None, ransomware="Unknown")
    dossier = build_dossier(finding, adv, kev_entry=kev, epss_percentile=None, chunks=[])
    assert "[KEV:CVE-1]" in dossier
    assert "2024-01-15" in dossier


def test_dossier_includes_evidence_chunks_with_ids():
    from vt.models import Chunk

    finding = Finding(
        package="jinja2", installed="2.10", advisory_id="GHSA-1", cve_ids=[],
        priority="P3", min_safe_version=None, verified=False, kev=False, epss=None,
    )
    adv = Advisory(id="GHSA-1", package="jinja2")
    chunk = Chunk(id="GHSA-1#summary#0", advisory_id="GHSA-1", kind="summary", header="[h]", content="sandbox escape details")
    dossier = build_dossier(finding, adv, kev_entry=None, epss_percentile=None, chunks=[chunk])
    assert "[GHSA-1#summary#0] sandbox escape details" in dossier
