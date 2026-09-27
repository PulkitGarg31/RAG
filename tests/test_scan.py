import json
from pathlib import Path

from vt.models import Advisory
from vt.scanner.scan import advisory_fixed_at, attribute_advisories, build_findings, fetch_missing_advisories

FIXTURES = Path(__file__).parent / "fixtures"


def test_build_findings_sorts_by_priority_then_cvss():
    advisories_by_pin = {
        ("jinja2", "2.10"): [Advisory(id="GHSA-1", package="jinja2", cve_ids=["CVE-1"],
                                      fixed_versions=["2.11.3"], cvss_score=9.8)],
        ("pyyaml", "5.3"): [Advisory(id="GHSA-2", package="pyyaml", cve_ids=["CVE-2"],
                                     fixed_versions=["5.4"], cvss_score=7.5)],
    }
    parsed = [("jinja2", "2.10"), ("pyyaml", "5.3")]

    findings = build_findings(parsed, advisories_by_pin, set(), {}, verify_fn=lambda pkg, v, adv: True)

    assert [f.package for f in findings] == ["jinja2", "pyyaml"]  # P1 (cvss 9.8) before P2 (cvss 7.5)
    assert findings[0].priority == "P1"
    assert findings[0].min_safe_version == "2.11.3"
    assert findings[0].verified is True


def test_build_findings_package_with_no_advisories_is_skipped():
    findings = build_findings([("safe-pkg", "1.0.0")], {}, set(), {}, verify_fn=lambda pkg, v, adv: True)
    assert findings == []


def test_build_findings_kev_hit_forces_p0():
    advisories_by_pin = {
        ("jinja2", "2.10"): [Advisory(id="GHSA-1", package="jinja2", cve_ids=["CVE-KEV"],
                                      fixed_versions=["2.11.3"], cvss_score=5.0)],
    }
    findings = build_findings([("jinja2", "2.10")], advisories_by_pin, {"CVE-KEV"}, {}, verify_fn=lambda pkg, v, adv: True)
    assert findings[0].priority == "P0"
    assert findings[0].kev is True


def test_same_package_pinned_twice_keeps_each_versions_advisories():
    a = Advisory(id="GHSA-a", package="foo", fixed_versions=["1.1"])
    b = Advisory(id="GHSA-b", package="foo", fixed_versions=["2.1"])
    result = attribute_advisories([("foo", "1.0"), ("foo", "2.0")], [["GHSA-a"], ["GHSA-b"]], {"GHSA-a": a, "GHSA-b": b})
    assert [x.id for x in result[("foo", "1.0")]] == ["GHSA-a"]
    assert [x.id for x in result[("foo", "2.0")]] == ["GHSA-b"]


def test_ghsa_and_pysec_mirrors_become_one_finding():
    ghsa = Advisory(id="GHSA-462w-v97r-4m45", package="jinja2", aliases=["CVE-2019-10906"],
                    cve_ids=["CVE-2019-10906"], fixed_versions=["2.10.1"], cvss_score=9.8)
    pysec = Advisory(id="PYSEC-2019-217", package="jinja2", aliases=["CVE-2019-10906", "GHSA-462w-v97r-4m45"],
                     cve_ids=["CVE-2019-10906"], fixed_versions=["2.10.1"], cvss_score=None)

    result = attribute_advisories([("jinja2", "2.10")], [[pysec.id, ghsa.id]], {ghsa.id: ghsa, pysec.id: pysec})

    merged = result[("jinja2", "2.10")]
    assert len(merged) == 1
    assert merged[0].id == "GHSA-462w-v97r-4m45"
    assert merged[0].cvss_score == 9.8
    assert "PYSEC-2019-217" in merged[0].aliases
    assert merged[0].cve_ids == ["CVE-2019-10906"]


def test_fix_versions_come_from_the_scanned_package():
    adv = Advisory(id="GHSA-27px-qpmj-qg38", package="paste", fixed_versions=["1.7.5.1"], affected=[
        {"package": {"name": "paste", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.7.5.1"}]}]},
        {"package": {"name": "PasteScript", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}]},
    ])

    result = attribute_advisories([("pastescript", "1.0")], [[adv.id]], {adv.id: adv})

    assert result[("pastescript", "1.0")][0].fixed_versions == ["2.0.1"]
    findings = build_findings([("pastescript", "1.0")], result, set(), {}, verify_fn=lambda p, v, a: True)
    assert findings[0].min_safe_version == "2.0.1"


def test_advisory_fixed_at_checks_every_alias_id():
    adv = Advisory(id="GHSA-x", package="p", aliases=["PYSEC-y", "CVE-1"])
    assert advisory_fixed_at(adv, ["GHSA-other"]) is True
    assert advisory_fixed_at(adv, ["PYSEC-y"]) is False
    assert advisory_fixed_at(adv, ["GHSA-x"]) is False


def test_epss_fields_come_from_the_single_highest_epss_cve():
    adv = Advisory(id="GHSA-1", package="p", cve_ids=["CVE-A", "CVE-B"], fixed_versions=["2.0"])
    findings = build_findings(
        [("p", "1.0")], {("p", "1.0"): [adv]}, set(),
        {"CVE-A": (0.01, 0.25), "CVE-B": (0.5, 0.98)}, verify_fn=lambda p, v, a: True,
    )
    f = findings[0]
    assert (f.epss_cve, f.epss, f.epss_percentile) == ("CVE-B", 0.5, 0.98)
    assert f.priority == "P1"


def test_fetch_missing_advisories_reports_what_it_could_not_use():
    live = json.loads((FIXTURES / "osv_jinja2.json").read_text())
    withdrawn = dict(live, id="GHSA-gone", withdrawn="2021-01-01T00:00:00Z")

    def fake_fetch(ids):
        return {"GHSA-462w-v97r-4m45": live, "GHSA-gone": withdrawn}

    advisories, unresolved = fetch_missing_advisories(
        ["GHSA-462w-v97r-4m45", "GHSA-gone", "GHSA-404"], fetch=fake_fetch
    )
    assert [a.id for a in advisories] == ["GHSA-462w-v97r-4m45"]
    assert set(unresolved) == {"GHSA-gone", "GHSA-404"}
