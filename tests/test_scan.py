from unittest.mock import MagicMock

from vt.models import Advisory
from vt.scanner.scan import build_findings


def test_build_findings_sorts_by_priority_then_cvss():
    advisories_by_pkg = {
        "jinja2": [Advisory(id="GHSA-1", package="jinja2", cve_ids=["CVE-1"],
                             fixed_versions=["2.11.3"], cvss_score=9.8)],
        "pyyaml": [Advisory(id="GHSA-2", package="pyyaml", cve_ids=["CVE-2"],
                             fixed_versions=["5.4"], cvss_score=7.5)],
    }
    parsed = [("jinja2", "2.10"), ("pyyaml", "5.3")]
    kev_cves: set[str] = set()
    epss_lookup: dict[str, tuple[float, float]] = {}

    findings = build_findings(parsed, advisories_by_pkg, kev_cves, epss_lookup, verify_fn=lambda pkg, v: True)

    assert [f.package for f in findings] == ["jinja2", "pyyaml"]  # P1 (cvss 9.8) before P2 (cvss 7.5)
    assert findings[0].priority == "P1"
    assert findings[0].min_safe_version == "2.11.3"
    assert findings[0].verified is True


def test_build_findings_package_with_no_advisories_is_skipped():
    findings = build_findings(
        [("safe-pkg", "1.0.0")], {}, set(), {}, verify_fn=lambda pkg, v: True
    )
    assert findings == []


def test_build_findings_kev_hit_forces_p0():
    advisories_by_pkg = {
        "jinja2": [Advisory(id="GHSA-1", package="jinja2", cve_ids=["CVE-KEV"],
                             fixed_versions=["2.11.3"], cvss_score=5.0)],
    }
    findings = build_findings(
        [("jinja2", "2.10")], advisories_by_pkg, {"CVE-KEV"}, {}, verify_fn=lambda pkg, v: True
    )
    assert findings[0].priority == "P0"
    assert findings[0].kev is True
